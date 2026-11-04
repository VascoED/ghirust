//! Structured binary loading built on the `object` crate.
//!
//! The loader turns PE/ELF/Mach-O/WASM containers into a format-neutral view:
//! sections with virtual-address ranges, the entry point, imports, exports and
//! symbols. It never copies the whole binary; section data is referenced by
//! offset into a read-only memory map, and virtual reads synthesize zero fill
//! for `.bss`-style tails.
//!
//! This is a real loader for the metadata and bytes needed by the disassembler.
//! It does not implement every relocation, resource, TLS or exception-table
//! semantic of the original formats; those limitations are recorded in
//! `AnalysisWarnings` and in the compatibility matrix.

use std::path::{Path, PathBuf};

use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};

use crate::cache::hash_file;
use crate::error::{GhirustError, Result};
use crate::filemap::ReadOnlyMap;
use crate::strings::{StringOptions, StringRecord, extract_strings};

/// A loaded section or segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedSection {
    /// Section name as stored in the container.
    pub name: String,
    /// Virtual address of the first byte.
    pub address: u64,
    /// Virtual size (including zero-filled tails).
    pub virtual_size: u64,
    /// Offset in the mapped file, when the section has file-backed bytes.
    pub file_offset: u64,
    /// Number of file-backed bytes.
    pub file_size: u64,
    /// Executable permission.
    pub executable: bool,
    /// Writable permission.
    pub writable: bool,
    /// Coarse kind: `code`, `data`, `bss`, `debug`, `resource`, `other`.
    pub kind: String,
}

impl LoadedSection {
    /// Exclusive end of the virtual range.
    pub fn end(&self) -> u64 {
        self.address.saturating_add(self.virtual_size)
    }

    /// Whether `address` belongs to this section.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address < self.end()
    }
}

/// One imported symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    /// Library or module name.
    pub library: String,
    /// Imported symbol name.
    pub name: String,
}

/// One exported symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    /// Export name.
    pub name: String,
    /// Virtual address, or `None` for a forwarded export.
    pub address: Option<u64>,
    /// Forwarder target (`DLL.Function`) when present.
    pub forwarder: Option<String>,
}

/// One symbol available to analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecord {
    /// Symbol name.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Known size, when provided by the container.
    pub size: u64,
    /// `function`, `data`, `label`, `section`, or `unknown`.
    pub kind: String,
    /// `entry`, `export`, `symbol`, or `import`.
    pub source: String,
    /// Whether the symbol has global/dynamic visibility.
    pub global: bool,
}

/// Format-neutral loaded program.
#[derive(Debug)]
pub struct LoadedProgram {
    /// Source path.
    pub path: PathBuf,
    /// SHA-256 of the file contents.
    pub sha256: String,
    /// Container format label (`PE`, `ELF`, ...).
    pub format: String,
    /// Architecture label.
    pub architecture: String,
    /// Pointer width in bits.
    pub bits: u8,
    /// File byte order.
    pub endian: String,
    /// Coarse object kind (`executable`, `shared library`, ...).
    pub object_kind: String,
    /// Target operating system, when inferable.
    pub os: Option<String>,
    /// Image base from the loader.
    pub image_base: u64,
    /// Entry point virtual address (`0` when absent).
    pub entry: u64,
    /// Sections with virtual ranges.
    pub sections: Vec<LoadedSection>,
    /// Imports, when the format exposes them.
    pub imports: Vec<ImportRecord>,
    /// Exports, when the format exposes them.
    pub exports: Vec<ExportRecord>,
    /// All usable symbols.
    pub symbols: Vec<SymbolRecord>,
    /// Binary strings (bounded and deduplicated).
    pub strings: Vec<StringRecord>,
    /// Non-fatal loading limitations.
    pub warnings: Vec<String>,
    bytes: ReadOnlyMap,
}

impl LoadedProgram {
    /// Load a binary with the native loader.
    pub fn load(path: &Path) -> Result<Self> {
        let map = ReadOnlyMap::open(path)?;
        let bytes = map.bytes();
        let parsed = parse_with_object(path, bytes)?;
        let sha256 = hash_file(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            sha256,
            format: parsed.format,
            architecture: parsed.architecture,
            bits: parsed.bits,
            endian: parsed.endian,
            object_kind: parsed.object_kind,
            os: parsed.os,
            image_base: parsed.image_base,
            entry: parsed.entry,
            sections: parsed.sections,
            imports: parsed.imports,
            exports: parsed.exports,
            symbols: parsed.symbols,
            strings: parsed.strings,
            warnings: parsed.warnings,
            bytes: map,
        })
    }

    /// Raw mapped bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.bytes()
    }

    /// Section containing a virtual address.
    pub fn section_at(&self, address: u64) -> Option<&LoadedSection> {
        self.sections
            .iter()
            .find(|section| section.contains(address))
    }

    /// File-backed slice from a virtual address to the end of its section.
    pub fn code_slice(&self, address: u64) -> Option<&[u8]> {
        let section = self.section_at(address)?;
        if !section.executable {
            return None;
        }
        let start = address.checked_sub(section.address)?;
        if start >= section.file_size {
            return None;
        }
        let offset = section.file_offset.checked_add(start)? as usize;
        let end = section
            .file_offset
            .saturating_add(section.file_size)
            .min(self.bytes.len() as u64) as usize;
        self.bytes.bytes().get(offset..end)
    }

    /// Read `length` virtual bytes, synthesizing zero fill outside file-backed
    /// data. Returns `None` when the range crosses a section boundary.
    pub fn read_virtual(&self, address: u64, length: usize) -> Option<Vec<u8>> {
        let section = self.section_at(address)?;
        let start = address.checked_sub(section.address)?;
        let end = start.checked_add(length as u64)?;
        if end > section.virtual_size {
            return None;
        }
        let mut output = vec![0u8; length];
        if start < section.file_size {
            let available = (section.file_size - start) as usize;
            let copy_length = available.min(length);
            let offset = section.file_offset.checked_add(start)? as usize;
            let slice = self.bytes.bytes().get(offset..offset + copy_length)?;
            output[..copy_length].copy_from_slice(slice);
        }
        Some(output)
    }

    /// Read a little-endian unsigned value from the image.
    pub fn read_u64(&self, address: u64) -> Option<u64> {
        let bytes = self.read_virtual(address, 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Read a NUL-terminated ASCII string at a virtual address, up to `max`.
    pub fn read_c_string(&self, address: u64, max: usize) -> Option<String> {
        let section = self.section_at(address)?;
        let start = address.checked_sub(section.address)?;
        if start >= section.virtual_size {
            return None;
        }
        let available = (section.virtual_size - start).min(max as u64) as usize;
        let bytes = self.read_virtual(address, available.max(1))?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if end < 3 || !bytes[..end].iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return None;
        }
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Find a symbol by address.
    pub fn symbol_at(&self, address: u64) -> Option<&SymbolRecord> {
        self.symbols.iter().find(|symbol| symbol.address == address)
    }

    /// Name for an address, falling back to a stable generated label.
    pub fn name_for(&self, address: u64) -> String {
        self.symbol_at(address)
            .map(|symbol| symbol.name.clone())
            .unwrap_or_else(|| format!("FUN_{address:x}"))
    }

    /// Total number of file-backed executable bytes.
    pub fn executable_bytes(&self) -> u64 {
        self.sections
            .iter()
            .filter(|section| section.executable)
            .map(|section| section.file_size)
            .sum()
    }
}

struct ParsedProgram {
    format: String,
    architecture: String,
    bits: u8,
    endian: String,
    object_kind: String,
    os: Option<String>,
    image_base: u64,
    entry: u64,
    sections: Vec<LoadedSection>,
    imports: Vec<ImportRecord>,
    exports: Vec<ExportRecord>,
    symbols: Vec<SymbolRecord>,
    strings: Vec<StringRecord>,
    warnings: Vec<String>,
}

fn parse_with_object(path: &Path, bytes: &[u8]) -> Result<ParsedProgram> {
    let file = object::File::parse(bytes).map_err(|source| {
        GhirustError::message(format!(
            "{} is not a supported loadable binary: {source}",
            path.display()
        ))
    })?;

    let format = file_format(&file);
    let architecture = format!("{:?}", file.architecture());
    let bits = if file.is_64() { 64 } else { 32 };
    let endian = match file.endianness() {
        object::Endianness::Little => "little".to_owned(),
        object::Endianness::Big => "big".to_owned(),
    };
    let object_kind = object_kind(&file);
    let os = os_for(&format);
    let image_base = file.relative_address_base();
    let entry = file.entry();
    let mut warnings = Vec::new();

    let mut sections = Vec::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("<unnamed>").to_owned();
        let data = match section.data() {
            Ok(data) => data,
            Err(_) => {
                warnings.push(format!("section {name}: raw data could not be read"));
                &[]
            }
        };
        let (file_offset, file_size) = if data.is_empty() {
            (0, 0)
        } else {
            let range = section.file_range();
            let direct = range.filter(|(_, size)| *size as usize == data.len());
            if let Some((start, size)) = direct {
                (start, size)
            } else {
                // Compressed sections are decompressed by `object`; reference
                // them by their offset in our own map when possible.
                let base = bytes.as_ptr() as usize;
                let offset = data.as_ptr() as usize;
                if offset >= base && offset + data.len() <= base + bytes.len() {
                    ((offset - base) as u64, data.len() as u64)
                } else {
                    warnings.push(format!(
                        "section {name}: decompressed data is not in the mapped file"
                    ));
                    (0, 0)
                }
            }
        };
        let (executable, writable, readable) = section_permissions(&section);
        let kind = section_kind(&section, executable);
        if data.is_empty() && section.size() > 0 {
            warnings.push(format!(
                "section {name} is virtual-only ({} bytes); reads return zeros",
                section.size()
            ));
        }
        let _ = readable;
        sections.push(LoadedSection {
            name,
            address: section.address(),
            virtual_size: section.size().max(file_size),
            file_offset,
            file_size,
            executable,
            writable,
            kind,
        });
    }

    let mut imports = Vec::new();
    match file.imports() {
        Ok(entries) => {
            for entry in entries {
                let library = String::from_utf8_lossy(entry.library()).into_owned();
                let name = String::from_utf8_lossy(entry.name()).into_owned();
                if !name.is_empty() {
                    imports.push(ImportRecord { library, name });
                }
            }
        }
        Err(_) => warnings.push("import table could not be decoded".to_owned()),
    }

    let mut exports = Vec::new();
    match file.exports() {
        Ok(entries) => {
            for entry in entries {
                let name = String::from_utf8_lossy(entry.name()).into_owned();
                let address = if entry.address() == 0 {
                    None
                } else {
                    Some(entry.address())
                };
                exports.push(ExportRecord {
                    name,
                    address,
                    forwarder: None,
                });
            }
        }
        Err(_) => warnings.push("export table could not be decoded".to_owned()),
    }

    let mut symbols = Vec::new();
    let executable_range_ids: Vec<usize> = sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.executable)
        .map(|(index, _)| index)
        .collect();
    let in_executable = |address: u64| {
        executable_range_ids
            .iter()
            .any(|index| sections[*index].contains(address))
    };

    if entry != 0 && in_executable(entry) {
        symbols.push(SymbolRecord {
            name: "entry".to_owned(),
            address: entry,
            size: 0,
            kind: "function".to_owned(),
            source: "entry".to_owned(),
            global: true,
        });
    }
    for export in &exports {
        if let Some(address) = export.address {
            if in_executable(address) {
                symbols.push(SymbolRecord {
                    name: export.name.clone(),
                    address,
                    size: 0,
                    kind: "function".to_owned(),
                    source: "export".to_owned(),
                    global: true,
                });
            }
        }
    }

    let mut symbol_warnings = 0usize;
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let address = symbol.address();
        if address == 0 || !in_executable(address) {
            continue;
        }
        if symbol.kind() != SymbolKind::Text && symbol.kind() != SymbolKind::Label {
            continue;
        }
        let name = match symbol.name() {
            Ok(name) if !name.is_empty() => name.to_owned(),
            _ => continue,
        };
        if symbols
            .iter()
            .any(|existing| existing.address == address && existing.name == name)
        {
            continue;
        }
        symbols.push(SymbolRecord {
            name,
            address,
            size: symbol.size(),
            kind: if symbol.kind() == SymbolKind::Text {
                "function".to_owned()
            } else {
                "label".to_owned()
            },
            source: "symbol".to_owned(),
            global: symbol.is_global(),
        });
        if symbols.len() > 500_000 {
            symbol_warnings += 1;
            warnings.push("symbol table truncated at 500,000 entries".to_owned());
            break;
        }
    }
    let _ = symbol_warnings;

    // Imports have no load-time virtual address in `object`'s portable API.
    // Record them as symbols with address 0 only for the symbol table view;
    // disassembly resolves IAT references through PE parsing in a later pass.
    for import in &imports {
        symbols.push(SymbolRecord {
            name: import.name.clone(),
            address: 0,
            size: 0,
            kind: "import".to_owned(),
            source: "import".to_owned(),
            global: true,
        });
    }

    symbols.sort_by_key(|symbol| (symbol.address, symbol.name.clone()));

    let strings = extract_strings(
        path,
        &StringOptions {
            min_length: 4,
            utf16: true,
            deduplicate: true,
            limit: 50_000,
        },
    )
    .unwrap_or_default();

    Ok(ParsedProgram {
        format,
        architecture,
        bits,
        endian,
        object_kind,
        os,
        image_base,
        entry,
        sections,
        imports,
        exports,
        symbols,
        strings,
        warnings,
    })
}

fn file_format(file: &object::File<'_>) -> String {
    match file.format() {
        object::BinaryFormat::Coff | object::BinaryFormat::Pe => "PE".to_owned(),
        object::BinaryFormat::Elf => "ELF".to_owned(),
        object::BinaryFormat::MachO => "Mach-O".to_owned(),
        object::BinaryFormat::Wasm => "WebAssembly".to_owned(),
        object::BinaryFormat::Xcoff => "XCOFF".to_owned(),
        other => format!("{other:?}"),
    }
}

fn object_kind(file: &object::File<'_>) -> String {
    match file.kind() {
        object::ObjectKind::Executable => "executable",
        object::ObjectKind::Dynamic => "shared library",
        object::ObjectKind::Relocatable => "relocatable object",
        object::ObjectKind::Core => "core dump",
        _ => "unknown",
    }
    .to_owned()
}

fn os_for(format: &str) -> Option<String> {
    Some(match format {
        "PE" => "Windows".to_owned(),
        "ELF" => "Unix (ELF)".to_owned(),
        "Mach-O" => "macOS / Apple".to_owned(),
        "WebAssembly" => "WebAssembly".to_owned(),
        _ => return None,
    })
}

fn section_permissions(section: &object::Section<'_, '_>) -> (bool, bool, bool) {
    let mut executable = matches!(section.kind(), SectionKind::Text);
    let mut writable = false;
    let mut readable = true;
    match section.flags() {
        SectionFlags::Elf { sh_flags } => {
            executable |= sh_flags & 0x4 != 0;
            writable |= sh_flags & 0x1 != 0;
            readable = sh_flags & 0x2 != 0;
        }
        SectionFlags::Coff { characteristics } => {
            executable |= characteristics & 0x2000_0000 != 0;
            writable |= characteristics & 0x8000_0000 != 0;
            readable |= characteristics & 0x4000_0000 != 0;
        }
        SectionFlags::MachO { .. } => {}
        _ => {}
    }
    (executable, writable, readable)
}

fn section_kind(section: &object::Section<'_, '_>, executable: bool) -> String {
    if executable {
        return "code".to_owned();
    }
    match section.kind() {
        SectionKind::UninitializedData | SectionKind::UninitializedTls => "bss",
        SectionKind::Debug | SectionKind::DebugString => "debug",
        SectionKind::ReadOnlyData
        | SectionKind::ReadOnlyString
        | SectionKind::Data
        | SectionKind::Tls => "data",
        _ => "other",
    }
    .to_owned()
}

/// Information about the loader that produced an analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderSummary {
    /// Container format.
    pub format: String,
    /// Architecture.
    pub architecture: String,
    /// Pointer width.
    pub bits: u8,
    /// Byte order.
    pub endian: String,
    /// Object kind.
    pub object_kind: String,
    /// Target OS.
    pub os: Option<String>,
    /// Image base.
    pub image_base: u64,
    /// Entry point.
    pub entry: u64,
    /// Executable bytes.
    pub executable_bytes: u64,
}

impl From<&LoadedProgram> for LoaderSummary {
    fn from(program: &LoadedProgram) -> Self {
        Self {
            format: program.format.clone(),
            architecture: program.architecture.clone(),
            bits: program.bits,
            endian: program.endian.clone(),
            object_kind: program.object_kind.clone(),
            os: program.os.clone(),
            image_base: program.image_base,
            entry: program.entry,
            executable_bytes: program.executable_bytes(),
        }
    }
}

/// Convert loader errors into a stable suggestion for the CLI.
pub fn loader_hint(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() == 0 => "The file is empty.".to_owned(),
        Ok(_) => "The file may be packed, use an unsupported container, or be a raw dump. Inspect its headers first and choose a loader manually when available.".to_owned(),
        Err(error) => format!("The file could not be read: {error}"),
    }
}

/// Convenience helper that formats unsupported-binary errors with a hint.
pub fn load_or_hint(path: &Path) -> Result<LoadedProgram> {
    LoadedProgram::load(path).map_err(|error| {
        if error
            .to_string()
            .contains("not a supported loadable binary")
        {
            GhirustError::message(format!(
                "could not load {}: {}. {}",
                path.display(),
                error,
                loader_hint(path)
            ))
        } else {
            error
        }
    })
}
