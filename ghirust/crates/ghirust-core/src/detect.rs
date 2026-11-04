//! Binary format, architecture and language detection.
//!
//! This is deliberately a *small* detector, not a full loader. It reads only
//! the headers and section tables it needs, so inspecting a 30 MB DLL does not
//! allocate 30 MB. The result always carries evidence and a confidence value:
//! GHIRUST must never present a heuristic as confirmed metadata.

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{IoResultExt, Result};

const PREFIX_BYTES: u64 = 1024 * 1024;
const LANGUAGE_SCAN_BYTES: u64 = 8 * 1024 * 1024;

/// Recognised container formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    /// Windows Portable Executable.
    Pe,
    /// Unix ELF.
    Elf,
    /// Apple Mach-O (including universal/fat headers).
    MachO,
    /// Java class file.
    JavaClass,
    /// CPython bytecode.
    PythonBytecode,
    /// WebAssembly module.
    Wasm,
    /// ZIP container (including JAR/WAR/EAR).
    Zip,
    /// Legacy DOS executable.
    Dos,
    /// No known signature.
    Unknown,
}

impl BinaryFormat {
    /// Short human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::JavaClass => "Java class",
            Self::PythonBytecode => "Python bytecode",
            Self::Wasm => "WebAssembly",
            Self::Zip => "ZIP",
            Self::Dos => "DOS",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Byte order of the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

impl Endian {
    /// Read a `u16` at `offset`.
    fn u16(self, bytes: &[u8], offset: usize) -> Option<u16> {
        let slice = bytes.get(offset..offset + 2)?;
        Some(match self {
            Self::Little => u16::from_le_bytes([slice[0], slice[1]]),
            Self::Big => u16::from_be_bytes([slice[0], slice[1]]),
        })
    }

    /// Read a `u32` at `offset`.
    fn u32(self, bytes: &[u8], offset: usize) -> Option<u32> {
        let slice = bytes.get(offset..offset + 4)?;
        Some(match self {
            Self::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
            Self::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
        })
    }

    /// Read a `u64` at `offset`.
    fn u64(self, bytes: &[u8], offset: usize) -> Option<u64> {
        let slice = bytes.get(offset..offset + 8)?;
        Some(match self {
            Self::Little => u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            Self::Big => u64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
        })
    }
}

/// One section or segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name, when present.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Virtual size in bytes.
    pub size: u64,
    /// Raw bytes on disk, when known.
    pub file_size: Option<u64>,
    /// `code`, `data`, `bss`, `debug`, or `unknown`.
    pub kind: String,
}

/// Detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    /// Container format.
    pub format: BinaryFormat,
    /// CPU architecture, when known.
    pub architecture: Option<String>,
    /// Pointer width.
    pub bits: Option<u8>,
    /// Byte order.
    pub endian: Option<Endian>,
    /// Target operating system.
    pub os: Option<String>,
    /// `executable`, `library`, `object`, `class`, ...
    pub kind: Option<String>,
    /// Inferred source language.
    pub language: Option<String>,
    /// Confidence for `language`, from 0.0 to 1.0.
    pub language_confidence: f32,
    /// Inferred compiler or toolchain.
    pub compiler: Option<String>,
    /// Confidence for the format/architecture classification.
    pub confidence: f32,
    /// Entry point virtual address.
    pub entry_point: Option<u64>,
    /// Preferred image base, when known.
    pub image_base: Option<u64>,
    /// Sections found in the header table.
    pub sections: Vec<SectionInfo>,
    /// Why the detector reached this conclusion.
    pub evidence: Vec<String>,
    /// Non-fatal problems found while parsing.
    pub warnings: Vec<String>,
    /// File size.
    pub file_size: u64,
}

impl DetectionReport {
    fn unknown(size: u64) -> Self {
        Self {
            format: BinaryFormat::Unknown,
            architecture: None,
            bits: None,
            endian: None,
            os: None,
            kind: None,
            language: None,
            language_confidence: 0.0,
            compiler: None,
            confidence: 0.0,
            entry_point: None,
            image_base: None,
            sections: Vec::new(),
            evidence: Vec::new(),
            warnings: Vec::new(),
            file_size: size,
        }
    }
}

/// Detect a file by reading only its headers and a bounded language-sample.
pub fn detect_file(path: &Path) -> Result<DetectionReport> {
    let mut file = File::open(path).at(path)?;
    let size = file.metadata().at(path)?.len();
    let prefix = read_prefix(&mut file, size, PREFIX_BYTES).at(path)?;

    let mut report = detect_prefix(&prefix, size);
    if report.format == BinaryFormat::Elf {
        complete_elf_sections(&mut file, &prefix, &mut report).at(path)?;
    }
    scan_language_hints(&mut file, size, &mut report).at(path)?;
    Ok(report)
}

fn read_prefix(file: &mut File, size: u64, limit: u64) -> std::io::Result<Vec<u8>> {
    let length = size.min(limit) as usize;
    let mut bytes = vec![0u8; length];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn detect_prefix(bytes: &[u8], size: u64) -> DetectionReport {
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        return parse_pe(bytes, size);
    }
    if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        return parse_elf(bytes, size);
    }
    if bytes.len() >= 4 {
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
        ) {
            return parse_macho(bytes, size);
        }
        if magic == [0xca, 0xfe, 0xba, 0xbe] {
            return parse_java_or_fat_macho(bytes, size);
        }
        if magic == [0x00, 0x61, 0x73, 0x6d] {
            let mut report = DetectionReport::unknown(size);
            report.format = BinaryFormat::Wasm;
            report.architecture = Some("WebAssembly".to_owned());
            report.bits = Some(32);
            report.endian = Some(Endian::Little);
            report.kind = Some("module".to_owned());
            report.language = Some("WebAssembly".to_owned());
            report.language_confidence = 0.95;
            report.confidence = 1.0;
            report.evidence.push("\\0asm signature".to_owned());
            return report;
        }
        if magic == [0x50, 0x4b, 0x03, 0x04] {
            let mut report = DetectionReport::unknown(size);
            report.format = BinaryFormat::Zip;
            report.kind = Some("archive".to_owned());
            report.confidence = 0.9;
            report.evidence.push("ZIP local-file signature".to_owned());
            return report;
        }
        if let Some(version) = python_magic(magic) {
            let mut report = DetectionReport::unknown(size);
            report.format = BinaryFormat::PythonBytecode;
            report.architecture = Some("CPython VM".to_owned());
            report.language = Some(format!("Python ({version})"));
            report.language_confidence = 0.95;
            report.kind = Some("bytecode".to_owned());
            report.confidence = 1.0;
            report
                .evidence
                .push(format!("CPython magic {magic:02x?} ({version})"));
            return report;
        }
    }

    let mut report = DetectionReport::unknown(size);
    report.evidence.push("no known file signature".to_owned());
    report
}

fn parse_pe(bytes: &[u8], size: u64) -> DetectionReport {
    let mut report = DetectionReport::unknown(size);
    report.format = BinaryFormat::Pe;
    report.endian = Some(Endian::Little);
    report.confidence = 0.95;
    report.evidence.push("MZ and PE signatures".to_owned());

    let pe_offset = Endian::Little.u32(bytes, 0x3c).unwrap_or(0) as usize;
    if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        report
            .warnings
            .push("MZ file without a valid PE header".to_owned());
        report.confidence = 0.4;
        return report;
    }

    let coff = pe_offset + 4;
    let machine = Endian::Little.u16(bytes, coff).unwrap_or(0);
    let section_count = Endian::Little.u16(bytes, coff + 2).unwrap_or(0) as usize;
    let characteristics = Endian::Little.u16(bytes, coff + 18).unwrap_or(0);
    let optional_size = Endian::Little.u16(bytes, coff + 16).unwrap_or(0) as usize;
    let optional = coff + 20;

    report.architecture = pe_machine(machine).map(str::to_owned);
    report.kind = Some(if characteristics & 0x2000 != 0 {
        "library".to_owned()
    } else {
        "executable".to_owned()
    });
    report.os = Some("Windows".to_owned());

    let magic = Endian::Little.u16(bytes, optional).unwrap_or(0);
    let (bits, image_base, entry_rva, dir_offset) = match magic {
        0x10b => (
            32u8,
            Endian::Little.u32(bytes, optional + 28).map(u64::from),
            Endian::Little.u32(bytes, optional + 16),
            Some(optional + 96),
        ),
        0x20b => (
            64u8,
            Endian::Little.u64(bytes, optional + 24),
            Endian::Little.u32(bytes, optional + 16),
            Some(optional + 112),
        ),
        _ => (32, None, None, None),
    };
    report.bits = Some(bits);
    report.image_base = image_base;
    report.entry_point = entry_rva.and_then(|rva| image_base.map(|base| base + u64::from(rva)));

    if let Some(dirs) = dir_offset {
        let cli = Endian::Little.u32(bytes, dirs + 14 * 8);
        if cli.map(|rva| rva != 0).unwrap_or(false) {
            report.language = Some("C# / .NET (CLR)".to_owned());
            report.language_confidence = 0.9;
            report
                .evidence
                .push("PE CLI data directory is present".to_owned());
        }
    }

    let section_table = optional + optional_size;
    for index in 0..section_count {
        let offset = section_table + index * 40;
        let Some(header) = bytes.get(offset..offset + 40) else {
            report
                .warnings
                .push("section table extends beyond the inspected header".to_owned());
            break;
        };
        let name = fixed_name(&header[..8]);
        let virtual_size = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let virtual_address = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        let raw_size = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        let section_characteristics =
            u32::from_le_bytes([header[36], header[37], header[38], header[39]]);
        let kind = if section_characteristics & 0x20 != 0 {
            "code"
        } else if section_characteristics & 0x80 != 0 {
            "bss"
        } else if name.starts_with(".debug") {
            "debug"
        } else {
            "data"
        };
        report.sections.push(SectionInfo {
            name,
            address: image_base.unwrap_or(0) + u64::from(virtual_address),
            size: u64::from(virtual_size),
            file_size: Some(u64::from(raw_size)),
            kind: kind.to_owned(),
        });
    }

    report
}

fn parse_elf(bytes: &[u8], size: u64) -> DetectionReport {
    let mut report = DetectionReport::unknown(size);
    report.format = BinaryFormat::Elf;
    report.confidence = 0.99;
    report.evidence.push("ELF magic".to_owned());

    let class = bytes.get(4).copied().unwrap_or(0);
    let data = bytes.get(5).copied().unwrap_or(0);
    let endian = if data == 2 {
        Endian::Big
    } else {
        Endian::Little
    };
    report.endian = Some(endian);
    report.bits = Some(if class == 2 { 64 } else { 32 });

    let (machine, elf_type, entry, shoff, shentsize, shnum) = if class == 2 {
        (
            endian.u16(bytes, 18),
            endian.u16(bytes, 16),
            endian.u64(bytes, 24),
            endian.u64(bytes, 40),
            endian.u16(bytes, 58),
            endian.u16(bytes, 60),
        )
    } else {
        (
            endian.u16(bytes, 18),
            endian.u16(bytes, 16),
            endian.u32(bytes, 24).map(u64::from),
            endian.u32(bytes, 32).map(u64::from),
            endian.u16(bytes, 46),
            endian.u16(bytes, 48),
        )
    };

    report.architecture = machine.and_then(elf_machine).map(str::to_owned);
    report.kind = elf_type.map(|value| {
        match value {
            1 => "object",
            2 => "executable",
            3 => "library",
            4 => "core",
            _ => "other",
        }
        .to_owned()
    });
    report.entry_point = entry.filter(|value| *value != 0);
    let osabi = bytes.get(7).copied().unwrap_or(0);
    report.os = Some(
        match osabi {
            3 => "Linux",
            6 => "Solaris",
            9 => "FreeBSD",
            12 => "OpenBSD",
            _ => "Unix (ELF)",
        }
        .to_owned(),
    );

    // Parse the section table now when it is in the prefix; otherwise the
    // caller completes it with `complete_elf_sections`.
    if let (Some(shoff), Some(shentsize), Some(shnum)) = (shoff, shentsize, shnum) {
        if shoff > 0
            && shentsize as usize >= 40
            && (shoff as usize).saturating_add((shnum as usize).saturating_mul(shentsize as usize))
                <= bytes.len()
        {
            parse_elf_section_headers(bytes, class, endian, shoff, shentsize, shnum, &mut report);
        }
    }
    report
}

fn parse_elf_section_headers(
    bytes: &[u8],
    class: u8,
    endian: Endian,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    report: &mut DetectionReport,
) {
    let entry_size = shentsize as usize;
    let base = shoff as usize;
    let shstrndx = endian.u16(bytes, base + entry_size * 6).unwrap_or(0) as usize;

    let mut strtab_offset = 0u64;
    let mut strtab_size = 0u64;
    if shstrndx < shnum as usize {
        let header_offset = base + shstrndx * entry_size;
        if class == 2 {
            strtab_offset = endian.u64(bytes, header_offset + 24).unwrap_or(0);
            strtab_size = endian.u64(bytes, header_offset + 32).unwrap_or(0);
        } else {
            strtab_offset = endian
                .u32(bytes, header_offset + 16)
                .map(u64::from)
                .unwrap_or(0);
            strtab_size = endian
                .u32(bytes, header_offset + 20)
                .map(u64::from)
                .unwrap_or(0);
        }
    }

    let strtab = bytes
        .get(strtab_offset as usize..(strtab_offset + strtab_size) as usize)
        .unwrap_or(&[]);

    for index in 0..shnum as usize {
        let offset = base + index * entry_size;
        let name_offset = endian.u32(bytes, offset).unwrap_or(0) as usize;
        let kind_value = endian.u32(bytes, offset + 4).unwrap_or(0);
        let flags = if class == 2 {
            endian.u64(bytes, offset + 8).unwrap_or(0)
        } else {
            endian.u32(bytes, offset + 8).map(u64::from).unwrap_or(0)
        };
        let (address, file_offset, section_size) = if class == 2 {
            (
                endian.u64(bytes, offset + 16).unwrap_or(0),
                endian.u64(bytes, offset + 24).unwrap_or(0),
                endian.u64(bytes, offset + 32).unwrap_or(0),
            )
        } else {
            (
                endian.u32(bytes, offset + 12).map(u64::from).unwrap_or(0),
                endian.u32(bytes, offset + 16).map(u64::from).unwrap_or(0),
                endian.u32(bytes, offset + 20).map(u64::from).unwrap_or(0),
            )
        };
        let name = c_string(strtab, name_offset).unwrap_or_else(|| format!("section_{index}"));
        let kind = if kind_value == 8 {
            "bss"
        } else if flags & 0x4 != 0 {
            "code"
        } else if flags & 0x2 != 0 {
            "data"
        } else {
            "unknown"
        };
        report.sections.push(SectionInfo {
            name,
            address,
            size: section_size,
            file_size: Some(section_size),
            kind: kind.to_owned(),
        });
        let _ = file_offset;
    }
}

fn complete_elf_sections(
    file: &mut File,
    prefix: &[u8],
    report: &mut DetectionReport,
) -> std::io::Result<()> {
    if !report.sections.is_empty() || prefix.len() < 64 {
        return Ok(());
    }
    let class = prefix[4];
    let endian = if prefix[5] == 2 {
        Endian::Big
    } else {
        Endian::Little
    };
    let (shoff, shentsize, shnum) = if class == 2 {
        (
            endian.u64(prefix, 40),
            endian.u16(prefix, 58),
            endian.u16(prefix, 60),
        )
    } else {
        (
            endian.u32(prefix, 32).map(u64::from),
            endian.u16(prefix, 46),
            endian.u16(prefix, 48),
        )
    };
    let (Some(shoff), Some(shentsize), Some(shnum)) = (shoff, shentsize, shnum) else {
        return Ok(());
    };
    if shoff == 0 || shentsize < 40 || shnum == 0 || shnum > 4096 {
        return Ok(());
    }
    let total = (shentsize as u64).saturating_mul(shnum as u64);
    if total > 16 * 1024 * 1024 {
        report
            .warnings
            .push("ELF section table is unusually large; skipped".to_owned());
        return Ok(());
    }
    let mut buffer = vec![0u8; total as usize];
    file.seek(SeekFrom::Start(shoff))?;
    file.read_exact(&mut buffer)?;

    // Re-run the parser against a synthetic header where section offsets are
    // relative to the loaded table. The string table may live outside this
    // buffer, so names fall back to `section_N` when unavailable.
    let base = 0usize;
    let entry_size = shentsize as usize;
    let shstrndx = endian.u16(&buffer, base + entry_size * 6).unwrap_or(0) as usize;
    let mut strtab_offset = 0u64;
    let mut strtab_size = 0u64;
    if shstrndx < shnum as usize {
        let header_offset = base + shstrndx * entry_size;
        if class == 2 {
            strtab_offset = endian.u64(&buffer, header_offset + 24).unwrap_or(0);
            strtab_size = endian.u64(&buffer, header_offset + 32).unwrap_or(0);
        } else {
            strtab_offset = endian
                .u32(&buffer, header_offset + 16)
                .map(u64::from)
                .unwrap_or(0);
            strtab_size = endian
                .u32(&buffer, header_offset + 20)
                .map(u64::from)
                .unwrap_or(0);
        }
    }
    let mut strtab = Vec::new();
    if strtab_size > 0 && strtab_size <= 4 * 1024 * 1024 {
        strtab.resize(strtab_size as usize, 0);
        file.seek(SeekFrom::Start(strtab_offset))?;
        file.read_exact(&mut strtab)?;
    }

    for index in 0..shnum as usize {
        let offset = base + index * entry_size;
        let name_offset = endian.u32(&buffer, offset).unwrap_or(0) as usize;
        let kind_value = endian.u32(&buffer, offset + 4).unwrap_or(0);
        let flags = if class == 2 {
            endian.u64(&buffer, offset + 8).unwrap_or(0)
        } else {
            endian.u32(&buffer, offset + 8).map(u64::from).unwrap_or(0)
        };
        let (address, section_size) = if class == 2 {
            (
                endian.u64(&buffer, offset + 16).unwrap_or(0),
                endian.u64(&buffer, offset + 32).unwrap_or(0),
            )
        } else {
            (
                endian.u32(&buffer, offset + 12).map(u64::from).unwrap_or(0),
                endian.u32(&buffer, offset + 20).map(u64::from).unwrap_or(0),
            )
        };
        let name = c_string(&strtab, name_offset).unwrap_or_else(|| format!("section_{index}"));
        let kind = if kind_value == 8 {
            "bss"
        } else if flags & 0x4 != 0 {
            "code"
        } else if flags & 0x2 != 0 {
            "data"
        } else {
            "unknown"
        };
        report.sections.push(SectionInfo {
            name,
            address,
            size: section_size,
            file_size: Some(section_size),
            kind: kind.to_owned(),
        });
    }
    Ok(())
}

fn parse_macho(bytes: &[u8], size: u64) -> DetectionReport {
    let mut report = DetectionReport::unknown(size);
    report.format = BinaryFormat::MachO;
    report.os = Some("macOS / Apple".to_owned());
    report.confidence = 0.98;
    report.evidence.push("Mach-O magic".to_owned());

    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let (endian, bits) = match magic {
        [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => (Endian::Big, 32),
        [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => (Endian::Big, 64),
        _ => (Endian::Little, 64),
    };
    // The byte order is encoded by which magic we saw; for the common
    // little-endian files the stored fields are little-endian.
    let endian = if matches!(magic, [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe]) {
        Endian::Little
    } else {
        endian
    };

    let cputype = endian.u32(bytes, 4).unwrap_or(0);
    let filetype = endian.u32(bytes, 12).unwrap_or(0);
    report.bits = Some(bits);
    report.endian = Some(endian);
    report.architecture = macho_cpu(cputype).map(str::to_owned);
    report.kind = Some(
        match filetype {
            1 => "object",
            2 => "executable",
            6 => "library",
            8 => "bundle",
            _ => "other",
        }
        .to_owned(),
    );

    let header_size = if bits == 64 { 32 } else { 28 };
    let ncmds = endian.u32(bytes, 16).unwrap_or(0) as usize;
    let mut offset = header_size;
    for _ in 0..ncmds.min(4096) {
        let Some(cmd) = endian.u32(bytes, offset) else {
            break;
        };
        let Some(cmdsize) = endian.u32(bytes, offset + 4) else {
            break;
        };
        if cmdsize < 8 {
            report
                .warnings
                .push("invalid Mach-O load command size".to_owned());
            break;
        }
        let command = cmd & 0x7fff_ffff;
        if command == 0x19 || command == 0x1 {
            // LC_SEGMENT_64 / LC_SEGMENT
            let is64 = command == 0x19;
            let (name_offset, nsects_offset, section_offset, section_size) = if is64 {
                (8, 64, 72, 80)
            } else {
                (8, 48, 56, 68)
            };
            let segment_name = c_string(bytes, offset + name_offset).unwrap_or_default();
            let nsects = endian.u32(bytes, offset + nsects_offset).unwrap_or(0) as usize;
            let mut section_cursor = offset + section_offset;
            for _ in 0..nsects.min(1024) {
                let section_name = c_string(bytes, section_cursor).unwrap_or_default();
                let address = if is64 {
                    endian.u64(bytes, section_cursor + 32).unwrap_or(0)
                } else {
                    endian
                        .u32(bytes, section_cursor + 32)
                        .map(u64::from)
                        .unwrap_or(0)
                };
                let section_length = if is64 {
                    endian.u64(bytes, section_cursor + 40).unwrap_or(0)
                } else {
                    endian
                        .u32(bytes, section_cursor + 36)
                        .map(u64::from)
                        .unwrap_or(0)
                };
                let kind = if section_name == "__text" {
                    "code".to_owned()
                } else if section_name == "__bss" {
                    "bss".to_owned()
                } else {
                    "data".to_owned()
                };
                let full_name = if segment_name.is_empty() {
                    section_name
                } else {
                    format!("{segment_name},{section_name}")
                };
                report.sections.push(SectionInfo {
                    name: full_name,
                    address,
                    size: section_length,
                    file_size: None,
                    kind,
                });
                section_cursor = section_cursor.saturating_add(section_size);
            }
        }
        offset = offset.saturating_add(cmdsize as usize);
    }
    report
}

fn parse_java_or_fat_macho(bytes: &[u8], size: u64) -> DetectionReport {
    // Both Java class files and universal Mach-O binaries start with CAFEBABE.
    // Java stores minor/major versions at offsets 4 and 6; fat Mach-O stores
    // an architecture count there.
    let fat_count = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let first_cpu = bytes
        .get(8..12)
        .map(|slice| u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
    let looks_like_fat = (1..=64).contains(&fat_count)
        && first_cpu
            .map(|cpu| macho_cpu(cpu).is_some() || cpu & 0xff00_0000 == 0x0100_0000)
            .unwrap_or(false);
    if looks_like_fat {
        let mut report = DetectionReport::unknown(size);
        report.format = BinaryFormat::MachO;
        report.os = Some("macOS / Apple".to_owned());
        report.kind = Some("universal binary".to_owned());
        report.confidence = 0.95;
        report.evidence.push("Mach-O fat header".to_owned());
        report
            .warnings
            .push("universal binaries contain multiple architectures".to_owned());
        return report;
    }

    let major = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut report = DetectionReport::unknown(size);
    if major >= 45 {
        report.format = BinaryFormat::JavaClass;
        report.architecture = Some("JVM".to_owned());
        report.bits = Some(32);
        report.endian = Some(Endian::Big);
        report.os = Some("JVM (platform independent)".to_owned());
        report.kind = Some("class".to_owned());
        report.language = Some(format!("Java (class version {major})"));
        report.language_confidence = 0.95;
        report.confidence = 1.0;
        report.evidence.push("CAFEBABE Java class magic".to_owned());
    } else {
        report.evidence.push("CAFEBABE signature".to_owned());
    }
    report
}

fn scan_language_hints(
    file: &mut File,
    size: u64,
    report: &mut DetectionReport,
) -> std::io::Result<()> {
    if report.language.is_some() {
        return Ok(());
    }
    let length = size.min(LANGUAGE_SCAN_BYTES) as usize;
    if length == 0 {
        return Ok(());
    }
    let mut bytes = vec![0u8; length];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;

    let hints: &[(&[u8], &str, f32, Option<&str>)] = &[
        (b"Go build ID:", "Go", 0.95, Some("Go toolchain")),
        (b"runtime.gopanic", "Go", 0.85, Some("Go runtime")),
        (b".gopclntab", "Go", 0.85, Some("Go runtime")),
        (b"rust_begin_unwind", "Rust", 0.9, Some("rustc")),
        (b"core::panicking", "Rust", 0.85, Some("rustc")),
        (b"RUST_BACKTRACE", "Rust", 0.7, Some("rustc")),
        (b"mscorlib", "C# / .NET", 0.8, Some(".NET runtime")),
        (
            b"System.Private.CoreLib",
            "C# / .NET",
            0.85,
            Some(".NET runtime"),
        ),
        (b"_CorExeMain", "C# / .NET", 0.8, Some(".NET runtime")),
        (
            b"objc_msgSend",
            "Objective-C",
            0.8,
            Some("Apple Objective-C runtime"),
        ),
        (
            b"__objc",
            "Objective-C",
            0.65,
            Some("Apple Objective-C runtime"),
        ),
        (b"swift_", "Swift", 0.7, Some("Swift runtime")),
        (b"java/lang/", "Java", 0.7, Some("JVM")),
        (b"Py_Initialize", "Python", 0.6, Some("CPython")),
        (b"python3", "Python", 0.4, Some("CPython")),
        (b"GLIBCXX", "C++", 0.75, Some("GCC/libstdc++")),
        (b"libstdc++", "C++", 0.7, Some("GCC/libstdc++")),
        (b"Microsoft (R) C/C++", "C/C++", 0.8, Some("MSVC")),
        (b"clang version", "C/C++", 0.6, Some("Clang")),
        (b"GCC: (", "C/C++", 0.6, Some("GCC")),
        (b"Borland", "Delphi / C++", 0.5, Some("Borland")),
    ];

    let mut best: Option<(&str, f32, &str)> = None;
    for (needle, language, confidence, compiler) in hints {
        if find_bytes(&bytes, needle).is_some() {
            report.evidence.push(format!(
                "found marker '{}'",
                String::from_utf8_lossy(needle)
            ));
            if best
                .map(|(_, value, _)| *confidence > value)
                .unwrap_or(true)
            {
                best = Some((language, *confidence, compiler.unwrap_or("unknown")));
            }
        }
    }

    if let Some((language, confidence, compiler)) = best {
        report.language = Some(language.to_owned());
        report.language_confidence = confidence;
        if report.compiler.is_none() {
            report.compiler = Some(compiler.to_owned());
        }
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    memchr::memmem::find(haystack, needle)
}

fn fixed_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

fn c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let slice = bytes.get(offset..)?;
    let end = slice.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

fn pe_machine(value: u16) -> Option<&'static str> {
    Some(match value {
        0x14c => "x86",
        0x8664 => "x86-64",
        0x1c0 => "ARM",
        0x1c4 => "ARM Thumb-2",
        0xaa64 => "ARM64",
        0x200 => "IA-64",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        0xebc => "EFI bytecode",
        0x9041 => "M32R",
        _ => return None,
    })
}

fn elf_machine(value: u16) -> Option<&'static str> {
    Some(match value {
        2 => "SPARC",
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC 64",
        22 => "IBM S/390",
        40 => "ARM",
        43 => "SPARC V9",
        50 => "IA-64",
        62 => "x86-64",
        183 => "ARM64",
        243 => "RISC-V",
        258 => "LoongArch",
        _ => return None,
    })
}

fn macho_cpu(value: u32) -> Option<&'static str> {
    Some(match value {
        7 => "x86",
        0x0100_0007 => "x86-64",
        12 => "ARM",
        0x0100_000c => "ARM64",
        18 => "PowerPC",
        0x0100_0012 => "PowerPC 64",
        _ => return None,
    })
}

fn python_magic(magic: [u8; 4]) -> Option<&'static str> {
    // Magic numbers are stable for CPython releases. This list covers the
    // 3.x series commonly found in the wild; unknown versions remain unknown.
    Some(match magic {
        [0x42, 0x0d, 0x0d, 0x0a] => "3.6",
        [0x33, 0x0d, 0x0d, 0x0a] => "3.7",
        [0x55, 0x0d, 0x0d, 0x0a] => "3.8",
        [0x61, 0x0d, 0x0d, 0x0a] => "3.9",
        [0x6f, 0x0d, 0x0d, 0x0a] => "3.10",
        [0xa7, 0x0d, 0x0d, 0x0a] => "3.11",
        [0xcb, 0x0d, 0x0d, 0x0a] => "3.12",
        [0xf3, 0x0d, 0x0d, 0x0a] => "3.13",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF header: x86-64, 1 section, optional header size 0xF0.
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        // PE32+ optional header.
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0x98 + 16..0x98 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x98 + 24..0x98 + 32].copy_from_slice(&0x1400_0000u64.to_le_bytes());
        // One .text section.
        let section = 0x98 + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes
    }

    fn minimal_elf() -> Vec<u8> {
        let mut bytes = vec![0u8; 128];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // 64-bit
        bytes[5] = 1; // little-endian
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // executable
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        bytes
    }

    #[test]
    fn detects_pe_architecture_and_sections() {
        let report = detect_prefix(&minimal_pe(), 0x400);
        assert_eq!(report.format, BinaryFormat::Pe);
        assert_eq!(report.architecture.as_deref(), Some("x86-64"));
        assert_eq!(report.bits, Some(64));
        assert_eq!(report.entry_point, Some(0x1400_1000));
        assert!(
            report
                .sections
                .iter()
                .any(|section| section.name == ".text")
        );
    }

    #[test]
    fn detects_elf_architecture_and_entry() {
        let report = detect_prefix(&minimal_elf(), 128);
        assert_eq!(report.format, BinaryFormat::Elf);
        assert_eq!(report.architecture.as_deref(), Some("x86-64"));
        assert_eq!(report.entry_point, Some(0x401000));
        assert_eq!(report.kind.as_deref(), Some("executable"));
    }

    #[test]
    fn detects_java_class() {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        bytes[6..8].copy_from_slice(&61u16.to_be_bytes());
        let report = detect_prefix(&bytes, 16);
        assert_eq!(report.format, BinaryFormat::JavaClass);
        assert_eq!(report.architecture.as_deref(), Some("JVM"));
    }

    #[test]
    fn detects_wasm_and_unknown() {
        let wasm = detect_prefix(b"\0asm\x01\0\0\0", 8);
        assert_eq!(wasm.format, BinaryFormat::Wasm);
        let unknown = detect_prefix(b"hello world", 11);
        assert_eq!(unknown.format, BinaryFormat::Unknown);
    }
}
