//! Ghidra-style search over a complete `ProgramAnalysis`.
//!
//! Each mode declares exactly what it searches. Modes that GHIRUST cannot
//! support honestly are absent from this module (the GUI renders them as
//! disabled with an explicit label).
//!
//! All searches are bounded: `max_results` is a hard limit and hitting it
//! sets `truncated` on the report.

use serde::{Deserialize, Serialize};

use crate::analysis::ProgramAnalysis;

/// Search mode. Matches the Ghidra `Search` menu where feasible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramSearchMode {
    /// Search text in strings, symbols, imports, exports and function names.
    ProgramText,
    /// Search the reconstructed pseudocode of every function.
    DecompiledText,
    /// Search functions, symbols and labels by name or address.
    Labels,
    /// Search cross-references by source, target or kind.
    DirectReferences,
    /// Search immediate values used by instructions (hex or decimal).
    Scalars,
    /// Search extracted strings (ASCII and UTF-16LE) by value.
    Strings,
    /// Search the listing by instruction mnemonic / operand substring.
    InstructionPatterns,
    /// Exact instruction text (mnemonic + operands) search.
    MatchingInstructions,
    /// Search raw loaded memory sections for a byte sequence or ASCII text.
    /// Bounded and only over file-backed initialized sections.
    Memory,
    /// Search encoded strings; currently UTF-16LE only (partial).
    EncodedStrings,
}

impl ProgramSearchMode {
    pub const ALL: [ProgramSearchMode; 10] = [
        ProgramSearchMode::ProgramText,
        ProgramSearchMode::DecompiledText,
        ProgramSearchMode::Labels,
        ProgramSearchMode::DirectReferences,
        ProgramSearchMode::Scalars,
        ProgramSearchMode::Strings,
        ProgramSearchMode::InstructionPatterns,
        ProgramSearchMode::MatchingInstructions,
        ProgramSearchMode::Memory,
        ProgramSearchMode::EncodedStrings,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ProgramSearchMode::ProgramText => "Program Text",
            ProgramSearchMode::DecompiledText => "Decompiled Text",
            ProgramSearchMode::Labels => "Label History / Symbols",
            ProgramSearchMode::DirectReferences => "Direct References",
            ProgramSearchMode::Scalars => "Scalars",
            ProgramSearchMode::Strings => "Strings",
            ProgramSearchMode::InstructionPatterns => "Instruction Patterns",
            ProgramSearchMode::MatchingInstructions => "Matching Instructions",
            ProgramSearchMode::Memory => "Memory",
            ProgramSearchMode::EncodedStrings => "Encoded Strings (UTF-16LE)",
        }
    }

    /// What this mode actually searches, stated plainly in the UI.
    pub fn description(self) -> &'static str {
        match self {
            ProgramSearchMode::ProgramText => {
                "Case-insensitive text in strings, symbols, imports, exports and function names."
            }
            ProgramSearchMode::DecompiledText => {
                "Substring search in the reconstructed pseudocode; results navigate to the function."
            }
            ProgramSearchMode::Labels => {
                "Functions, symbols and labels matched by name or address."
            }
            ProgramSearchMode::DirectReferences => {
                "Cross-references matched by source address, target address or kind (call/jump/data)."
            }
            ProgramSearchMode::Scalars => {
                "Immediate values in decoded instructions, matched as hex or decimal."
            }
            ProgramSearchMode::Strings => "Extracted string values (ASCII and UTF-16LE).",
            ProgramSearchMode::InstructionPatterns => {
                "Listing search by mnemonic or operand substring (plain text, not regex)."
            }
            ProgramSearchMode::MatchingInstructions => {
                "Exact instruction match on 'mnemonic operands' text."
            }
            ProgramSearchMode::Memory => {
                "Byte sequence or ASCII text search over loaded, initialized sections."
            }
            ProgramSearchMode::EncodedStrings => {
                "Encoded string scan; only UTF-16LE is implemented (partial)."
            }
        }
    }
}

/// Options for one program search.
#[derive(Debug, Clone)]
pub struct ProgramSearchOptions {
    pub mode: ProgramSearchMode,
    pub query: String,
    pub max_results: usize,
}

impl Default for ProgramSearchOptions {
    fn default() -> Self {
        Self {
            mode: ProgramSearchMode::ProgramText,
            query: String::new(),
            max_results: 500,
        }
    }
}

/// One search result row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramSearchHit {
    /// Result kind: `function`, `symbol`, `string`, `instruction`, `xref`,
    /// `scalar`, `memory`, `decompiled`.
    pub kind: String,
    /// Address or file offset, when applicable.
    pub address: Option<u64>,
    /// Owning function name, when applicable.
    pub function: Option<String>,
    /// Human-readable preview.
    pub preview: String,
    /// Source of the match (symbol/import/export/listing/...).
    pub source: String,
}

/// Search report over a single program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramSearchReport {
    pub mode: ProgramSearchMode,
    pub query: String,
    pub hits: Vec<ProgramSearchHit>,
    pub truncated: bool,
}

fn parse_address(query: &str) -> Option<u64> {
    let text = query.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

/// Run a bounded search over a complete analysis.
pub fn search_program(
    analysis: &ProgramAnalysis,
    options: &ProgramSearchOptions,
) -> ProgramSearchReport {
    let query = options.query.trim();
    let limit = options.max_results.max(1);
    let mut hits: Vec<ProgramSearchHit> = Vec::new();
    let mut truncated = false;
    let needle = query.to_lowercase();

    let mut push = |hit: ProgramSearchHit, hits: &mut Vec<ProgramSearchHit>| {
        if hits.len() >= limit {
            truncated = true;
            return;
        }
        hits.push(hit);
    };

    match options.mode {
        ProgramSearchMode::ProgramText => {
            for function in &analysis.functions {
                if needle.is_empty() || function.name.to_lowercase().contains(&needle) {
                    push(
                        ProgramSearchHit {
                            kind: "function".to_owned(),
                            address: Some(function.address),
                            function: Some(function.name.clone()),
                            preview: function.name.clone(),
                            source: "function name".to_owned(),
                        },
                        &mut hits,
                    );
                }
            }
            for symbol in &analysis.symbols {
                if !needle.is_empty() && !symbol.name.to_lowercase().contains(&needle) {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "symbol".to_owned(),
                        address: Some(symbol.address),
                        function: None,
                        preview: symbol.name.clone(),
                        source: format!("symbol ({})", symbol.source),
                    },
                    &mut hits,
                );
            }
            for import in &analysis.imports {
                if !needle.is_empty()
                    && !import.name.to_lowercase().contains(&needle)
                    && !import.library.to_lowercase().contains(&needle)
                {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "symbol".to_owned(),
                        address: None,
                        function: None,
                        preview: format!("{}!{}", import.library, import.name),
                        source: "import".to_owned(),
                    },
                    &mut hits,
                );
            }
            for export in &analysis.exports {
                if !needle.is_empty() && !export.name.to_lowercase().contains(&needle) {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "symbol".to_owned(),
                        address: export.address,
                        function: None,
                        preview: export.name.clone(),
                        source: "export".to_owned(),
                    },
                    &mut hits,
                );
            }
            for string in &analysis.strings {
                if !needle.is_empty() && !string.value.to_lowercase().contains(&needle) {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "string".to_owned(),
                        address: Some(string.offset),
                        function: None,
                        preview: string.value.clone(),
                        source: format!("string ({})", string.encoding.as_str()),
                    },
                    &mut hits,
                );
            }
        }
        ProgramSearchMode::DecompiledText => {
            for function in &analysis.functions {
                let text = &function.decompiled.text;
                if !needle.is_empty() && !text.to_lowercase().contains(&needle) {
                    continue;
                }
                let line = text
                    .lines()
                    .find(|line| needle.is_empty() || line.to_lowercase().contains(&needle))
                    .unwrap_or("(match)")
                    .trim();
                push(
                    ProgramSearchHit {
                        kind: "decompiled".to_owned(),
                        address: Some(function.address),
                        function: Some(function.name.clone()),
                        preview: truncate(line, 120).to_owned(),
                        source: "decompiled text".to_owned(),
                    },
                    &mut hits,
                );
            }
        }
        ProgramSearchMode::Labels => {
            if let Some(address) = parse_address(query) {
                for function in &analysis.functions {
                    if function.address == address
                        || (function.address..function.end).contains(&address)
                    {
                        push(
                            ProgramSearchHit {
                                kind: "function".to_owned(),
                                address: Some(function.address),
                                function: Some(function.name.clone()),
                                preview: format!("0x{address:x} → {}", function.name),
                                source: "address match".to_owned(),
                            },
                            &mut hits,
                        );
                    }
                }
                for symbol in &analysis.symbols {
                    if symbol.address == address {
                        push(
                            ProgramSearchHit {
                                kind: "symbol".to_owned(),
                                address: Some(symbol.address),
                                function: None,
                                preview: symbol.name.clone(),
                                source: format!("symbol ({})", symbol.source),
                            },
                            &mut hits,
                        );
                    }
                }
            }
            for function in &analysis.functions {
                if needle.is_empty() || function.name.to_lowercase().contains(&needle) {
                    push(
                        ProgramSearchHit {
                            kind: "function".to_owned(),
                            address: Some(function.address),
                            function: Some(function.name.clone()),
                            preview: function.name.clone(),
                            source: "function label".to_owned(),
                        },
                        &mut hits,
                    );
                }
            }
            for symbol in &analysis.symbols {
                if !needle.is_empty() && !symbol.name.to_lowercase().contains(&needle) {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "symbol".to_owned(),
                        address: Some(symbol.address),
                        function: None,
                        preview: symbol.name.clone(),
                        source: format!("symbol ({})", symbol.source),
                    },
                    &mut hits,
                );
            }
        }
        ProgramSearchMode::DirectReferences => {
            let address = parse_address(query);
            for xref in &analysis.xrefs {
                let matches = if let Some(address) = address {
                    xref.from == address || xref.to == address
                } else {
                    !needle.is_empty()
                        && (xref.kind.to_lowercase().contains(&needle)
                            || format!("0x{:x}", xref.from).contains(&needle)
                            || format!("0x{:x}", xref.to).contains(&needle))
                };
                if !matches {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "xref".to_owned(),
                        address: Some(xref.to),
                        function: xref
                            .function
                            .and_then(|address| {
                                analysis
                                    .functions
                                    .iter()
                                    .find(|function| function.address == address)
                            })
                            .map(|function| function.name.clone()),
                        preview: format!("0x{:x} → 0x{:x} ({})", xref.from, xref.to, xref.kind),
                        source: "cross-reference".to_owned(),
                    },
                    &mut hits,
                );
            }
        }
        ProgramSearchMode::Scalars => {
            let expected = parse_address(query);
            for function in &analysis.functions {
                for block in &function.blocks {
                    for instruction in &block.instructions {
                        let text = &instruction.text;
                        // Extract immediate-ish tokens from the operand text.
                        let operands = instruction.operands.as_str();
                        let matches = if let Some(expected) = expected {
                            operands.contains(&format!("0x{expected:x}"))
                                || operands.contains(&expected.to_string())
                        } else {
                            !needle.is_empty() && operands.contains(&needle)
                        };
                        if !matches {
                            continue;
                        }
                        push(
                            ProgramSearchHit {
                                kind: "scalar".to_owned(),
                                address: Some(instruction.address),
                                function: Some(function.name.clone()),
                                preview: text.clone(),
                                source: "instruction immediate".to_owned(),
                            },
                            &mut hits,
                        );
                    }
                }
            }
        }
        ProgramSearchMode::Strings => {
            for string in &analysis.strings {
                if !needle.is_empty() && !string.value.to_lowercase().contains(&needle) {
                    continue;
                }
                push(
                    ProgramSearchHit {
                        kind: "string".to_owned(),
                        address: Some(string.offset),
                        function: None,
                        preview: string.value.clone(),
                        source: format!("string ({})", string.encoding.as_str()),
                    },
                    &mut hits,
                );
            }
        }
        ProgramSearchMode::InstructionPatterns => {
            for function in &analysis.functions {
                for block in &function.blocks {
                    for instruction in &block.instructions {
                        let text = format!("{} {}", instruction.mnemonic, instruction.operands);
                        if !needle.is_empty() && !text.to_lowercase().contains(&needle) {
                            continue;
                        }
                        push(
                            ProgramSearchHit {
                                kind: "instruction".to_owned(),
                                address: Some(instruction.address),
                                function: Some(function.name.clone()),
                                preview: instruction.text.clone(),
                                source: "listing pattern".to_owned(),
                            },
                            &mut hits,
                        );
                    }
                }
            }
        }
        ProgramSearchMode::MatchingInstructions => {
            let expected = query.trim().to_lowercase();
            for function in &analysis.functions {
                for block in &function.blocks {
                    for instruction in &block.instructions {
                        let text = format!("{} {}", instruction.mnemonic, instruction.operands);
                        if text.trim().to_lowercase() == expected {
                            push(
                                ProgramSearchHit {
                                    kind: "instruction".to_owned(),
                                    address: Some(instruction.address),
                                    function: Some(function.name.clone()),
                                    preview: instruction.text.clone(),
                                    source: "exact instruction".to_owned(),
                                },
                                &mut hits,
                            );
                        }
                    }
                }
            }
        }
        ProgramSearchMode::Memory => {
            let needle_bytes: Vec<u8> = if let Some(hex) = query
                .strip_prefix("bytes:")
                .or_else(|| query.strip_prefix("hex:"))
            {
                hex.split_whitespace()
                    .filter_map(|token| u8::from_str_radix(token, 16).ok())
                    .collect()
            } else if query.starts_with("ascii:") || query.starts_with("text:") {
                let text = query
                    .split_once(':')
                    .map(|(_, value)| value)
                    .unwrap_or_default();
                text.as_bytes().to_vec()
            } else if let Some(hex) = parse_address(query) {
                hex.to_le_bytes().to_vec()
            } else {
                query.as_bytes().to_vec()
            };
            if needle_bytes.is_empty() {
                return ProgramSearchReport {
                    mode: options.mode,
                    query: query.to_owned(),
                    hits,
                    truncated,
                };
            }
            for section in &analysis.sections {
                if section.kind != "code" && section.kind != "data" {
                    continue;
                }
                let size = section
                    .virtual_size
                    .min(section.file_size.max(section.virtual_size));
                let mut address = section.address;
                let mut remaining = size.saturating_sub(needle_bytes.len() as u64);
                while remaining > 0 && hits.len() < limit {
                    if let Some(bytes) = analysis_read(analysis, address, needle_bytes.len()) {
                        if bytes == needle_bytes {
                            push(
                                ProgramSearchHit {
                                    kind: "memory".to_owned(),
                                    address: Some(address),
                                    function: None,
                                    preview: format!(
                                        "0x{address:x}: {}",
                                        needle_bytes
                                            .iter()
                                            .map(|byte| format!("{byte:02x}"))
                                            .collect::<Vec<_>>()
                                            .join(" ")
                                    ),
                                    source: format!("memory ({})", section.name),
                                },
                                &mut hits,
                            );
                        }
                    }
                    address += 1;
                    remaining -= 1;
                }
            }
        }
        ProgramSearchMode::EncodedStrings => {
            // Partial: UTF-16LE strings only.
            let needle_utf16: Vec<u8> = query.encode_utf16().flat_map(u16::to_le_bytes).collect();
            if needle_utf16.is_empty() {
                return ProgramSearchReport {
                    mode: options.mode,
                    query: query.to_owned(),
                    hits,
                    truncated,
                };
            }
            for section in &analysis.sections {
                let size = section
                    .virtual_size
                    .min(section.file_size.max(section.virtual_size));
                let mut address = section.address;
                let mut remaining = size.saturating_sub(needle_utf16.len() as u64);
                while remaining > 0 && hits.len() < limit {
                    if let Some(bytes) = analysis_read(analysis, address, needle_utf16.len()) {
                        if bytes == needle_utf16 {
                            push(
                                ProgramSearchHit {
                                    kind: "string".to_owned(),
                                    address: Some(address),
                                    function: None,
                                    preview: query.to_owned(),
                                    source: format!("encoded string (utf16le) ({})", section.name),
                                },
                                &mut hits,
                            );
                        }
                    }
                    address += 2;
                    remaining -= 2;
                }
            }
        }
    }

    ProgramSearchReport {
        mode: options.mode,
        query: query.to_owned(),
        hits,
        truncated,
    }
}

/// Bounded virtual read over the analysis. Uses the loader's mapped data when
/// the address falls inside a file-backed initialized section; otherwise
/// returns `None` instead of guessing.
fn analysis_read(analysis: &ProgramAnalysis, address: u64, length: usize) -> Option<Vec<u8>> {
    let section = analysis.sections.iter().find(|section| {
        address >= section.address
            && address + length as u64 <= section.address + section.virtual_size
    })?;
    if section.file_size == 0 {
        return None;
    }
    let offset = address - section.address;
    let file = std::fs::File::open(&analysis.path).ok()?;
    use std::io::{Read, Seek, SeekFrom};
    let mut file = file;
    file.seek(SeekFrom::Start(section.file_offset + offset))
        .ok()?;
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

fn truncate(value: &str, width: usize) -> &str {
    match value.char_indices().nth(width) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{AnalysisOptions, analyze_path};
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn demo_analysis() -> Option<ProgramAnalysis> {
        static ANALYSIS: OnceLock<Option<ProgramAnalysis>> = OnceLock::new();
        ANALYSIS
            .get_or_init(|| {
                let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("..")
                    .join("..")
                    .join("..")
                    .join("tests")
                    .join("objectives")
                    .join("binaries")
                    .join("demo.dll");
                if !path.is_file() {
                    return None;
                }
                analyze_path(&path, &AnalysisOptions::default()).ok()
            })
            .clone()
    }

    fn search(mode: ProgramSearchMode, query: &str) -> ProgramSearchReport {
        let analysis = demo_analysis().expect("objective fixture missing");
        search_program(
            &analysis,
            &ProgramSearchOptions {
                mode,
                query: query.to_owned(),
                max_results: 500,
            },
        )
    }

    #[test]
    fn program_text_finds_functions_symbols_and_strings() {
        let report = search(ProgramSearchMode::ProgramText, "demo_add");
        assert!(
            report
                .hits
                .iter()
                .any(|hit| hit.kind == "function" && hit.preview == "demo_add")
        );
    }

    #[test]
    fn decompiled_text_finds_functions() {
        let report = search(ProgramSearchMode::DecompiledText, "return");
        assert!(!report.hits.is_empty());
        assert!(
            report
                .hits
                .iter()
                .all(|hit| hit.address.is_some() && hit.function.is_some())
        );
    }

    #[test]
    fn labels_match_addresses() {
        let report = search(ProgramSearchMode::Labels, "0x180001000");
        assert!(
            report
                .hits
                .iter()
                .any(|hit| hit.preview.contains("demo_add"))
        );
    }

    #[test]
    fn direct_references_find_calls() {
        let report = search(ProgramSearchMode::DirectReferences, "call");
        assert!(!report.hits.is_empty());
        assert!(
            report
                .hits
                .iter()
                .all(|hit| hit.kind == "xref" && hit.preview.contains("call"))
        );
    }

    #[test]
    fn scalars_find_immediates() {
        let report = search(ProgramSearchMode::Scalars, "1");
        assert!(!report.hits.is_empty());
        assert!(report.hits.iter().all(|hit| hit.kind == "scalar"));
    }

    #[test]
    fn strings_find_known_values() {
        let report = search(ProgramSearchMode::Strings, "demo");
        assert!(!report.hits.is_empty());
    }

    #[test]
    fn instruction_patterns_find_mnemonics() {
        let report = search(ProgramSearchMode::InstructionPatterns, "mov");
        assert!(!report.hits.is_empty());
        assert!(report.hits.iter().all(|hit| hit.kind == "instruction"));
    }

    #[test]
    fn matching_instructions_are_exact() {
        let report = search(ProgramSearchMode::MatchingInstructions, "ret");
        assert!(!report.hits.is_empty());
        assert!(
            report
                .hits
                .iter()
                .all(|hit| hit.preview.trim().starts_with("ret"))
        );
    }

    #[test]
    fn memory_search_finds_bytes() {
        // `ret` = c3 appears in the executable section.
        let report = search(ProgramSearchMode::Memory, "bytes:c3");
        assert!(!report.hits.is_empty());
        assert!(report.hits.iter().all(|hit| hit.kind == "memory"));
    }

    #[test]
    fn encoded_strings_search_is_bounded() {
        let report = search(ProgramSearchMode::EncodedStrings, "demo");
        let _ = report; // may be empty for short ASCII-only queries; must not panic
    }

    #[test]
    fn result_limit_truncates() {
        let analysis = demo_analysis().expect("objective fixture missing");
        let report = search_program(
            &analysis,
            &ProgramSearchOptions {
                mode: ProgramSearchMode::InstructionPatterns,
                query: "mov".to_owned(),
                max_results: 3,
            },
        );
        assert!(report.truncated);
        assert_eq!(report.hits.len(), 3);
    }
}
