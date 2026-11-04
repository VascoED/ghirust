//! Extract printable ASCII and UTF-16LE strings from a binary.
//!
//! The file is memory-mapped read-only, so extracting strings from a large
//! DLL does not duplicate the binary in RAM. Results are capped and can be
//! deduplicated, which keeps output usable for binaries that repeat the same
//! runtime strings thousands of times.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::filemap::ReadOnlyMap;

/// Encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// Printable ASCII.
    Ascii,
    /// UTF-16 little-endian with ASCII code units.
    Utf16Le,
}

impl StringEncoding {
    /// Short display name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf16le",
        }
    }
}

/// One extracted string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringRecord {
    /// Byte offset in the file.
    pub offset: u64,
    /// Encoding used by the string.
    pub encoding: StringEncoding,
    /// Decoded text.
    pub value: String,
}

/// String extraction options.
#[derive(Debug, Clone)]
pub struct StringOptions {
    /// Minimum number of characters.
    pub min_length: usize,
    /// Scan UTF-16LE strings as well as ASCII.
    pub utf16: bool,
    /// Drop duplicate values.
    pub deduplicate: bool,
    /// Maximum number of strings returned.
    pub limit: usize,
}

impl Default for StringOptions {
    fn default() -> Self {
        Self {
            min_length: 4,
            utf16: true,
            deduplicate: false,
            limit: 10_000,
        }
    }
}

/// Extract strings from `path`.
pub fn extract_strings(path: &Path, options: &StringOptions) -> Result<Vec<StringRecord>> {
    let map = ReadOnlyMap::open(path)?;
    let bytes = map.bytes();
    let mut records = Vec::new();
    let mut seen = HashSet::new();

    scan_ascii(bytes, options, &mut records, &mut seen);
    if options.utf16 && records.len() < options.limit {
        scan_utf16(bytes, options, &mut records, &mut seen);
    }
    records.sort_by_key(|record| record.offset);
    records.truncate(options.limit);
    Ok(records)
}

fn scan_ascii(
    bytes: &[u8],
    options: &StringOptions,
    records: &mut Vec<StringRecord>,
    seen: &mut HashSet<String>,
) {
    let mut index = 0usize;
    while index < bytes.len() && records.len() < options.limit {
        if !is_printable(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_printable(bytes[index]) {
            index += 1;
        }
        if index - start >= options.min_length {
            let value = String::from_utf8_lossy(&bytes[start..index]).to_string();
            push(records, seen, options, start as u64, StringEncoding::Ascii, value);
        }
    }
}

fn scan_utf16(
    bytes: &[u8],
    options: &StringOptions,
    records: &mut Vec<StringRecord>,
    seen: &mut HashSet<String>,
) {
    let mut index = 0usize;
    while index + 1 < bytes.len() && records.len() < options.limit {
        if !(is_printable(bytes[index]) && bytes[index + 1] == 0) {
            index += 1;
            continue;
        }
        let start = index;
        let mut value = Vec::new();
        while index + 1 < bytes.len() && is_printable(bytes[index]) && bytes[index + 1] == 0 {
            value.push(bytes[index]);
            index += 2;
        }
        if value.len() >= options.min_length {
            let text = String::from_utf8_lossy(&value).to_string();
            push(
                records,
                seen,
                options,
                start as u64,
                StringEncoding::Utf16Le,
                text,
            );
        }
    }
}

fn push(
    records: &mut Vec<StringRecord>,
    seen: &mut HashSet<String>,
    options: &StringOptions,
    offset: u64,
    encoding: StringEncoding,
    value: String,
) {
    if options.deduplicate && !seen.insert(value.clone()) {
        return;
    }
    records.push(StringRecord {
        offset,
        encoding,
        value,
    });
}

fn is_printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) || byte == b'\t'
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn extracts_ascii_and_utf16_strings() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sample.bin");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\x00\x01Hello, GHIRUST\x00\x02");
        for character in "WideString".bytes() {
            bytes.push(character);
            bytes.push(0);
        }
        bytes.push(0);
        fs::write(&path, bytes).unwrap();

        let records = extract_strings(&path, &StringOptions::default()).unwrap();
        assert!(records.iter().any(|record| record.value == "Hello, GHIRUST"));
        assert!(records.iter().any(|record| record.value == "WideString"));
        assert!(records.iter().all(|record| record.value.len() >= 4));
    }

    #[test]
    fn honours_minimum_length_and_limit() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sample.bin");
        fs::write(&path, b"abcd\0abc\0longer-string\0another-one").unwrap();

        let records = extract_strings(
            &path,
            &StringOptions {
                min_length: 5,
                utf16: false,
                deduplicate: false,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "longer-string");
    }

    #[test]
    fn deduplicates_repeated_values() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sample.bin");
        fs::write(&path, b"repeat\0repeat\0other\0").unwrap();

        let records = extract_strings(
            &path,
            &StringOptions {
                deduplicate: true,
                utf16: false,
                ..StringOptions::default()
            },
        )
        .unwrap();
        let values: Vec<_> = records.iter().map(|record| record.value.as_str()).collect();
        assert_eq!(values, vec!["repeat", "other"]);
    }

    #[test]
    fn rejects_empty_files() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        assert!(extract_strings(&path, &StringOptions::default()).is_err());
    }
}
