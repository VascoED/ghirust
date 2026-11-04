//! Data exchanged with analysis backends.

use serde::{Deserialize, Serialize};

/// One decompiled function.
///
/// This is the record format accepted by `ghirust export` when the input is a
/// newline-delimited JSON (NDJSON) file. Keeping one function per line is what
/// makes bounded-memory export possible: GHIRUST only ever holds one record at
/// a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// Human-readable function name, for example `FUN_00401000`.
    pub name: String,
    /// Optional virtual address such as `0x00401000`.
    #[serde(default)]
    pub address: Option<String>,
    /// Optional kind (`function`, `thunk`, `external`, ...).
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional source path (module or original file).
    #[serde(default)]
    pub source: Option<String>,
    /// The decompiled body.
    pub code: String,
}

/// Entry written by the Ghidra bridge into `manifest.ndjson`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRecord {
    /// Function name.
    pub name: String,
    /// Optional virtual address.
    #[serde(default)]
    pub address: Option<String>,
    /// Name of the file containing the body.
    pub file: String,
}

/// One manifest entry produced by the streaming exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFunction {
    /// Function name.
    pub name: String,
    /// Optional virtual address.
    #[serde(default)]
    pub address: Option<String>,
    /// Byte offset in the *uncompressed* output where the function starts.
    pub offset: u64,
    /// Number of uncompressed bytes written for this function.
    pub length: u64,
}
