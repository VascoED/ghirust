//! GHIRUST core: search indexing, fast text search and bounded-memory export.
//!
//! The crate deliberately contains no decompiler. It is the reusable engine
//! around a decompiler:
//!
//! * [`index`] builds a persistent symbol/function index over exported code.
//! * [`search`] queries that index and memory-maps the source text.
//! * [`export`] turns a stream of functions into one output file without ever
//!   materialising the whole output in RAM.
//!
//! The public surface is intentionally small so that the command line
//! application, the future egui Command Center and Ghidra integration scripts
//! all use exactly the same implementation.

pub mod cache;
pub mod detect;
pub mod error;
pub mod export;
pub mod filemap;
pub mod index;
pub mod ir;
pub mod model;
pub mod search;
pub mod strings;

pub use cache::{Cache, CacheStats, hash_bytes, hash_file};
pub use detect::{BinaryFormat, DetectionReport, Endian, SectionInfo, detect_file};
pub use error::{GhirustError, Result};
pub use export::{
    Compression, ExportOptions, ExportReport, export_directory, export_input, export_ndjson,
    export_single_file,
};
pub use index::{IndexOptions, IndexReport, SearchIndex, build_index, load_index, save_index};
pub use model::{ExportedFunction, FunctionRecord, ManifestRecord};
pub use search::{SearchHit, SearchMode, SearchOptions, SearchReport, search};
pub use strings::{StringEncoding, StringOptions, StringRecord, extract_strings};
