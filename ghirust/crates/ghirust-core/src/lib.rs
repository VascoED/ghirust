//! GHIRUST core: binary loading, x86/x86-64 disassembly, CFG recovery,
//! heuristic pseudocode reconstruction and persistent projects.
//!
//! The crate is the shared engine used by the command line application and the
//! egui desktop application:
//!
//! * [`loader`] maps PE/ELF/Mach-O/WASM images and exposes sections, symbols,
//!   imports and exports.
//! * [`analysis`] decodes instructions, discovers functions, builds control
//!   flow graphs and records cross-references.
//! * [`pseudocode`] reconstructs C-like pseudocode from the recovered CFG. It is
//!   an explicit heuristic decompiler with documented limitations, not a clone
//!   of Ghidra's decompiler.
//! * [`project`] persists imported programs, saved analyses, user overrides
//!   (renames, comments, types, bookmarks) and UI sessions.
//! * [`index`] and [`search`] provide persistent search over exported code.
//! * [`export`] turns a stream of functions into one output file without ever
//!   materialising the whole output in RAM.

pub mod analysis;
pub mod cache;
pub mod detect;
pub mod error;
pub mod export;
pub mod filemap;
pub mod index;
pub mod ir;
pub mod loader;
pub mod model;
pub mod program_search;
pub mod project;
pub mod pseudocode;
pub mod resources;
pub mod search;
pub mod strings;
pub mod telemetry;

pub use analysis::{
    ANALYSIS_VERSION, AnalysisOptions, AnalysisStats, AnalysisStats as Stats, BlockAnalysis,
    DecodedBlock, DecodedFunction, DecodedInstruction, DecodedTerminator, FunctionAnalysis,
    ListingInstruction, ProgramAnalysis, Xref, analyze_path, analyze_path_managed, analyze_program,
};
pub use cache::{Cache, CacheStats, hash_bytes, hash_file};
pub use detect::{BinaryFormat, DetectionReport, Endian, SectionInfo, detect_file};
pub use error::{GhirustError, Result};
pub use export::{
    Compression, ExportOptions, ExportReport, export_directory, export_input, export_ndjson,
    export_single_file,
};
pub use index::{IndexOptions, IndexReport, SearchIndex, build_index, load_index, save_index};
pub use loader::{
    ExportRecord, ImportRecord, LoadedProgram, LoadedSection, LoaderSummary, SymbolRecord,
    load_or_hint,
};
pub use model::{ExportedFunction, FunctionRecord, ManifestRecord};
pub use program_search::{
    ProgramSearchHit, ProgramSearchMode, ProgramSearchOptions, ProgramSearchReport, search_program,
};
pub use project::{
    Bookmark, FunctionOverride, ImportMode, PROJECT_VERSION, ProgramEntry, ProgramVerification,
    Project, ProjectManifest, ProjectSettings, SessionState, UserOverrides, VerifyReport,
    open_or_create, recover,
};
pub use pseudocode::{
    DecompiledFunction, DecompiledParameter, DecompiledVariable, decompile_function,
};
pub use resources::{
    CancellationToken, CpuPool, Metrics, PoolError, PoolTask, PressureState, Priority, Reservation,
    ReservationRequest, ResourceBudget, ResourceError, ResourceManager, ResourceProfile,
};
pub use search::{SearchHit, SearchMode, SearchOptions, SearchReport, search};
pub use strings::{StringEncoding, StringOptions, StringRecord, extract_strings};
pub use telemetry::{GpuMetrics, SystemSnapshot, Telemetry};
