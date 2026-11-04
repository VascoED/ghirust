//! Error types shared by the GHIRUST core.
//!
//! The rule for errors is simple: every error must tell the user what failed
//! and, where possible, what to do next. Library code never panics on input
//! that comes from a file or from the command line.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Result alias used throughout the core.
pub type Result<T> = std::result::Result<T, GhirustError>;

/// All recoverable failures produced by GHIRUST.
#[derive(Debug, Error)]
pub enum GhirustError {
    /// An I/O operation failed for a specific path.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },

    /// A JSON document could not be decoded or encoded.
    #[error("invalid JSON in {path}: {source}")]
    Json {
        /// Path of the JSON document.
        path: PathBuf,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// The caller asked to search for an empty string.
    #[error("the search query cannot be empty")]
    EmptyQuery,

    /// The caller did not provide any input records.
    #[error("no input records were found")]
    EmptyInput,

    /// The output file already exists and `--force` was not supplied.
    #[error("output already exists: {path} (use --force to overwrite it)")]
    OutputExists {
        /// Existing output path.
        path: PathBuf,
    },

    /// Resuming is only supported for uncompressed output.
    #[error(
        "--resume is not supported for gzip output; write a plain file and compress it afterwards"
    )]
    ResumeGzip,

    /// A checkpoint points outside the partial output file.
    #[error(
        "checkpoint is inconsistent with {path}: expected at most {actual} bytes, found {expected}"
    )]
    CorruptCheckpoint {
        /// Partial output path.
        path: PathBuf,
        /// Number of bytes recorded in the checkpoint.
        expected: u64,
        /// Actual length of the partial file.
        actual: u64,
    },

    /// The search index was produced by an incompatible version.
    #[error(
        "unsupported index version {found}; expected {expected}. Run `ghirust index` to rebuild it"
    )]
    IndexVersion {
        /// Version found on disk.
        found: u32,
        /// Version understood by this binary.
        expected: u32,
    },

    /// A generic, already-formatted user-facing message.
    #[error("{0}")]
    Message(String),
}

impl GhirustError {
    /// Attach a path to a low-level I/O error.
    pub fn io(path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    /// Attach a path to a JSON error.
    pub fn json(path: impl AsRef<Path>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    /// Build a user-facing message.
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

/// Convenience extension for adding path context to `io::Result`.
pub trait IoResultExt<T> {
    /// Convert an I/O result into a path-aware GHIRUST result.
    fn at(self, path: impl AsRef<Path>) -> Result<T>;
}

impl<T> IoResultExt<T> for io::Result<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T> {
        self.map_err(|source| GhirustError::io(path, source))
    }
}
