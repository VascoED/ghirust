//! The only module in the core that performs memory mapping.
//!
//! `memmap2::Mmap::map` is unsafe because the file must not be mutated while
//! the mapping is alive. GHIRUST only maps files that the index treats as
//! read-only analysis artifacts. All unsafe code is kept here, behind a safe
//! wrapper, so the rest of the crate remains safe Rust.

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{GhirustError, IoResultExt, Result};

/// A read-only memory map of a file.
#[derive(Debug)]
pub struct ReadOnlyMap {
    map: Mmap,
}

impl ReadOnlyMap {
    /// Map `path` read-only.
    ///
    /// # Errors
    ///
    /// Returns a path-aware I/O error if the file cannot be opened, is empty,
    /// or cannot be mapped.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).at(path)?;
        let len = file.metadata().at(path)?.len();
        if len == 0 {
            return Err(GhirustError::message(format!(
                "cannot map empty file: {}",
                path.display()
            )));
        }

        // SAFETY: the mapping is read-only for its entire lifetime. The caller
        // must not modify the file while a search is running; GHIRUST treats
        // exported analysis files as immutable inputs. The file handle is kept
        // alive by `File::open` for the duration of `map`.
        let map = unsafe { Mmap::map(&file) }.at(path)?;
        Ok(Self { map })
    }

    /// Return the mapped bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }

    /// Length of the mapped region.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the mapped region is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
