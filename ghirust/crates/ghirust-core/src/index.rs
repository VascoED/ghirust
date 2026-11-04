//! Persistent index of exported source files and function boundaries.
//!
//! Ghidra searches by walking its program database each time a query is
//! issued. GHIRUST instead pays the indexing cost once, at export/import time,
//! and stores:
//!
//! * the list of text files with size and modification time;
//! * every function marker (`// Function: name @ address`);
//! * the byte offset of each function, so a text hit can be attributed to the
//!   function that contains it.
//!
//! The index is deliberately a plain JSON document. It is easy to inspect,
//! easy to version, and small compared with the source corpus. Text itself is
//! never copied into the index; searches memory-map the original files.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

use crate::cache::{Cache, hash_file};
use crate::error::{GhirustError, IoResultExt, Result};
use crate::model::ManifestRecord;

/// Current on-disk index version.
pub const INDEX_VERSION: u32 = 1;

const TEXT_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx", "txt", "md", "json", "jsonl", "ndjson",
    "log", "py", "java", "rs", "go",
];

/// One indexed text file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFile {
    /// Path relative to the index root, using `/` separators.
    pub path: String,
    /// File size at index time.
    pub size: u64,
    /// Modification time at index time, in seconds since the Unix epoch.
    pub modified_unix: u64,
    /// Number of function entries found in this file.
    pub functions: u64,
}

/// A function boundary discovered in an export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Function name.
    pub name: String,
    /// Optional virtual address.
    #[serde(default)]
    pub address: Option<String>,
    /// Index into [`SearchIndex::files`].
    pub file_id: u32,
    /// 1-based line number of the function marker.
    pub line: u64,
    /// Byte offset of the function marker in the file.
    pub offset: u64,
}

/// The complete persisted search index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndex {
    /// Format version.
    pub version: u32,
    /// Canonical root that all `files[].path` values are relative to.
    pub root: PathBuf,
    /// Creation time, in seconds since the Unix epoch.
    pub built_unix: u64,
    /// Indexed files.
    pub files: Vec<IndexedFile>,
    /// Function boundaries, sorted by `(file_id, offset)`.
    pub functions: Vec<FunctionEntry>,
}

impl SearchIndex {
    /// Whether any indexed file changed since the index was built.
    ///
    /// The check is intentionally cheap and conservative: a changed size or
    /// modification time marks the index stale. New files are not detected
    /// until the next explicit `ghirust index` run.
    pub fn is_stale(&self) -> bool {
        self.files.iter().any(|file| {
            let path = self.root.join(&file.path);
            match fs::metadata(&path) {
                Ok(metadata) => {
                    metadata.len() != file.size
                        || metadata
                            .modified()
                            .ok()
                            .and_then(system_time_to_unix)
                            .unwrap_or_default()
                            != file.modified_unix
                }
                Err(_) => true,
            }
        })
    }

    /// Find the function containing `offset` in `file_id`.
    pub fn enclosing_function(&self, file_id: u32, offset: u64) -> Option<&FunctionEntry> {
        let end = self.functions.partition_point(|function| {
            function.file_id < file_id || (function.file_id == file_id && function.offset <= offset)
        });
        if end == 0 {
            return None;
        }
        let function = &self.functions[end - 1];
        (function.file_id == file_id).then_some(function)
    }

    /// Functions belonging to one file.
    pub fn functions_for_file(&self, file_id: u32) -> impl Iterator<Item = &FunctionEntry> {
        self.functions
            .iter()
            .filter(move |function| function.file_id == file_id)
    }
}

/// Options for building an index.
#[derive(Debug, Clone)]
pub struct IndexOptions {
    /// Directory containing exported code.
    pub root: PathBuf,
    /// Destination JSON index path.
    pub index_path: PathBuf,
    /// Include hidden files and directories.
    pub include_hidden: bool,
}

impl IndexOptions {
    /// Create options with the conventional `.ghirust/index.json` location.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let index_path = root.join(".ghirust").join("index.json");
        Self {
            root,
            index_path,
            include_hidden: false,
        }
    }
}

/// Result of an index build.
#[derive(Debug, Clone, Serialize)]
pub struct IndexReport {
    /// Root that was indexed.
    pub root: PathBuf,
    /// Index file that was written.
    pub index_path: PathBuf,
    /// Number of text files scanned.
    pub files: u64,
    /// Number of function boundaries found.
    pub functions: u64,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Per-file scan results reused from the persistent cache.
    pub cache_hits: u64,
    /// Per-file scan results recomputed because the cache missed.
    pub cache_misses: u64,
    /// Recoverable cache errors encountered while building the index.
    pub cache_warnings: Vec<String>,
    /// Wall-clock duration.
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedScan {
    functions: Vec<FunctionEntry>,
}

/// Build an index over `options.root` and save it.
pub fn build_index(options: &IndexOptions) -> Result<IndexReport> {
    let started = Instant::now();
    let root = fs::canonicalize(&options.root).at(&options.root)?;
    if !root.is_dir() {
        return Err(GhirustError::message(format!(
            "index root is not a directory: {}",
            root.display()
        )));
    }

    let mut paths = collect_files(&root, options.include_hidden)?;
    paths.sort();

    let mut files = Vec::with_capacity(paths.len());
    let mut path_to_id = HashMap::with_capacity(paths.len());
    let mut bytes_scanned = 0u64;

    for (id, path) in paths.iter().enumerate() {
        let metadata = fs::metadata(path).at(path)?;
        let relative = relative_string(&root, path);
        path_to_id.insert(relative.clone(), id as u32);
        bytes_scanned = bytes_scanned.saturating_add(metadata.len());
        files.push(IndexedFile {
            path: relative,
            size: metadata.len(),
            modified_unix: metadata
                .modified()
                .ok()
                .and_then(system_time_to_unix)
                .unwrap_or_default(),
            functions: 0,
        });
    }

    let mut functions = Vec::new();
    let mut pending_manifest = Vec::new();
    let mut files_with_markers = HashSet::new();
    let mut cache_hits = 0u64;
    let mut cache_misses = 0u64;
    let mut cache_warnings = Vec::new();
    let mut cache = match Cache::open(root.join(".ghirust").join("cache"), 256 * 1024 * 1024) {
        Ok(cache) => Some(cache),
        Err(error) => {
            cache_warnings.push(format!("scan cache unavailable: {error}"));
            None
        }
    };

    for (id, path) in paths.iter().enumerate() {
        let file_id = id as u32;
        let is_manifest =
            path.file_name().and_then(|value| value.to_str()) == Some("manifest.ndjson");
        let mut used_cache = false;

        if !is_manifest {
            if let Some(cache) = cache.as_mut() {
                match hash_file(path) {
                    Ok(hash) => {
                        let key = format!("scan-v1-{hash}");
                        match cache.get_json::<CachedScan>(&key) {
                            Ok(Some(mut cached)) => {
                                for function in &mut cached.functions {
                                    function.file_id = file_id;
                                }
                                if !cached.functions.is_empty() {
                                    files_with_markers.insert(file_id);
                                }
                                functions.append(&mut cached.functions);
                                cache_hits += 1;
                                used_cache = true;
                            }
                            Ok(None) => {}
                            Err(error) => cache_warnings.push(format!(
                                "failed reading scan cache for {}: {error}",
                                path.display()
                            )),
                        }
                    }
                    Err(error) => cache_warnings.push(format!(
                        "failed hashing {} for scan cache: {error}",
                        path.display()
                    )),
                }
            }
        }

        if used_cache {
            continue;
        }

        let (mut markers, mut manifest_entries, _) = scan_file(&root, path, file_id)?;
        if !markers.is_empty() {
            files_with_markers.insert(file_id);
        }
        if !is_manifest {
            if let Some(cache) = cache.as_mut() {
                match hash_file(path) {
                    Ok(hash) => {
                        let key = format!("scan-v1-{hash}");
                        if let Err(error) = cache.put_json(
                            &key,
                            &CachedScan {
                                functions: markers.clone(),
                            },
                        ) {
                            cache_warnings.push(format!(
                                "failed storing scan cache for {}: {error}",
                                path.display()
                            ));
                        }
                    }
                    Err(error) => cache_warnings.push(format!(
                        "failed hashing {} for scan cache: {error}",
                        path.display()
                    )),
                }
            }
            cache_misses += 1;
        }
        functions.append(&mut markers);
        pending_manifest.append(&mut manifest_entries);
    }
    if let Some(cache) = cache.as_mut() {
        if let Err(error) = cache.flush() {
            cache_warnings.push(format!("failed flushing scan cache: {error}"));
        }
        cache_warnings.extend(cache.take_diagnostics());
    }
    drop(cache);

    // Resolve manifest entries after every file has an ID. This is what lets
    // `ghirust export --from-dir` work with the Ghidra bridge, which writes
    // one file per function plus a manifest.
    for (manifest_path, record) in pending_manifest {
        let Some(target) = resolve_manifest_target(&root, &manifest_path, &record.file) else {
            continue;
        };
        let Some(&file_id) = path_to_id.get(&target) else {
            continue;
        };
        if files_with_markers.contains(&file_id) {
            continue;
        }
        functions.push(FunctionEntry {
            name: record.name,
            address: record.address,
            file_id,
            line: 1,
            offset: 0,
        });
    }

    functions.sort_by(|left, right| {
        left.file_id
            .cmp(&right.file_id)
            .then(left.offset.cmp(&right.offset))
            .then(left.name.cmp(&right.name))
    });

    let mut function_counts = vec![0u64; files.len()];
    for function in &functions {
        if let Some(count) = function_counts.get_mut(function.file_id as usize) {
            *count += 1;
        }
    }
    for (file, count) in files.iter_mut().zip(function_counts) {
        file.functions = count;
    }

    let index = SearchIndex {
        version: INDEX_VERSION,
        root,
        built_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
        files,
        functions,
    };
    save_index(&index, &options.index_path)?;

    let report = IndexReport {
        root: index.root.clone(),
        index_path: options.index_path.clone(),
        files: index.files.len() as u64,
        functions: index.functions.len() as u64,
        bytes_scanned,
        cache_hits,
        cache_misses,
        cache_warnings,
        elapsed_ms: started.elapsed().as_millis(),
    };
    Ok(report)
}

/// Save an index atomically.
pub fn save_index(index: &SearchIndex, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).at(parent)?;
        }
    }
    let temp = sibling(path, ".tmp");
    let file = File::create(&temp).at(&temp)?;
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer(&mut writer, index)
        .map_err(|source| GhirustError::json(&temp, source))?;
    writer.flush().at(&temp)?;
    writer.get_ref().sync_all().at(&temp)?;

    if path.exists() {
        fs::remove_file(path).at(path)?;
    }
    fs::rename(&temp, path).at(path)
}

/// Load an index and validate its version.
pub fn load_index(path: &Path) -> Result<SearchIndex> {
    let bytes = fs::read(path).at(path)?;
    let index: SearchIndex =
        serde_json::from_slice(&bytes).map_err(|source| GhirustError::json(path, source))?;
    if index.version != INDEX_VERSION {
        return Err(GhirustError::IndexVersion {
            found: index.version,
            expected: INDEX_VERSION,
        });
    }
    Ok(index)
}

/// Load an index when it is fresh, otherwise rebuild it.
///
/// Returns the index and whether it was rebuilt.
pub fn ensure_index(root: &Path, index_path: &Path, force: bool) -> Result<(SearchIndex, bool)> {
    if !force && index_path.exists() {
        match load_index(index_path) {
            Ok(index) if !index.is_stale() => return Ok((index, false)),
            Ok(_) | Err(GhirustError::IndexVersion { .. }) => {}
            Err(error) => return Err(error),
        }
    }

    let options = IndexOptions {
        root: root.to_path_buf(),
        index_path: index_path.to_path_buf(),
        include_hidden: false,
    };
    build_index(&options)?;
    Ok((load_index(index_path)?, true))
}

fn collect_files(root: &Path, include_hidden: bool) -> Result<Vec<PathBuf>> {
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| keep_entry(entry, include_hidden));

    let mut paths = Vec::new();
    for entry in walker {
        let entry = entry.map_err(|error| {
            GhirustError::message(format!("failed to walk {}: {error}", root.display()))
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if is_text_file(path) {
            paths.push(path.to_path_buf());
        }
    }
    Ok(paths)
}

fn keep_entry(entry: &DirEntry, include_hidden: bool) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if name == ".git" || name == ".ghirust" || name == "target" || name == "node_modules" {
        return false;
    }
    if !include_hidden && name.starts_with('.') {
        return false;
    }
    true
}

fn is_text_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if name == "manifest.ndjson" {
        return true;
    }
    path.extension()
        .and_then(|value| value.to_str())
        .map(|extension| TEXT_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Functions, manifest records and byte count produced by one file scan.
type ScannedFile = (Vec<FunctionEntry>, Vec<(PathBuf, ManifestRecord)>, u64);

fn scan_file(root: &Path, path: &Path, file_id: u32) -> Result<ScannedFile> {
    let file = File::open(path).at(path)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut line = Vec::new();
    let mut offset = 0u64;
    let mut line_number = 0u64;
    let mut functions = Vec::new();
    let mut manifest = Vec::new();
    let is_manifest = path.file_name().and_then(|value| value.to_str()) == Some("manifest.ndjson");

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).at(path)?;
        if read == 0 {
            break;
        }
        line_number += 1;
        let text = String::from_utf8_lossy(&line);

        if let Some((name, address)) = parse_function_marker(&text) {
            functions.push(FunctionEntry {
                name,
                address,
                file_id,
                line: line_number,
                offset,
            });
        } else if is_manifest {
            if let Ok(record) = serde_json::from_str::<ManifestRecord>(text.trim()) {
                manifest.push((path.to_path_buf(), record));
            }
        }

        offset = offset.saturating_add(read as u64);
    }

    let _ = root;
    Ok((functions, manifest, offset))
}

/// Parse the machine-readable marker written by the streaming exporter.
///
/// Accepted forms:
///
/// ```text
/// // Function: main
/// // Function: FUN_00401000 @ 0x00401000
/// ```
pub fn parse_function_marker(line: &str) -> Option<(String, Option<String>)> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("// Function:")
        .or_else(|| trimmed.strip_prefix("// function:"))?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }

    if let Some((name, address)) = rest.rsplit_once(" @ ") {
        let address = address.trim();
        if is_address_like(address) {
            let name = name.trim();
            if !name.is_empty() {
                return Some((name.to_owned(), Some(address.to_owned())));
            }
        }
    }
    Some((rest.to_owned(), None))
}

fn is_address_like(value: &str) -> bool {
    value.starts_with("0x")
        || value.starts_with("0X")
        || value
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == ':')
}

fn relative_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn resolve_manifest_target(root: &Path, manifest: &Path, target: &str) -> Option<String> {
    let manifest_relative = manifest.strip_prefix(root).ok()?;
    let parent = manifest_relative.parent().unwrap_or(Path::new(""));
    let joined = parent.join(target);
    let mut normalized = Vec::new();
    for component in joined.components() {
        match component {
            std::path::Component::Normal(value) => normalized.push(value.to_string_lossy()),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(normalized.join("/"))
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut value = std::ffi::OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn system_time_to_unix(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
