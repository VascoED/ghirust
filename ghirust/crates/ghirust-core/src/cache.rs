//! Persistent content-addressable cache.
//!
//! Analysis results are expensive. The cache stores them under a SHA-256 key
//! derived from the input bytes and the analysis configuration, updates an
//! access timestamp, and evicts least-recently-used entries when the size
//! budget is exceeded. Writes are atomic (temporary file + rename) so an
//! interrupted process never leaves a half-written value visible.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{GhirustError, IoResultExt, Result};

/// Current cache manifest version.
pub const CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheManifest {
    version: u32,
    max_bytes: u64,
    entries: BTreeMap<String, CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    size: u64,
    created_unix: u64,
    last_used_unix: u64,
}

/// Cache statistics.
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    /// Directory backing the cache.
    pub root: PathBuf,
    /// Number of values.
    pub entries: u64,
    /// Total bytes of cached values.
    pub total_bytes: u64,
    /// Configured soft limit.
    pub max_bytes: u64,
    /// Cache hits observed during this process.
    pub hits: u64,
    /// Cache misses observed during this process.
    pub misses: u64,
}

/// A persistent cache instance.
pub struct Cache {
    root: PathBuf,
    manifest_path: PathBuf,
    manifest: CacheManifest,
    dirty: bool,
    hits: u64,
    misses: u64,
    diagnostics: Vec<String>,
}

impl Cache {
    /// Open (or create) a cache directory.
    pub fn open(root: impl Into<PathBuf>, max_bytes: u64) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).at(&root)?;
        let manifest_path = root.join("index.json");
        let mut diagnostics = Vec::new();
        let manifest = match fs::read(&manifest_path) {
            Ok(bytes) => match serde_json::from_slice::<CacheManifest>(&bytes) {
                Ok(manifest) if manifest.version == CACHE_VERSION => manifest,
                Ok(manifest) => {
                    diagnostics.push(format!(
                        "ignoring cache manifest {} with unsupported version {}",
                        manifest_path.display(),
                        manifest.version
                    ));
                    CacheManifest {
                        version: CACHE_VERSION,
                        max_bytes,
                        entries: BTreeMap::new(),
                    }
                }
                Err(error) => {
                    diagnostics.push(format!(
                        "ignoring invalid cache manifest {}: {error}",
                        manifest_path.display()
                    ));
                    CacheManifest {
                        version: CACHE_VERSION,
                        max_bytes,
                        entries: BTreeMap::new(),
                    }
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => CacheManifest {
                version: CACHE_VERSION,
                max_bytes,
                entries: BTreeMap::new(),
            },
            Err(error) => {
                diagnostics.push(format!(
                    "ignoring unreadable cache manifest {}: {error}",
                    manifest_path.display()
                ));
                CacheManifest {
                    version: CACHE_VERSION,
                    max_bytes,
                    entries: BTreeMap::new(),
                }
            }
        };

        let mut cache = Self {
            root,
            manifest_path,
            manifest,
            dirty: false,
            hits: 0,
            misses: 0,
            diagnostics,
        };
        cache.manifest.max_bytes = max_bytes;
        Ok(cache)
    }

    /// Fetch a value by key.
    pub fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        let Some(entry) = self.manifest.entries.get(key).cloned() else {
            self.misses += 1;
            return Ok(None);
        };
        let path = self.value_path(key);
        match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() as u64 != entry.size {
                    self.manifest.entries.remove(key);
                    self.diagnostics.push(format!(
                        "discarding truncated cache value {} (expected {} bytes, found {})",
                        path.display(),
                        entry.size,
                        bytes.len()
                    ));
                    self.misses += 1;
                    self.dirty = true;
                    return Ok(None);
                }
                self.hits += 1;
                if let Some(entry) = self.manifest.entries.get_mut(key) {
                    entry.last_used_unix = now_unix();
                }
                self.dirty = true;
                Ok(Some(bytes))
            }
            Err(error) => {
                self.misses += 1;
                self.manifest.entries.remove(key);
                self.dirty = true;
                self.diagnostics.push(format!(
                    "discarding unreadable cache value {}: {error}",
                    path.display()
                ));
                Ok(None)
            }
        }
    }

    /// Fetch and decode a JSON value.
    pub fn get_json<T: DeserializeOwned>(&mut self, key: &str) -> Result<Option<T>> {
        let Some(bytes) = self.get(key)? else {
            return Ok(None);
        };
        match serde_json::from_slice(&bytes) {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                self.manifest.entries.remove(key);
                self.dirty = true;
                self.diagnostics.push(format!(
                    "discarding invalid JSON cache value for key {key}: {error}"
                ));
                Ok(None)
            }
        }
    }

    /// Store a value by key.
    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        validate_key(key)?;
        let path = self.value_path(key);
        write_atomic(&path, value)?;
        let timestamp = now_unix();
        self.manifest.entries.insert(
            key.to_owned(),
            CacheEntry {
                size: value.len() as u64,
                created_unix: timestamp,
                last_used_unix: timestamp,
            },
        );
        self.dirty = true;
        self.evict_if_needed()
    }

    /// Encode and store a JSON value.
    pub fn put_json<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        let bytes =
            serde_json::to_vec(value).map_err(|source| GhirustError::json(&self.root, source))?;
        self.put(key, &bytes)
    }

    /// Remove one value.
    pub fn remove(&mut self, key: &str) -> Result<()> {
        validate_key(key)?;
        self.manifest.entries.remove(key);
        let path = self.value_path(key);
        if path.exists() {
            fs::remove_file(&path).at(&path)?;
        }
        self.dirty = true;
        Ok(())
    }

    /// Remove all values.
    pub fn clear(&mut self) -> Result<()> {
        for key in self.manifest.entries.keys().cloned().collect::<Vec<_>>() {
            let path = self.value_path(&key);
            if path.exists() {
                fs::remove_file(&path).at(&path)?;
            }
        }
        self.manifest.entries.clear();
        self.dirty = true;
        Ok(())
    }

    /// Persist the manifest.
    pub fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&self.manifest)
            .map_err(|source| GhirustError::json(&self.manifest_path, source))?;
        write_atomic(&self.manifest_path, &bytes)?;
        self.dirty = false;
        Ok(())
    }

    /// Current statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            root: self.root.clone(),
            entries: self.manifest.entries.len() as u64,
            total_bytes: self.manifest.entries.values().map(|entry| entry.size).sum(),
            max_bytes: self.manifest.max_bytes,
            hits: self.hits,
            misses: self.misses,
        }
    }

    /// Return and clear recoverable cache diagnostics.
    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }

    fn evict_if_needed(&mut self) -> Result<()> {
        while self.total_bytes() > self.manifest.max_bytes && !self.manifest.entries.is_empty() {
            let oldest = self
                .manifest
                .entries
                .iter()
                .min_by_key(|(_, entry)| (entry.last_used_unix, entry.created_unix))
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else {
                break;
            };
            let path = self.value_path(&oldest);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(GhirustError::io(&path, error)),
            }
            self.manifest.entries.remove(&oldest);
            self.dirty = true;
        }
        Ok(())
    }

    fn total_bytes(&self) -> u64 {
        self.manifest.entries.values().map(|entry| entry.size).sum()
    }

    fn value_path(&self, key: &str) -> PathBuf {
        self.root.join(format!("{key}.bin"))
    }
}

/// Whether a cache key is safe to use as a file name.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 160 {
        return Err(GhirustError::message(
            "cache key must contain between 1 and 160 characters",
        ));
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(GhirustError::message(format!("invalid cache key: {key}")));
    }
    if key == "." || key == ".." {
        return Err(GhirustError::message("invalid cache key"));
    }
    Ok(())
}

/// SHA-256 of a byte slice, as lowercase hexadecimal.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    to_hex(&digest)
}

/// SHA-256 of a file, read in bounded chunks.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).at(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let read = file.read(&mut buffer).at(path)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(to_hex(&hasher.finalize()))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = sibling(path, ".tmp");
    let mut file = File::create(&temp).at(&temp)?;
    file.write_all(bytes).at(&temp)?;
    file.sync_all().at(&temp)?;
    if path.exists() {
        fs::remove_file(path).at(path)?;
    }
    fs::rename(&temp, path).at(path)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut value = std::ffi::OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn stores_and_reads_values() {
        let temp = tempdir().unwrap();
        let mut cache = Cache::open(temp.path(), 1024 * 1024).unwrap();
        cache.put("key-one", b"hello").unwrap();
        cache.flush().unwrap();

        let mut reopened = Cache::open(temp.path(), 1024 * 1024).unwrap();
        assert_eq!(reopened.get("key-one").unwrap(), Some(b"hello".to_vec()));
        assert_eq!(reopened.stats().hits, 1);
    }

    #[test]
    fn truncated_values_are_reported_as_misses() {
        let temp = tempdir().unwrap();
        let mut cache = Cache::open(temp.path(), 1024 * 1024).unwrap();
        cache.put("key-one", b"hello").unwrap();
        cache.flush().unwrap();
        fs::write(temp.path().join("key-one.bin"), b"x").unwrap();

        let mut reopened = Cache::open(temp.path(), 1024 * 1024).unwrap();
        assert_eq!(reopened.get("key-one").unwrap(), None);
        assert_eq!(reopened.stats().hits, 0);
        assert_eq!(reopened.stats().misses, 1);
        assert!(
            reopened
                .take_diagnostics()
                .iter()
                .any(|warning| warning.contains("truncated cache value"))
        );
    }

    #[test]
    fn stores_json_values() {
        let temp = tempdir().unwrap();
        let mut cache = Cache::open(temp.path(), 1024 * 1024).unwrap();
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Value {
            name: String,
            count: u32,
        }
        let value = Value {
            name: "main".to_owned(),
            count: 3,
        };
        cache.put_json("json-key", &value).unwrap();
        assert_eq!(cache.get_json::<Value>("json-key").unwrap(), Some(value));
    }

    #[test]
    fn evicts_least_recently_used_entries() {
        let temp = tempdir().unwrap();
        let mut cache = Cache::open(temp.path(), 8).unwrap();
        cache.put("first", b"12345").unwrap();
        cache.put("second", b"67890").unwrap();
        // The cache is over budget, so at least one entry must be gone.
        assert!(cache.stats().total_bytes <= 8);
        assert_eq!(cache.stats().entries, 1);
    }

    #[test]
    fn rejects_path_like_keys() {
        let temp = tempdir().unwrap();
        let mut cache = Cache::open(temp.path(), 1024).unwrap();
        assert!(cache.put("../escape", b"x").is_err());
        assert!(cache.put("sub/dir", b"x").is_err());
    }

    #[test]
    fn hash_is_stable_and_content_addressed() {
        assert_eq!(hash_bytes(b"ghirust"), hash_bytes(b"ghirust"));
        assert_ne!(hash_bytes(b"ghirust"), hash_bytes(b"ghirusT"));
        assert_eq!(hash_bytes(b"abc").len(), 64);
    }

    #[test]
    fn clears_entries() {
        let temp = tempdir().unwrap();
        let mut cache = Cache::open(temp.path(), 1024).unwrap();
        cache.put("one", b"1").unwrap();
        cache.put("two", b"2").unwrap();
        cache.clear().unwrap();
        assert_eq!(cache.stats().entries, 0);
    }
}
