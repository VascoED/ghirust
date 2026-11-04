//! Bounded-memory export of decompiled functions.
//!
//! The original Ghidra exporters collect every function body in a
//! `StringBuilder` and only then write the result. For a 30 MB DLL that can
//! mean a 100 MB string plus reallocation headroom, and the UI may appear
//! frozen while it happens.
//!
//! This module takes the opposite approach:
//!
//! * functions are written to disk as soon as they arrive;
//! * the in-memory buffer is capped (default 8 MiB of output between flushes);
//! * large function bodies can be copied directly from a reader;
//! * output is written to a `.part` file and atomically renamed;
//! * checkpoints and a streaming manifest make long exports resumable and
//!   searchable.
//!
//! Peak memory is therefore `buffer + largest single function`, not
//! `size of the complete output`.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use flate2::Compression as GzipLevel;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

use crate::error::{GhirustError, IoResultExt, Result};
use crate::model::{ExportedFunction, FunctionRecord, ManifestRecord};

/// Header written at the start of every GHIRUST export.
const HEADER: &str =
    "// GHIRUST streaming export (format 1)\n// Function markers are machine-readable.\n";

/// Compression applied to the final file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    /// Plain UTF-8 text.
    #[default]
    None,
    /// Gzip-compressed text.
    Gzip,
}

impl Compression {
    /// Parse a user-facing compression name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "plain" => Some(Self::None),
            "gzip" | "gz" => Some(Self::Gzip),
            _ => None,
        }
    }

    /// File extension conventionally associated with the format.
    pub fn extension(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Gzip => ".gz",
        }
    }
}

/// Configuration for a streaming export.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Final output path.
    pub output: PathBuf,
    /// Whether to gzip the output.
    pub compression: Compression,
    /// Overwrite an existing output file.
    pub force: bool,
    /// Resume a previous interrupted plain-text export.
    pub resume: bool,
    /// Number of uncompressed bytes between checkpoints and flushes.
    pub checkpoint_bytes: u64,
    /// Write a streaming manifest next to the output.
    pub write_manifest: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            output: PathBuf::new(),
            compression: Compression::None,
            force: false,
            resume: false,
            checkpoint_bytes: 8 * 1024 * 1024,
            write_manifest: true,
        }
    }
}

/// Result of a completed export.
#[derive(Debug, Clone, Serialize)]
pub struct ExportReport {
    /// Final output path.
    pub output: PathBuf,
    /// Number of functions written.
    pub records: u64,
    /// Uncompressed bytes of text produced.
    pub uncompressed_bytes: u64,
    /// Bytes actually written to disk (compressed when gzip is enabled).
    pub written_bytes: u64,
    /// Wall-clock duration.
    pub elapsed_ms: u128,
    /// Number of records restored from a checkpoint before continuing.
    pub resumed_from: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    records: u64,
    output_bytes: u64,
}

struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W, count: u64) -> Self {
        Self { inner, count }
    }

    fn count(&self) -> u64 {
        self.count
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count = self.count.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum Sink {
    Plain(BufWriter<CountingWriter<File>>),
    Gzip(BufWriter<GzEncoder<CountingWriter<File>>>),
}

impl Sink {
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.write_all(bytes),
            Self::Gzip(writer) => writer.write_all(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Gzip(writer) => writer.flush(),
        }
    }

    fn compressed_bytes(&self) -> u64 {
        match self {
            Self::Plain(writer) => writer.get_ref().count(),
            Self::Gzip(writer) => writer.get_ref().get_ref().count(),
        }
    }

    fn sync_data(&mut self) -> io::Result<()> {
        self.flush()?;
        match self {
            Self::Plain(writer) => writer.get_ref().inner.sync_data(),
            Self::Gzip(writer) => writer.get_ref().get_ref().inner.sync_data(),
        }
    }

    fn finish(self) -> io::Result<u64> {
        match self {
            Self::Plain(mut writer) => {
                writer.flush()?;
                let counting = writer.into_inner().map_err(|error| error.into_error())?;
                let count = counting.count();
                counting.inner.sync_all()?;
                Ok(count)
            }
            Self::Gzip(mut writer) => {
                writer.flush()?;
                let encoder = writer.into_inner().map_err(|error| error.into_error())?;
                let counting = encoder.finish()?;
                let count = counting.count();
                counting.inner.sync_all()?;
                Ok(count)
            }
        }
    }
}

struct ExportWriter {
    output: PathBuf,
    part: PathBuf,
    checkpoint_path: PathBuf,
    manifest_path: PathBuf,
    sink: Sink,
    manifest: Option<BufWriter<File>>,
    records: u64,
    uncompressed: u64,
    last_checkpoint: u64,
    checkpoint_bytes: u64,
    resumed_from: u64,
    started: Instant,
}

impl ExportWriter {
    fn create(options: &ExportOptions) -> Result<Self> {
        if options.output.as_os_str().is_empty() {
            return Err(GhirustError::message("an output path is required"));
        }

        if options.resume && options.compression == Compression::Gzip {
            return Err(GhirustError::ResumeGzip);
        }

        if options.output.exists() {
            if options.resume {
                return Err(GhirustError::message(format!(
                    "refusing to resume because the final output already exists: {}",
                    options.output.display()
                )));
            }
            if !options.force {
                return Err(GhirustError::OutputExists {
                    path: options.output.clone(),
                });
            }
        }

        if let Some(parent) = options.output.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).at(parent)?;
            }
        }

        let part = sibling(&options.output, ".part");
        let checkpoint_path = sibling(&options.output, ".checkpoint.json");
        let manifest_path = sibling(&options.output, ".manifest.ndjson");

        let mut records = 0u64;
        let mut uncompressed = 0u64;
        let mut resumed_from = 0u64;

        let file = if options.resume && part.exists() && checkpoint_path.exists() {
            let checkpoint = read_checkpoint(&checkpoint_path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&part)
                .at(&part)?;
            let actual = file.metadata().at(&part)?.len();
            if actual < checkpoint.output_bytes {
                return Err(GhirustError::CorruptCheckpoint {
                    path: part.clone(),
                    expected: checkpoint.output_bytes,
                    actual,
                });
            }
            file.set_len(checkpoint.output_bytes).at(&part)?;
            file.seek(SeekFrom::End(0)).at(&part)?;
            records = checkpoint.records;
            uncompressed = checkpoint.output_bytes;
            resumed_from = records;
            truncate_manifest(&manifest_path, records)?;
            file
        } else {
            // A resume request without usable state is not a hard error:
            // start cleanly and tell the caller through `resumed_from`.
            // A normal export also discards stale sidecars from an earlier
            // interrupted run, otherwise the manifest would contain duplicates.
            let _ = fs::remove_file(&part);
            let _ = fs::remove_file(&checkpoint_path);
            let _ = fs::remove_file(&manifest_path);
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(true)
                .open(&part)
                .at(&part)?;
            file
        };

        let counting = CountingWriter::new(file, uncompressed);
        let sink = match options.compression {
            Compression::None => Sink::Plain(BufWriter::with_capacity(1024 * 1024, counting)),
            Compression::Gzip => Sink::Gzip(BufWriter::with_capacity(
                1024 * 1024,
                GzEncoder::new(counting, GzipLevel::default()),
            )),
        };

        let manifest = if options.write_manifest {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&manifest_path)
                .at(&manifest_path)?;
            Some(BufWriter::with_capacity(256 * 1024, file))
        } else {
            None
        };

        let mut writer = Self {
            output: options.output.clone(),
            part,
            checkpoint_path,
            manifest_path,
            sink,
            manifest,
            records,
            uncompressed,
            last_checkpoint: uncompressed,
            checkpoint_bytes: options.checkpoint_bytes.max(64 * 1024),
            resumed_from,
            started: Instant::now(),
        };

        if resumed_from == 0 {
            writer.write_header()?;
        }

        Ok(writer)
    }

    fn write_header(&mut self) -> Result<()> {
        self.sink
            .write_all(HEADER.as_bytes())
            .map_err(|source| GhirustError::io(&self.part, source))?;
        self.uncompressed = HEADER.len() as u64;
        self.last_checkpoint = self.uncompressed;
        Ok(())
    }

    fn resumed_from(&self) -> u64 {
        self.resumed_from
    }

    fn write_record(&mut self, record: &FunctionRecord) -> Result<()> {
        self.write_body(
            &record.name,
            record.address.as_deref(),
            Body::Text(record.code.as_bytes()),
        )
    }

    fn write_function_from_reader(
        &mut self,
        name: &str,
        address: Option<&str>,
        reader: &mut dyn Read,
    ) -> Result<()> {
        self.write_body(name, address, Body::Reader(reader))
    }

    fn write_body(&mut self, name: &str, address: Option<&str>, body: Body<'_>) -> Result<()> {
        let start = self.uncompressed;
        self.write_all_checked(format_function_header(name, address).as_bytes())?;

        let last_byte = match body {
            Body::Text(bytes) => {
                self.write_all_checked(bytes)?;
                bytes.last().copied()
            }
            Body::Reader(reader) => {
                let (copied, last) = copy_stream(reader, &mut self.sink, &self.part)?;
                self.uncompressed = self.uncompressed.saturating_add(copied);
                last
            }
        };

        if last_byte != Some(b'\n') {
            self.write_all_checked(b"\n")?;
        }

        let end = self.uncompressed;
        self.records += 1;

        if let Some(manifest) = self.manifest.as_mut() {
            let entry = ExportedFunction {
                name: name.to_owned(),
                address: address.map(str::to_owned),
                offset: start,
                length: end.saturating_sub(start),
            };
            serde_json::to_writer(&mut *manifest, &entry)
                .map_err(|source| GhirustError::json(&self.manifest_path, source))?;
            manifest
                .write_all(b"\n")
                .map_err(|source| GhirustError::io(&self.manifest_path, source))?;
        }

        if self.uncompressed.saturating_sub(self.last_checkpoint) >= self.checkpoint_bytes {
            self.checkpoint(false)?;
        }

        Ok(())
    }

    fn write_all_checked(&mut self, bytes: &[u8]) -> Result<()> {
        self.sink
            .write_all(bytes)
            .map_err(|source| GhirustError::io(&self.part, source))?;
        self.uncompressed = self.uncompressed.saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn checkpoint(&mut self, force: bool) -> Result<()> {
        if !force && self.uncompressed == self.last_checkpoint {
            return Ok(());
        }

        self.sink
            .sync_data()
            .map_err(|source| GhirustError::io(&self.part, source))?;

        if let Some(manifest) = self.manifest.as_mut() {
            manifest
                .flush()
                .map_err(|source| GhirustError::io(&self.manifest_path, source))?;
            manifest
                .get_ref()
                .sync_data()
                .map_err(|source| GhirustError::io(&self.manifest_path, source))?;
        }

        let checkpoint = Checkpoint {
            records: self.records,
            output_bytes: self.sink.compressed_bytes(),
        };
        write_checkpoint(&self.checkpoint_path, &checkpoint)?;
        self.last_checkpoint = self.uncompressed;
        Ok(())
    }

    fn finish(mut self) -> Result<ExportReport> {
        self.checkpoint(true)?;

        let written_bytes = self
            .sink
            .finish()
            .map_err(|source| GhirustError::io(&self.part, source))?;

        if let Some(mut manifest) = self.manifest.take() {
            manifest
                .flush()
                .map_err(|source| GhirustError::io(&self.manifest_path, source))?;
            manifest
                .get_ref()
                .sync_all()
                .map_err(|source| GhirustError::io(&self.manifest_path, source))?;
        }

        if self.output.exists() {
            fs::remove_file(&self.output).at(&self.output)?;
        }
        fs::rename(&self.part, &self.output).at(&self.output)?;
        let _ = fs::remove_file(&self.checkpoint_path);

        Ok(ExportReport {
            output: self.output,
            records: self.records,
            uncompressed_bytes: self.uncompressed,
            written_bytes,
            elapsed_ms: self.started.elapsed().as_millis(),
            resumed_from: self.resumed_from,
        })
    }

    fn discard(self) {
        drop(self.sink);
        let _ = fs::remove_file(&self.part);
        let _ = fs::remove_file(&self.checkpoint_path);
        let _ = fs::remove_file(&self.manifest_path);
    }
}

enum Body<'a> {
    Text(&'a [u8]),
    Reader(&'a mut dyn Read),
}

fn copy_stream(
    reader: &mut dyn Read,
    sink: &mut Sink,
    path: &Path,
) -> Result<(u64, Option<u8>)> {
    let mut buffer = vec![0u8; 256 * 1024];
    let mut last = None;
    let mut copied = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| GhirustError::io(path, source))?;
        if read == 0 {
            break;
        }
        sink.write_all(&buffer[..read])
            .map_err(|source| GhirustError::io(path, source))?;
        copied = copied.saturating_add(read as u64);
        last = Some(buffer[read - 1]);
    }
    Ok((copied, last))
}

fn format_function_header(name: &str, address: Option<&str>) -> String {
    match address {
        Some(address) if !address.is_empty() => {
            format!("\n// Function: {name} @ {address}\n")
        }
        _ => format!("\n// Function: {name}\n"),
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn read_checkpoint(path: &Path) -> Result<Checkpoint> {
    let bytes = fs::read(path).at(path)?;
    serde_json::from_slice(&bytes).map_err(|source| GhirustError::json(path, source))
}

fn write_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<()> {
    let temp = sibling(path, ".tmp");
    let bytes = serde_json::to_vec(checkpoint)
        .map_err(|source| GhirustError::json(path, source))?;
    fs::write(&temp, bytes).at(&temp)?;
    if path.exists() {
        fs::remove_file(path).at(path)?;
    }
    fs::rename(&temp, path).at(path)
}

fn truncate_manifest(path: &Path, records: u64) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if records == 0 {
        fs::remove_file(path).at(path)?;
        return Ok(());
    }

    let source = File::open(path).at(path)?;
    let mut reader = BufReader::new(source);
    let temp = sibling(path, ".truncate");
    let target = File::create(&temp).at(&temp)?;
    let mut writer = BufWriter::new(target);
    let mut line = Vec::new();
    let mut count = 0u64;
    while count < records {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).at(path)?;
        if read == 0 {
            break;
        }
        writer.write_all(&line).at(&temp)?;
        count += 1;
    }
    writer.flush().at(&temp)?;
    writer.get_ref().sync_all().at(&temp)?;

    fs::remove_file(path).at(path)?;
    fs::rename(&temp, path).at(path)
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let candidate = Path::new(relative);
    if candidate.is_absolute() {
        return Err(GhirustError::message(format!(
            "manifest entry must be relative, found: {relative}"
        )));
    }
    for component in candidate.components() {
        if matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_)) {
            return Err(GhirustError::message(format!(
                "manifest entry escapes the export directory: {relative}"
            )));
        }
    }
    Ok(root.join(candidate))
}

/// Export a newline-delimited JSON file, one [`FunctionRecord`] per line.
pub fn export_ndjson(input: &Path, options: &ExportOptions) -> Result<ExportReport> {
    let file = File::open(input).at(input)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut writer = ExportWriter::create(options)?;
    let skip = writer.resumed_from();

    let mut parsed = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).at(input)?;
        if read == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        if parsed < skip {
            parsed += 1;
            continue;
        }
        let record: FunctionRecord =
            serde_json::from_str(&line).map_err(|source| GhirustError::json(input, source))?;
        writer.write_record(&record)?;
        parsed += 1;
    }

    if writer.records == 0 {
        writer.discard();
        return Err(GhirustError::EmptyInput);
    }
    writer.finish()
}

/// Export a directory of function files.
///
/// If `manifest.ndjson` exists, it determines the order and the names.
/// Otherwise every `.c`, `.cc`, `.cpp` or `.cxx` file is exported in name
/// order, using the file stem as the function name.
pub fn export_directory(input: &Path, options: &ExportOptions) -> Result<ExportReport> {
    let manifest_path = input.join("manifest.ndjson");
    let entries = if manifest_path.exists() {
        read_directory_manifest(&manifest_path)?
    } else {
        discover_function_files(input)?
    };

    if entries.is_empty() {
        return Err(GhirustError::EmptyInput);
    }

    let mut writer = ExportWriter::create(options)?;
    let skip = writer.resumed_from();
    let mut processed = 0u64;

    for entry in entries {
        if processed < skip {
            processed += 1;
            continue;
        }
        let path = safe_join(input, &entry.file)?;
        let mut file = File::open(&path).at(&path)?;
        writer.write_function_from_reader(&entry.name, entry.address.as_deref(), &mut file)?;
        processed += 1;
    }

    if writer.records == 0 {
        writer.discard();
        return Err(GhirustError::EmptyInput);
    }
    writer.finish()
}

/// Export a single text file as one function body.
///
/// This is a convenience path for users who already have a `.c` file and want
/// to normalise it or compress it. The function name is the file stem.
pub fn export_single_file(input: &Path, options: &ExportOptions) -> Result<ExportReport> {
    let name = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("source")
        .to_owned();
    let mut file = File::open(input).at(input)?;
    let mut writer = ExportWriter::create(options)?;
    if writer.resumed_from() > 0 {
        writer.discard();
        return Err(GhirustError::message(
            "resuming is only supported for NDJSON or directory exports",
        ));
    }
    writer.write_function_from_reader(&name, None, &mut file)?;
    writer.finish()
}

/// Export either an NDJSON file, a single text file, or a directory.
///
/// The input kind is detected from the filesystem and the extension:
///
/// * directory → manifest/directory reader;
/// * `.c`, `.cc`, `.cpp`, `.cxx`, `.txt` → single-file copy;
/// * anything else → newline-delimited JSON.
pub fn export_input(input: &Path, options: &ExportOptions) -> Result<ExportReport> {
    let metadata = fs::metadata(input).at(input)?;
    if metadata.is_dir() {
        return export_directory(input, options);
    }
    let extension = input
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(extension.as_str(), "c" | "cc" | "cpp" | "cxx" | "txt") {
        export_single_file(input, options)
    } else {
        export_ndjson(input, options)
    }
}

fn read_directory_manifest(path: &Path) -> Result<Vec<ManifestRecord>> {
    let file = File::open(path).at(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line.at(path)?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: ManifestRecord =
            serde_json::from_str(&line).map_err(|source| GhirustError::json(path, source))?;
        entries.push(entry);
    }
    Ok(entries)
}

fn discover_function_files(input: &Path) -> Result<Vec<ManifestRecord>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(input).at(input)? {
        let entry = entry.at(input)?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "c" | "cc" | "cpp" | "cxx") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown")
            .to_owned();
        let file = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                GhirustError::message(format!("invalid file name in {}", input.display()))
            })?
            .to_owned();
        entries.push(ManifestRecord {
            name,
            address: None,
            file,
        });
    }
    entries.sort_by(|left, right| left.file.cmp(&right.file));
    Ok(entries)
}
