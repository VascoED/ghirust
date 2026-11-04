//! Fast search over exported decompilation.
//!
//! Two strategies are used:
//!
//! * **Symbol search** walks the persisted function index. Tens of thousands
//!   of names can be filtered in a few milliseconds.
//! * **Text search** memory-maps each source file and uses SIMD-accelerated
//!   substring search (`memchr`). Files are processed in parallel batches
//!   with Rayon, stopping once the global result cap is known to be exceeded.
//!
//! No query ever copies a whole source file into memory, and no query rescans
//! the Ghidra database.

use std::time::Instant;

use memchr::{memchr_iter, memchr2, memmem, memrchr};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::{GhirustError, Result};
use crate::filemap::ReadOnlyMap;
use crate::index::SearchIndex;

/// How a query should be interpreted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchMode {
    /// Detect `name:` / `text:` / `file:` prefixes, otherwise text search.
    #[default]
    Auto,
    /// Match function names and addresses.
    Name,
    /// Match file contents.
    Text,
    /// Match indexed file paths.
    File,
}

impl SearchMode {
    /// Parse a user-facing mode name.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "name" | "symbol" | "function" => Some(Self::Name),
            "text" | "code" => Some(Self::Text),
            "file" | "path" => Some(Self::File),
            _ => None,
        }
    }
}

/// Search configuration.
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// Query text. May include `name:`, `text:` or `file:`.
    pub query: String,
    /// Explicit mode, or [`SearchMode::Auto`].
    pub mode: SearchMode,
    /// Case-insensitive matching.
    pub ignore_case: bool,
    /// Maximum number of hits returned.
    pub limit: usize,
    /// Maximum characters kept in a snippet.
    pub snippet_chars: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            query: String::new(),
            mode: SearchMode::Auto,
            ignore_case: false,
            limit: 100,
            snippet_chars: 240,
        }
    }
}

/// One search result.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    /// File path relative to the index root.
    pub file: String,
    /// 1-based line number.
    pub line: u64,
    /// 1-based byte column.
    pub column: u64,
    /// The matching line, trimmed.
    pub text: String,
    /// Enclosing function, when known.
    pub function: Option<String>,
    /// Enclosing function address, when known.
    pub address: Option<String>,
    /// Optional relevance score (highest first for symbol searches).
    pub score: u32,
}

/// The result of a complete search.
#[derive(Debug, Clone, Serialize)]
pub struct SearchReport {
    /// Original query after prefix removal.
    pub query: String,
    /// Effective mode.
    pub mode: SearchMode,
    /// Hits, already sorted and truncated.
    pub hits: Vec<SearchHit>,
    /// Whether at least one result was omitted.
    pub truncated: bool,
    /// Bytes of text examined.
    pub scanned_bytes: u64,
    /// Wall-clock duration.
    pub elapsed_ms: u128,
}

/// Default search parallelism: a bounded fraction of the machine. Searches
/// never occupy every core by default.
pub fn search_worker_limit() -> usize {
    let logical = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    (logical / 2).clamp(1, 4)
}

/// Execute a search against a previously built index. The parallel text scan
/// runs on a bounded worker pool (see [`search_worker_limit`]), never on the
/// global rayon pool with every core.
pub fn search(index: &SearchIndex, options: &SearchOptions) -> Result<SearchReport> {
    let workers = search_worker_limit();
    search_with_workers(index, options, workers)
}

/// Execute a search with an explicit worker limit (clamped to 1..=64).
pub fn search_with_workers(
    index: &SearchIndex,
    options: &SearchOptions,
    workers: usize,
) -> Result<SearchReport> {
    let workers = workers.clamp(1, 64);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|index| format!("ghirust-search-{index}"))
        .build()
        .map_err(|error| GhirustError::message(format!("could not build search pool: {error}")))?;
    pool.install(|| search_in_pool(index, options))
}

fn search_in_pool(index: &SearchIndex, options: &SearchOptions) -> Result<SearchReport> {
    let started = Instant::now();
    let (query, mode) = resolve_query(options);
    if query.is_empty() {
        return Err(GhirustError::EmptyQuery);
    }

    let limit = options.limit.max(1);
    let mut report = match mode {
        SearchMode::Name => search_names(index, &query, options, limit),
        SearchMode::File => search_files(index, &query, options, limit),
        SearchMode::Text | SearchMode::Auto => search_text(index, &query, options, limit)?,
    };
    report.query = query;
    report.mode = mode;
    report.elapsed_ms = started.elapsed().as_millis();
    Ok(report)
}

fn resolve_query(options: &SearchOptions) -> (String, SearchMode) {
    let query = options.query.trim();
    if options.mode != SearchMode::Auto {
        return (query.to_owned(), options.mode);
    }

    for (prefix, mode) in [
        ("name:", SearchMode::Name),
        ("symbol:", SearchMode::Name),
        ("text:", SearchMode::Text),
        ("code:", SearchMode::Text),
        ("file:", SearchMode::File),
        ("path:", SearchMode::File),
    ] {
        if let Some(rest) = query.strip_prefix(prefix) {
            return (rest.trim().to_owned(), mode);
        }
    }
    (query.to_owned(), SearchMode::Text)
}

fn search_names(
    index: &SearchIndex,
    query: &str,
    options: &SearchOptions,
    limit: usize,
) -> SearchReport {
    let query_folded = fold(query, options.ignore_case);
    let mut hits = Vec::new();
    let mut truncated = false;

    for function in &index.functions {
        let name_folded = fold(&function.name, options.ignore_case);
        let address_matches = function
            .address
            .as_deref()
            .map(|address| fold(address, options.ignore_case).contains(&query_folded))
            .unwrap_or(false);

        let score = if name_folded == query_folded {
            100
        } else if name_folded.starts_with(&query_folded) {
            80
        } else if name_folded.contains(&query_folded) {
            60
        } else if address_matches {
            40
        } else {
            continue;
        };

        if hits.len() >= limit {
            truncated = true;
            break;
        }

        let file = index
            .files
            .get(function.file_id as usize)
            .map(|file| file.path.clone())
            .unwrap_or_default();
        let mut text = function.name.clone();
        if let Some(address) = &function.address {
            text.push_str(" @ ");
            text.push_str(address);
        }
        hits.push(SearchHit {
            file,
            line: function.line,
            column: 1,
            text,
            function: Some(function.name.clone()),
            address: function.address.clone(),
            score,
        });
    }

    hits.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.function.cmp(&right.function))
    });

    SearchReport {
        query: String::new(),
        mode: SearchMode::Name,
        hits,
        truncated,
        scanned_bytes: 0,
        elapsed_ms: 0,
    }
}

fn search_files(
    index: &SearchIndex,
    query: &str,
    options: &SearchOptions,
    limit: usize,
) -> SearchReport {
    let query_folded = fold(query, options.ignore_case);
    let mut hits = Vec::new();
    let mut truncated = false;

    for (file_id, file) in index.files.iter().enumerate() {
        if !fold(&file.path, options.ignore_case).contains(&query_folded) {
            continue;
        }

        let mut file_functions: Vec<_> = index.functions_for_file(file_id as u32).collect();
        if file_functions.is_empty() {
            if hits.len() >= limit {
                truncated = true;
                break;
            }
            hits.push(SearchHit {
                file: file.path.clone(),
                line: 1,
                column: 1,
                text: file.path.clone(),
                function: None,
                address: None,
                score: 50,
            });
            continue;
        }

        file_functions.sort_by_key(|function| function.line);
        for function in file_functions {
            if hits.len() >= limit {
                truncated = true;
                break;
            }
            hits.push(SearchHit {
                file: file.path.clone(),
                line: function.line,
                column: 1,
                text: format!("{} · {} function(s)", file.path, file.functions),
                function: Some(function.name.clone()),
                address: function.address.clone(),
                score: 50,
            });
        }
        if truncated {
            break;
        }
    }

    SearchReport {
        query: String::new(),
        mode: SearchMode::File,
        hits,
        truncated,
        scanned_bytes: 0,
        elapsed_ms: 0,
    }
}

struct FileSearch {
    hits: Vec<SearchHit>,
    scanned_bytes: u64,
}

fn search_text(
    index: &SearchIndex,
    query: &str,
    options: &SearchOptions,
    limit: usize,
) -> Result<SearchReport> {
    let needle = query.as_bytes().to_vec();
    let ignore_case = options.ignore_case;
    let snippet_chars = options.snippet_chars.max(32);

    let mut all_hits = Vec::new();
    let mut scanned_bytes = 0u64;
    let mut truncated = false;
    let mut file_order: Vec<usize> = (0..index.files.len()).collect();
    file_order.sort_by(|left, right| index.files[*left].path.cmp(&index.files[*right].path));

    for batch in file_order.chunks(rayon::current_num_threads().max(1)) {
        let file_limit = limit.saturating_sub(all_hits.len()).saturating_add(1);
        let file_results: Vec<Result<FileSearch>> = batch
            .par_iter()
            .map(|&file_id| {
                let file = &index.files[file_id];
                let path = index.root.join(&file.path);
                let map = ReadOnlyMap::open(&path)?;
                let bytes = map.bytes();
                let positions = find_positions(bytes, &needle, ignore_case, file_limit);

                let mut tracker = LineTracker::new();
                let mut hits = Vec::with_capacity(positions.len());
                for position in positions {
                    let (line, line_start) = tracker.locate(bytes, position);
                    let line_end = memchr_iter(b'\n', &bytes[position..])
                        .next()
                        .map(|offset| position + offset)
                        .unwrap_or(bytes.len());
                    let snippet = snippet(bytes, line_start, line_end, snippet_chars);
                    let enclosing = index.enclosing_function(file_id as u32, position as u64);
                    hits.push(SearchHit {
                        file: file.path.clone(),
                        line,
                        column: (position.saturating_sub(line_start) + 1) as u64,
                        text: snippet,
                        function: enclosing.map(|function| function.name.clone()),
                        address: enclosing.and_then(|function| function.address.clone()),
                        score: 0,
                    });
                }

                Ok(FileSearch {
                    hits,
                    scanned_bytes: bytes.len() as u64,
                })
            })
            .collect();

        for result in file_results {
            let result = result?;
            scanned_bytes = scanned_bytes.saturating_add(result.scanned_bytes);
            all_hits.extend(result.hits);
        }

        if all_hits.len() > limit {
            all_hits.truncate(limit);
            truncated = true;
            break;
        }
    }

    all_hits.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.column.cmp(&right.column))
    });
    Ok(SearchReport {
        query: String::new(),
        mode: SearchMode::Text,
        hits: all_hits,
        truncated,
        scanned_bytes,
        elapsed_ms: 0,
    })
}

fn find_positions(haystack: &[u8], needle: &[u8], ignore_case: bool, limit: usize) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    if !ignore_case {
        return memmem::find_iter(haystack, needle).take(limit).collect();
    }

    let first = needle[0];
    let lower = first.to_ascii_lowercase();
    let upper = first.to_ascii_uppercase();
    let mut positions = Vec::new();
    let mut start = 0usize;
    while positions.len() < limit {
        let Some(offset) = memchr2(lower, upper, &haystack[start..]) else {
            break;
        };
        let position = start + offset;
        if haystack.len().saturating_sub(position) >= needle.len()
            && haystack[position..position + needle.len()].eq_ignore_ascii_case(needle)
        {
            positions.push(position);
        }
        start = position + 1;
    }
    positions
}

struct LineTracker {
    position: usize,
    line: u64,
    line_start: usize,
}

impl LineTracker {
    fn new() -> Self {
        Self {
            position: 0,
            line: 1,
            line_start: 0,
        }
    }

    fn locate(&mut self, bytes: &[u8], position: usize) -> (u64, usize) {
        let slice = &bytes[self.position..position];
        self.line += memchr_iter(b'\n', slice).count() as u64;
        if let Some(last_newline) = memrchr(b'\n', slice) {
            self.line_start = self.position + last_newline + 1;
        }
        self.position = position;
        (self.line, self.line_start)
    }
}

fn snippet(bytes: &[u8], start: usize, end: usize, max_chars: usize) -> String {
    let line = String::from_utf8_lossy(&bytes[start..end]);
    let line = line.trim().trim_end_matches('\r');
    truncate_chars(line, max_chars)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut result: String = value.chars().take(max_chars.saturating_sub(1)).collect();
    result.push('…');
    result
}

fn fold(value: &str, ignore_case: bool) -> String {
    if ignore_case {
        value.to_lowercase()
    } else {
        value.to_owned()
    }
}
