//! Persistent reverse-engineering projects.
//!
//! A project is a directory that contains:
//!
//! ```text
//! project.json                 manifest (programs, settings, timestamps)
//! programs/<id>/binary         imported copy (or a reference to the source path)
//! programs/<id>/analysis.json  complete ProgramAnalysis (listing, CFG, pseudocode)
//! programs/<id>/user.json      renames, comments, user types and bookmarks
//! sessions/<name>.json         cursor/selection/search state
//! ```
//!
//! Writes are crash-aware: data is written to a temporary file, the previous
//! version is moved to a backup and the new file is renamed into place. On
//! open, orphaned backups are restored and stale temporary files are removed.
//! This is deliberately a small, inspectable format rather than a database.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::analysis::{AnalysisOptions, ProgramAnalysis, analyze_path};
use crate::cache::hash_file;
use crate::error::{GhirustError, Result};
use crate::loader::load_or_hint;

/// Current project manifest version.
pub const PROJECT_VERSION: u32 = 1;

/// How an imported binary is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    /// Copy the binary into the project (portable).
    Copy,
    /// Record the original path only (no duplication).
    Reference,
}

/// Settings persisted with a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSettings {
    /// UI language tag, for example `en-US` or `pt-PT`.
    pub language: String,
    /// UI theme name.
    pub theme: String,
    /// Reconstruct pseudocode by default when analyzing.
    pub decompile_by_default: bool,
    /// Default function limit for interactive analysis.
    pub max_functions: usize,
}

impl Default for ProjectSettings {
    fn default() -> Self {
        Self {
            language: "en-US".to_owned(),
            theme: "dark".to_owned(),
            decompile_by_default: true,
            max_functions: 100_000,
        }
    }
}

/// One program imported into a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramEntry {
    /// Stable identifier derived from the content hash.
    pub id: String,
    /// User-facing name.
    pub display_name: String,
    /// Original source path recorded at import time.
    pub source_path: String,
    /// Path relative to the project root when the binary was copied.
    pub stored_path: Option<String>,
    /// SHA-256 of the imported bytes.
    pub sha256: String,
    /// Container format.
    pub format: String,
    /// Architecture label.
    pub architecture: String,
    /// Pointer width.
    pub bits: u8,
    /// Object kind.
    pub object_kind: String,
    /// Entry point.
    pub entry: u64,
    /// Import time (Unix seconds).
    pub imported_unix: u64,
    /// Last successful analysis time.
    pub analyzed_unix: Option<u64>,
    /// Number of functions in the saved analysis.
    pub function_count: u64,
    /// Number of instructions in the saved analysis.
    pub instruction_count: u64,
}

/// Project manifest stored as `project.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectManifest {
    /// Manifest format version.
    pub format_version: u32,
    /// Project name.
    pub name: String,
    /// Creation time (Unix seconds).
    pub created_unix: u64,
    /// Last modification time (Unix seconds).
    pub updated_unix: u64,
    /// Imported programs.
    pub programs: Vec<ProgramEntry>,
    /// Project settings.
    pub settings: ProjectSettings,
}

/// A user override for one function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionOverride {
    /// User-defined function name.
    pub name: Option<String>,
    /// User-defined return type.
    pub return_type: Option<String>,
    /// Function-level comment.
    pub comment: Option<String>,
}

/// A saved bookmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Virtual address.
    pub address: u64,
    /// Short label.
    pub label: String,
    /// Optional longer note.
    pub note: String,
}

/// Persistent user annotations for one program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOverrides {
    /// Override format version.
    pub format_version: u32,
    /// Function overrides keyed by entry address.
    pub functions: BTreeMap<u64, FunctionOverride>,
    /// Address comments.
    pub comments: BTreeMap<u64, String>,
    /// User-declared types keyed by address.
    pub data_types: BTreeMap<u64, String>,
    /// Bookmarks.
    pub bookmarks: Vec<Bookmark>,
}

impl Default for UserOverrides {
    fn default() -> Self {
        Self {
            format_version: 1,
            functions: BTreeMap::new(),
            comments: BTreeMap::new(),
            data_types: BTreeMap::new(),
            bookmarks: Vec::new(),
        }
    }
}

/// Saved UI session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Session format version.
    pub format_version: u32,
    /// Session name (also the file stem).
    pub name: String,
    /// Program selected at save time.
    pub program_id: Option<String>,
    /// Selected function entry address.
    pub selected_function: Option<u64>,
    /// Cursor address in the listing.
    pub cursor_address: Option<u64>,
    /// Last search query.
    pub search_query: Option<String>,
    /// Free-form notes.
    pub notes: String,
    /// Save time (Unix seconds).
    pub saved_unix: u64,
}

impl SessionState {
    /// Create an empty session with the current timestamp.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            format_version: 1,
            name: name.into(),
            program_id: None,
            selected_function: None,
            cursor_address: None,
            search_query: None,
            notes: String::new(),
            saved_unix: now_unix(),
        }
    }
}

/// Result of checking a project's files against recorded hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Per-program verification results.
    pub programs: Vec<ProgramVerification>,
    /// Whether every program and analysis verified.
    pub ok: bool,
}

/// Verification of one program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramVerification {
    /// Program identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Whether the binary exists and matches its recorded hash.
    pub binary_ok: bool,
    /// Whether the saved analysis exists and matches the binary hash.
    pub analysis_ok: bool,
    /// Human-readable explanation when a check failed.
    pub problem: Option<String>,
}

/// An open project.
#[derive(Debug, Clone)]
pub struct Project {
    root: PathBuf,
    manifest: ProjectManifest,
    recovered: Vec<String>,
}

impl Project {
    /// Create a new project directory.
    pub fn create(root: &Path, name: &str) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(GhirustError::message("project name must not be empty"));
        }
        if root.join("project.json").exists() {
            return Err(GhirustError::message(format!(
                "{} already contains a GHIRUST project",
                root.display()
            )));
        }
        fs::create_dir_all(root.join("programs")).map_err(|source| GhirustError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        fs::create_dir_all(root.join("sessions")).map_err(|source| GhirustError::Io {
            path: root.join("sessions"),
            source,
        })?;
        let now = now_unix();
        let manifest = ProjectManifest {
            format_version: PROJECT_VERSION,
            name: name.trim().to_owned(),
            created_unix: now,
            updated_unix: now,
            programs: Vec::new(),
            settings: ProjectSettings::default(),
        };
        let project = Self {
            root: root.to_path_buf(),
            manifest,
            recovered: Vec::new(),
        };
        project.save_manifest()?;
        Ok(project)
    }

    /// Open an existing project, restoring recoverable files first.
    pub fn open(root: &Path) -> Result<Self> {
        let recovered = recover(root)?;
        let manifest_path = root.join("project.json");
        let file = fs::File::open(&manifest_path).map_err(|source| GhirustError::Io {
            path: manifest_path.clone(),
            source,
        })?;
        let manifest: ProjectManifest =
            serde_json::from_reader(BufReader::new(file)).map_err(|source| {
                GhirustError::message(format!(
                    "{} is not a valid GHIRUST project manifest: {source}",
                    manifest_path.display()
                ))
            })?;
        if manifest.format_version > PROJECT_VERSION {
            return Err(GhirustError::message(format!(
                "project version {} is newer than this build supports ({PROJECT_VERSION})",
                manifest.format_version
            )));
        }
        fs::create_dir_all(root.join("programs")).map_err(|source| GhirustError::Io {
            path: root.join("programs"),
            source,
        })?;
        fs::create_dir_all(root.join("sessions")).map_err(|source| GhirustError::Io {
            path: root.join("sessions"),
            source,
        })?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            recovered,
        })
    }

    /// Project root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Project manifest.
    pub fn manifest(&self) -> &ProjectManifest {
        &self.manifest
    }

    /// Files repaired or cleaned during the last open.
    pub fn recovered(&self) -> &[String] {
        &self.recovered
    }

    /// Update project settings and persist them.
    pub fn set_settings(&mut self, settings: ProjectSettings) -> Result<()> {
        self.manifest.settings = settings;
        self.save_manifest()
    }

    /// Import a binary, copying it into the project by default.
    pub fn import(&mut self, path: &Path, mode: ImportMode) -> Result<ProgramEntry> {
        if !path.is_file() {
            return Err(GhirustError::message(format!(
                "{} is not a readable file",
                path.display()
            )));
        }
        let program = load_or_hint(path)?;
        if let Some(existing) = self
            .manifest
            .programs
            .iter()
            .find(|entry| entry.sha256 == program.sha256)
        {
            // The binary already exists in the project; do not import it twice.
            return Ok(existing.clone());
        }
        let id = next_program_id(&self.manifest, &program.sha256);
        let directory = self.program_directory(&id);
        fs::create_dir_all(&directory).map_err(|source| GhirustError::Io {
            path: directory.clone(),
            source,
        })?;
        let stored_path = match mode {
            ImportMode::Copy => {
                let target = directory.join("binary");
                fs::copy(path, &target).map_err(|source| GhirustError::Io {
                    path: target.clone(),
                    source,
                })?;
                Some(relative_string(&self.root, &target))
            }
            ImportMode::Reference => None,
        };
        let display_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&id)
            .to_owned();
        let entry = ProgramEntry {
            id,
            display_name,
            source_path: absolute_string(path),
            stored_path,
            sha256: program.sha256.clone(),
            format: program.format.clone(),
            architecture: program.architecture.clone(),
            bits: program.bits,
            object_kind: program.object_kind.clone(),
            entry: program.entry,
            imported_unix: now_unix(),
            analyzed_unix: None,
            function_count: 0,
            instruction_count: 0,
        };
        self.manifest.programs.push(entry.clone());
        self.save_manifest()?;
        Ok(entry)
    }

    /// Imported programs.
    pub fn programs(&self) -> &[ProgramEntry] {
        &self.manifest.programs
    }

    /// Find one program by exact ID.
    pub fn program(&self, id: &str) -> Result<&ProgramEntry> {
        self.manifest
            .programs
            .iter()
            .find(|program| program.id == id)
            .ok_or_else(|| GhirustError::message(format!("program '{id}' is not in this project")))
    }

    /// Path to the binary used for analysis.
    pub fn binary_path(&self, id: &str) -> Result<PathBuf> {
        let entry = self.program(id)?.clone();
        if let Some(stored) = &entry.stored_path {
            let path = self.root.join(stored);
            if path.is_file() {
                return Ok(path);
            }
        }
        let path = PathBuf::from(&entry.source_path);
        if path.is_file() {
            return Ok(path);
        }
        Err(GhirustError::message(format!(
            "binary for program '{id}' is missing (looked at {} and {})",
            self.root
                .join(entry.stored_path.unwrap_or_default())
                .display(),
            entry.source_path
        )))
    }

    /// Analyze a program and persist listing, CFG, GUIR and pseudocode.
    pub fn analyze(&mut self, id: &str, options: &AnalysisOptions) -> Result<ProgramAnalysis> {
        let path = self.binary_path(id)?;
        let analysis = analyze_path(&path, options)?;
        let entry = self
            .manifest
            .programs
            .iter()
            .find(|program| program.id == id)
            .ok_or_else(|| GhirustError::message(format!("program '{id}' is not in this project")))?
            .clone();
        if analysis.sha256 != entry.sha256 {
            return Err(GhirustError::message(format!(
                "program '{id}' changed on disk (expected {}, found {}); re-import it",
                entry.sha256, analysis.sha256
            )));
        }
        let analysis_path = self.analysis_path(id);
        write_json_atomic(&analysis_path, &analysis)?;
        if let Some(entry) = self
            .manifest
            .programs
            .iter_mut()
            .find(|program| program.id == id)
        {
            entry.analyzed_unix = Some(now_unix());
            entry.function_count = analysis.stats.functions;
            entry.instruction_count = analysis.stats.instructions;
        }
        self.save_manifest()?;
        Ok(analysis)
    }

    /// Load the saved analysis for a program.
    pub fn load_analysis(&self, id: &str) -> Result<ProgramAnalysis> {
        self.program(id)?;
        let path = self.analysis_path(id);
        let file = fs::File::open(&path).map_err(|source| GhirustError::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_reader(BufReader::new(file)).map_err(|source| {
            GhirustError::message(format!(
                "{} is not a valid saved analysis: {source}",
                path.display()
            ))
        })
    }

    /// Load an analysis and overlay saved user names, comments and types.
    pub fn load_analysis_with_overrides(&self, id: &str) -> Result<ProgramAnalysis> {
        let mut analysis = self.load_analysis(id)?;
        let overrides = self.load_overrides(id)?;
        apply_overrides(&mut analysis, &overrides);
        Ok(analysis)
    }

    /// Path of the saved analysis file.
    pub fn analysis_path(&self, id: &str) -> PathBuf {
        self.program_directory(id).join("analysis.json")
    }

    /// Load annotations, returning defaults when none were saved yet.
    pub fn load_overrides(&self, id: &str) -> Result<UserOverrides> {
        self.program(id)?;
        let path = self.program_directory(id).join("user.json");
        if !path.exists() {
            return Ok(UserOverrides::default());
        }
        let file = fs::File::open(&path).map_err(|source| GhirustError::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_reader(BufReader::new(file)).map_err(|source| {
            GhirustError::message(format!(
                "{} is not valid user annotation data: {source}",
                path.display()
            ))
        })
    }

    /// Persist annotations.
    pub fn save_overrides(&mut self, id: &str, overrides: &UserOverrides) -> Result<()> {
        self.program(id)?;
        let path = self.program_directory(id).join("user.json");
        write_json_atomic(&path, overrides)?;
        self.save_manifest()
    }

    /// Rename a function and persist the override.
    pub fn rename_function(&mut self, id: &str, address: u64, name: &str) -> Result<()> {
        validate_user_text(name, "function name")?;
        let analysis = self.load_analysis(id)?;
        if !analysis
            .functions
            .iter()
            .any(|function| function.address == address)
        {
            return Err(GhirustError::message(format!(
                "no function at 0x{address:x} in program '{id}'"
            )));
        }
        let mut overrides = self.load_overrides(id)?;
        overrides.functions.entry(address).or_default().name = Some(name.trim().to_owned());
        self.save_overrides(id, &overrides)
    }

    /// Set a return type override for a function.
    pub fn set_return_type(&mut self, id: &str, address: u64, ty: &str) -> Result<()> {
        validate_user_text(ty, "return type")?;
        let mut overrides = self.load_overrides(id)?;
        overrides.functions.entry(address).or_default().return_type = Some(ty.trim().to_owned());
        self.save_overrides(id, &overrides)
    }

    /// Add or replace a comment at an address.
    pub fn set_comment(&mut self, id: &str, address: u64, comment: &str) -> Result<()> {
        validate_user_text(comment, "comment")?;
        let mut overrides = self.load_overrides(id)?;
        if comment.trim().is_empty() {
            overrides.comments.remove(&address);
        } else {
            overrides
                .comments
                .insert(address, comment.trim().to_owned());
        }
        self.save_overrides(id, &overrides)
    }

    /// Declare a user type at an address.
    pub fn set_data_type(&mut self, id: &str, address: u64, ty: &str) -> Result<()> {
        validate_user_text(ty, "type")?;
        let mut overrides = self.load_overrides(id)?;
        if ty.trim().is_empty() {
            overrides.data_types.remove(&address);
        } else {
            overrides.data_types.insert(address, ty.trim().to_owned());
        }
        self.save_overrides(id, &overrides)
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, id: &str, address: u64, label: &str, note: &str) -> Result<()> {
        validate_user_text(label, "bookmark label")?;
        validate_user_text(note, "bookmark note")?;
        let mut overrides = self.load_overrides(id)?;
        overrides
            .bookmarks
            .retain(|bookmark| bookmark.address != address);
        overrides.bookmarks.push(Bookmark {
            address,
            label: label.trim().to_owned(),
            note: note.trim().to_owned(),
        });
        self.save_overrides(id, &overrides)
    }

    /// Save a session state by name.
    pub fn save_session(&self, session: &SessionState) -> Result<()> {
        validate_session_name(&session.name)?;
        let mut session = session.clone();
        session.saved_unix = now_unix();
        write_json_atomic(&self.session_path(&session.name), &session)
    }

    /// Load a session by name.
    pub fn load_session(&self, name: &str) -> Result<SessionState> {
        validate_session_name(name)?;
        let path = self.session_path(name);
        let file = fs::File::open(&path).map_err(|source| GhirustError::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_reader(BufReader::new(file)).map_err(|source| {
            GhirustError::message(format!(
                "{} is not a valid session: {source}",
                path.display()
            ))
        })
    }

    /// List saved session names, sorted.
    pub fn list_sessions(&self) -> Result<Vec<String>> {
        let directory = self.root.join("sessions");
        let mut names = Vec::new();
        let entries = fs::read_dir(&directory).map_err(|source| GhirustError::Io {
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| GhirustError::Io {
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("json")
                && let Some(stem) = path.file_stem().and_then(|value| value.to_str())
            {
                names.push(stem.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Verify every binary and saved analysis against its recorded hash.
    pub fn verify(&self) -> VerifyReport {
        let mut report = VerifyReport {
            programs: Vec::new(),
            ok: true,
        };
        for program in &self.manifest.programs {
            let mut binary_ok = false;
            let mut analysis_ok = false;
            let mut problem = None;
            match self.binary_path(&program.id) {
                Ok(path) => match hash_file(&path) {
                    Ok(hash) if hash == program.sha256 => binary_ok = true,
                    Ok(hash) => {
                        problem = Some(format!(
                            "binary hash mismatch: expected {}, found {}",
                            program.sha256, hash
                        ));
                    }
                    Err(error) => problem = Some(error.to_string()),
                },
                Err(error) => problem = Some(error.to_string()),
            }
            if binary_ok {
                let path = self.analysis_path(&program.id);
                if path.exists() {
                    match self.load_analysis(&program.id) {
                        Ok(analysis) if analysis.sha256 == program.sha256 => analysis_ok = true,
                        Ok(analysis) => {
                            problem = Some(format!(
                                "analysis hash mismatch: expected {}, found {}",
                                program.sha256, analysis.sha256
                            ));
                        }
                        Err(error) => problem = Some(error.to_string()),
                    }
                } else {
                    problem = Some("no saved analysis; run project analyze".to_owned());
                }
            }
            if !binary_ok || !analysis_ok {
                report.ok = false;
            }
            report.programs.push(ProgramVerification {
                id: program.id.clone(),
                name: program.display_name.clone(),
                binary_ok,
                analysis_ok,
                problem,
            });
        }
        report
    }

    fn program_directory(&self, id: &str) -> PathBuf {
        self.root.join("programs").join(id)
    }

    fn session_path(&self, name: &str) -> PathBuf {
        self.root.join("sessions").join(format!("{name}.json"))
    }

    fn save_manifest(&self) -> Result<()> {
        let mut manifest = self.manifest.clone();
        manifest.updated_unix = now_unix();
        write_json_atomic(&self.root.join("project.json"), &manifest)
    }
}

fn apply_overrides(analysis: &mut ProgramAnalysis, overrides: &UserOverrides) {
    for function in &mut analysis.functions {
        if let Some(user) = overrides.functions.get(&function.address) {
            if let Some(name) = &user.name {
                let old_name = function.name.clone();
                function.name = name.clone();
                if let Some(first_line) = function.decompiled.signature.lines().next() {
                    let replaced = first_line.replacen(&old_name, name, 1);
                    function.decompiled.signature = function
                        .decompiled
                        .signature
                        .replacen(first_line, &replaced, 1);
                }
                function.decompiled.text = function.decompiled.text.replacen(
                    &format!("// Symbol: {old_name}"),
                    &format!("// Original symbol: {old_name}"),
                    1,
                );
                function.decompiled.text = function.decompiled.text.replacen(&old_name, name, 1);
            }
            if let Some(return_type) = &user.return_type {
                function.decompiled.return_type = return_type.clone();
                if let Some((_, rest)) = function.decompiled.signature.split_once(' ') {
                    function.decompiled.signature = format!("{return_type} {rest}");
                }
            }
        }
    }
    if !overrides.comments.is_empty() || !overrides.data_types.is_empty() {
        let mut overlay = String::new();
        for (address, comment) in &overrides.comments {
            overlay.push_str(&format!("// user comment @ 0x{address:x}: {comment}\n"));
        }
        for (address, ty) in &overrides.data_types {
            overlay.push_str(&format!("// user type @ 0x{address:x}: {ty}\n"));
        }
        for function in &mut analysis.functions {
            if overrides.comments.contains_key(&function.address)
                || overrides.data_types.contains_key(&function.address)
            {
                function.decompiled.text.push_str(&format!("\n{overlay}"));
            }
        }
    }
}

fn next_program_id(manifest: &ProjectManifest, sha256: &str) -> String {
    let base = sha256.get(..16).unwrap_or(sha256).to_owned();
    if !manifest.programs.iter().any(|program| program.id == base) {
        return base;
    }
    for suffix in 2..10_000 {
        let candidate = format!("{base}-{suffix}");
        if !manifest
            .programs
            .iter()
            .any(|program| program.id == candidate)
        {
            return candidate;
        }
    }
    let digest = &sha256[sha256.len().saturating_sub(16)..];
    format!("{base}-{digest}")
}

fn validate_user_text(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(GhirustError::message(format!("{label} must not be empty")));
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(GhirustError::message(format!(
            "{label} must not contain control characters"
        )));
    }
    if value.chars().count() > 4_096 {
        return Err(GhirustError::message(format!(
            "{label} is too long (maximum 4096 characters)"
        )));
    }
    Ok(())
}

fn validate_session_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        || name.contains("..")
    {
        return Err(GhirustError::message(
            "session names may contain only letters, digits, '-', '_' and '.', and must not contain '..'",
        ));
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn absolute_string(path: &Path) -> String {
    if path.is_absolute() {
        path.display().to_string()
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    }
}

fn relative_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| GhirustError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let temporary = temporary_path(path);
    {
        let file = fs::File::create(&temporary).map_err(|source| GhirustError::Io {
            path: temporary.clone(),
            source,
        })?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, value).map_err(|source| {
            GhirustError::message(format!("could not serialize {}: {source}", path.display()))
        })?;
        writer.flush().map_err(|source| GhirustError::Io {
            path: temporary.clone(),
            source,
        })?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|source| GhirustError::Io {
                path: temporary.clone(),
                source,
            })?;
    }
    replace_file(&temporary, path)
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("data");
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}

fn backup_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("data");
    path.with_file_name(format!("{name}.bak"))
}

fn replace_file(temporary: &Path, destination: &Path) -> Result<()> {
    let backup = backup_path(destination);
    if backup.exists() {
        let _ = fs::remove_file(&backup);
    }
    let had_destination = destination.exists();
    if had_destination {
        fs::rename(destination, &backup).map_err(|source| GhirustError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    }
    match fs::rename(temporary, destination) {
        Ok(()) => {
            if backup.exists() {
                let _ = fs::remove_file(&backup);
            }
            Ok(())
        }
        Err(source) => {
            if had_destination && backup.exists() {
                let _ = fs::rename(&backup, destination);
            }
            Err(GhirustError::Io {
                path: destination.to_path_buf(),
                source,
            })
        }
    }
}

/// Restore backups and remove stale temporary files in a project directory.
pub fn recover(root: &Path) -> Result<Vec<String>> {
    let mut recovered = Vec::new();
    if !root.is_dir() {
        return Ok(recovered);
    }
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(recovered);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.contains(".tmp-") {
            if fs::remove_file(&path).is_ok() {
                recovered.push(format!("removed stale temporary {}", path.display()));
            }
            continue;
        }
        if let Some(stem) = name.strip_suffix(".bak") {
            let destination = root.join(stem);
            if destination.exists() {
                let _ = fs::remove_file(&path);
            } else if fs::rename(&path, &destination).is_ok() {
                recovered.push(format!("restored {}", destination.display()));
            }
        }
    }
    // Recurse into programs so a crash during analysis is also recoverable.
    let programs = root.join("programs");
    if let Ok(entries) = fs::read_dir(&programs) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                recovered.extend(recover(&entry.path())?);
            }
        }
    }
    Ok(recovered)
}

/// Load a project from a path, creating it when `name` is provided and the
/// directory does not contain a manifest yet.
pub fn open_or_create(root: &Path, name: Option<&str>) -> Result<Project> {
    if root.join("project.json").exists() {
        Project::open(root)
    } else if let Some(name) = name {
        Project::create(root, name)
    } else {
        Project::open(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture() -> Option<PathBuf> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..")
            .join("tests")
            .join("objectives")
            .join("binaries")
            .join("demo.dll");
        path.is_file().then_some(path)
    }

    #[test]
    fn project_import_analyze_and_reopen() {
        let Some(binary) = fixture() else {
            return;
        };
        let temp = tempdir().unwrap();
        let root = temp.path().join("project");
        let mut project = Project::create(&root, "Objective project").unwrap();
        let entry = project.import(&binary, ImportMode::Copy).unwrap();
        assert_eq!(entry.format, "PE");
        assert!(
            root.join("programs")
                .join(&entry.id)
                .join("binary")
                .is_file()
        );

        let analysis = project
            .analyze(
                &entry.id,
                &AnalysisOptions {
                    max_functions: 500,
                    decompile: true,
                    ..AnalysisOptions::default()
                },
            )
            .unwrap();
        assert!(analysis.functions.iter().any(|f| f.name == "demo_add"));
        assert!(project.analysis_path(&entry.id).is_file());

        project
            .rename_function(&entry.id, analysis.functions[0].address, "renamed_entry")
            .unwrap();
        project
            .set_comment(&entry.id, analysis.functions[0].address, "entry comment")
            .unwrap();
        project
            .set_data_type(&entry.id, 0x180001000, "demo_context")
            .unwrap();
        project
            .add_bookmark(&entry.id, 0x180001000, "start", "first function")
            .unwrap();

        let mut session = SessionState::new("main");
        session.program_id = Some(entry.id.clone());
        session.selected_function = Some(analysis.functions[0].address);
        session.cursor_address = Some(0x180001000);
        session.search_query = Some("demo".to_owned());
        project.save_session(&session).unwrap();

        let reopened = Project::open(&root).unwrap();
        assert_eq!(reopened.manifest().programs.len(), 1);
        let overrides = reopened.load_overrides(&entry.id).unwrap();
        assert_eq!(
            overrides.functions[&analysis.functions[0].address]
                .name
                .as_deref(),
            Some("renamed_entry")
        );
        assert_eq!(
            overrides.comments[&analysis.functions[0].address],
            "entry comment"
        );
        assert_eq!(overrides.data_types[&0x180001000], "demo_context");
        assert_eq!(overrides.bookmarks.len(), 1);

        let with_overrides = reopened.load_analysis_with_overrides(&entry.id).unwrap();
        let renamed = with_overrides
            .functions
            .iter()
            .find(|function| function.address == analysis.functions[0].address)
            .unwrap();
        assert_eq!(renamed.name, "renamed_entry");
        assert!(renamed.decompiled.text.contains("user comment @ 0x"));

        let loaded_session = reopened.load_session("main").unwrap();
        assert_eq!(loaded_session.program_id, Some(entry.id.clone()));
        assert_eq!(reopened.list_sessions().unwrap(), vec!["main".to_owned()]);

        let report = reopened.verify();
        assert!(report.ok, "{report:?}");
    }

    #[test]
    fn duplicate_import_reuses_the_existing_program() {
        let Some(binary) = fixture() else {
            return;
        };
        let temp = tempdir().unwrap();
        let mut project = Project::create(temp.path(), "duplicates").unwrap();
        let first = project.import(&binary, ImportMode::Reference).unwrap();
        let second = project.import(&binary, ImportMode::Reference).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(project.programs().len(), 1);
    }

    #[test]
    fn rejects_unsafe_program_and_session_names() {
        let temp = tempdir().unwrap();
        let project = Project::create(temp.path(), "safe").unwrap();
        assert!(project.program("../escape").is_err());
        assert!(project.load_session("../escape").is_err());
        assert!(validate_session_name("...").is_err());
        assert!(validate_session_name("valid-name_1").is_ok());
    }

    #[test]
    fn restores_a_backup_manifest_after_a_crash() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("recover");
        Project::create(&root, "recoverable").unwrap();
        let manifest = root.join("project.json");
        let backup = root.join("project.json.bak");
        fs::rename(&manifest, &backup).unwrap();
        fs::write(root.join(".project.json.tmp-1"), b"partial").unwrap();
        let project = Project::open(&root).unwrap();
        assert_eq!(project.manifest().name, "recoverable");
        assert!(!backup.exists());
        assert!(!root.join(".project.json.tmp-1").exists());
        assert!(!project.recovered().is_empty());
    }
}
