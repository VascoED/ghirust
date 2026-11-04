//! `ghirust project` — persistent reverse-engineering projects.
//!
//! A project groups imported binaries, saved analyses, user annotations
//! (renames, comments, data types, bookmarks) and named UI sessions. The
//! commands here are thin wrappers around [`ghirust_core::project`] so the GUI
//! and the CLI operate on exactly the same on-disk format.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};

use ghirust_core::analysis::AnalysisOptions;
use ghirust_core::project::{ImportMode, Project, SessionState};

/// Storage policy for an imported binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportModeArg {
    /// Copy the binary into the project so the project stays portable.
    Copy,
    /// Record the original path only; no bytes are duplicated.
    Reference,
}

impl From<ImportModeArg> for ImportMode {
    fn from(value: ImportModeArg) -> Self {
        match value {
            ImportModeArg::Copy => ImportMode::Copy,
            ImportModeArg::Reference => ImportMode::Reference,
        }
    }
}

/// Arguments for `ghirust project`.
#[derive(Debug, Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Create a new project directory.
    Create(CreateArgs),
    /// Import a binary into a project.
    Import(ImportArgs),
    /// Disassemble and decompile an imported program, saving the analysis.
    Analyze(ProjectAnalyzeArgs),
    /// List imported programs.
    List(ProjectRootArgs),
    /// Show details for one program.
    Show(ProgramArgs),
    /// Rename a recovered function.
    Rename(AnnotationArgs),
    /// Set a comment at an address.
    Comment(AnnotationArgs),
    /// Declare a user data type at an address.
    Type(AnnotationArgs),
    /// Add or replace a bookmark.
    Bookmark(BookmarkArgs),
    /// Manage named UI sessions.
    Session(SessionArgs),
    /// Verify binaries and saved analyses against recorded hashes.
    Verify(ProjectRootArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Directory that will hold the project.
    pub root: PathBuf,

    /// Project name.
    #[arg(long)]
    pub name: String,

    /// UI language tag recorded in the manifest.
    #[arg(long, default_value = "en-US")]
    pub language: String,

    /// UI theme recorded in the manifest.
    #[arg(long, default_value = "dark")]
    pub theme: String,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Binary to import.
    pub file: PathBuf,

    /// Copy the binary into the project (default) or store a reference.
    #[arg(long, value_enum, default_value_t = ImportModeArg::Copy)]
    pub mode: ImportModeArg,
}

#[derive(Debug, Args)]
pub struct ProjectAnalyzeArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Program identifier shown by `project list`.
    pub program: String,

    /// Maximum number of functions retained.
    #[arg(long, default_value_t = 100_000)]
    pub max_functions: usize,

    /// Skip pseudocode reconstruction.
    #[arg(long)]
    pub no_decompile: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ProjectRootArgs {
    /// Project directory.
    pub root: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct ProgramArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Program identifier.
    pub program: String,
}

#[derive(Debug, Clone, Args)]
pub struct AnnotationArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Program identifier.
    pub program: String,

    /// Address (0x-prefixed hexadecimal or decimal).
    pub address: String,

    /// New value (name, comment or type).
    pub value: String,
}

#[derive(Debug, Args)]
pub struct BookmarkArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Program identifier.
    pub program: String,

    /// Address (0x-prefixed hexadecimal or decimal).
    pub address: String,

    /// Short bookmark label.
    pub label: String,

    /// Optional longer note.
    #[arg(long, default_value = "")]
    pub note: String,
}

#[derive(Debug, Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Save a named session.
    Save(SessionSaveArgs),
    /// Load and print a named session.
    Load(SessionLoadArgs),
    /// List saved sessions.
    List(ProjectRootArgs),
}

#[derive(Debug, Args)]
pub struct SessionSaveArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Session name (letters, digits, '-', '_' and '.').
    pub name: String,

    /// Program identifier selected in the session.
    #[arg(long)]
    pub program: Option<String>,

    /// Selected function address.
    #[arg(long)]
    pub function: Option<String>,

    /// Listing cursor address.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Last search query.
    #[arg(long)]
    pub search: Option<String>,

    /// Free-form session notes.
    #[arg(long, default_value = "")]
    pub notes: String,
}

#[derive(Debug, Args)]
pub struct SessionLoadArgs {
    /// Project directory.
    pub root: PathBuf,

    /// Session name.
    pub name: String,
}

fn open(root: &std::path::Path) -> Result<Project> {
    Project::open(root).with_context(|| format!("could not open project at {}", root.display()))
}

fn parse_address(value: &str) -> Result<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .with_context(|| format!("'{value}' is not a valid hexadecimal address"))
    } else {
        value
            .parse::<u64>()
            .with_context(|| format!("'{value}' is not a valid decimal address"))
    }
}

pub fn run(args: &ProjectArgs, json: bool) -> Result<()> {
    match &args.command {
        ProjectCommand::Create(args) => run_create(args, json),
        ProjectCommand::Import(args) => run_import(args, json),
        ProjectCommand::Analyze(args) => run_analyze(args, json),
        ProjectCommand::List(args) => run_list(args, json),
        ProjectCommand::Show(args) => run_show(args, json),
        ProjectCommand::Rename(args) => run_annotation(args, AnnotationKind::Rename, json),
        ProjectCommand::Comment(args) => run_annotation(args, AnnotationKind::Comment, json),
        ProjectCommand::Type(args) => run_annotation(args, AnnotationKind::Type, json),
        ProjectCommand::Bookmark(args) => run_bookmark(args, json),
        ProjectCommand::Session(args) => match &args.command {
            SessionCommand::Save(args) => run_session_save(args, json),
            SessionCommand::Load(args) => run_session_load(args, json),
            SessionCommand::List(args) => run_session_list(args, json),
        },
        ProjectCommand::Verify(args) => run_verify(args, json),
    }
}

fn run_create(args: &CreateArgs, json: bool) -> Result<()> {
    let project = Project::create(&args.root, &args.name)
        .with_context(|| format!("could not create project at {}", args.root.display()))?;
    let mut settings = project.manifest().settings.clone();
    settings.language = args.language.clone();
    settings.theme = args.theme.clone();
    let mut project = project;
    project.set_settings(settings)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "root": project.root(),
                "manifest": project.manifest(),
            }))?
        );
        return Ok(());
    }
    println!("Created project '{}'", project.manifest().name);
    println!("Root: {}", project.root().display());
    println!(
        "Language: {} · theme: {}",
        project.manifest().settings.language,
        project.manifest().settings.theme
    );
    println!(
        "Next: ghirust project import {} <binary>",
        project.root().display()
    );
    Ok(())
}

fn run_import(args: &ImportArgs, json: bool) -> Result<()> {
    let mut project = open(&args.root)?;
    let entry = project
        .import(&args.file, args.mode.into())
        .with_context(|| format!("could not import {}", args.file.display()))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "program": entry,
                "root": project.root(),
            }))?
        );
        return Ok(());
    }
    println!("Imported {} as program {}", entry.display_name, entry.id);
    println!(
        "Format: {} · {} · {}-bit · entry 0x{:x}",
        entry.format, entry.architecture, entry.bits, entry.entry
    );
    println!("SHA-256: {}", entry.sha256);
    match &entry.stored_path {
        Some(path) => println!("Stored: {}", project.root().join(path).display()),
        None => println!("Referenced: {}", entry.source_path),
    }
    println!(
        "Next: ghirust project analyze {} {}",
        project.root().display(),
        entry.id
    );
    Ok(())
}

fn run_analyze(args: &ProjectAnalyzeArgs, json: bool) -> Result<()> {
    let mut project = open(&args.root)?;
    let options = AnalysisOptions {
        max_functions: args.max_functions,
        decompile: !args.no_decompile,
        ..AnalysisOptions::default()
    };
    let analysis = project
        .analyze(&args.program, &options)
        .with_context(|| format!("could not analyze program '{}'", args.program))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "program": args.program,
                "sha256": analysis.sha256,
                "stats": analysis.stats,
                "loader": analysis.loader,
                "functions": analysis.functions.iter().take(50).map(|function| {
                    serde_json::json!({
                        "address": function.address,
                        "name": function.name,
                        "discovery": function.discovery,
                        "confidence": function.confidence,
                        "instructions": function.instruction_count,
                        "blocks": function.blocks.len(),
                        "signature": function.decompiled.signature,
                    })
                }).collect::<Vec<_>>(),
                "saved": project.analysis_path(&args.program),
            }))?
        );
        return Ok(());
    }
    println!(
        "Analyzed program {} · {} functions · {} instructions · {} blocks · {} xrefs",
        args.program,
        analysis.stats.functions,
        analysis.stats.instructions,
        analysis.stats.blocks,
        analysis.stats.xrefs
    );
    println!("Saved: {}", project.analysis_path(&args.program).display());
    if !analysis.functions.is_empty() {
        println!("\nFunctions:");
        for function in analysis.functions.iter().take(25) {
            println!(
                "  0x{:08x}  {:<32} {:<10} {:>4.0}%  {} insn",
                function.address,
                truncate(&function.name, 32),
                function.discovery,
                function.confidence * 100.0,
                function.instruction_count
            );
        }
        if analysis.functions.len() > 25 {
            println!("  … {} more", analysis.functions.len() - 25);
        }
    }
    Ok(())
}

fn run_list(args: &ProjectRootArgs, json: bool) -> Result<()> {
    let project = open(&args.root)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "root": project.root(),
                "name": project.manifest().name,
                "programs": project.programs(),
                "sessions": project.list_sessions().unwrap_or_default(),
            }))?
        );
        return Ok(());
    }
    println!("Project: {}", project.manifest().name);
    println!("Root: {}", project.root().display());
    if project.programs().is_empty() {
        println!("No programs imported yet.");
        println!(
            "Next: ghirust project import {} <binary>",
            project.root().display()
        );
        return Ok(());
    }
    println!(
        "\n{:<18} {:<28} {:<8} {:<10} {:<10} SHA-256",
        "Program", "Name", "Format", "Functions", "Analyzed"
    );
    for program in project.programs() {
        println!(
            "{:<18} {:<28} {:<8} {:<10} {:<10} {}",
            program.id,
            truncate(&program.display_name, 28),
            program.format,
            program.function_count,
            program
                .analyzed_unix
                .map(|value| value.to_string())
                .unwrap_or_else(|| "never".to_owned()),
            &program.sha256[..program.sha256.len().min(16)]
        );
    }
    Ok(())
}

fn run_show(args: &ProgramArgs, json: bool) -> Result<()> {
    let project = open(&args.root)?;
    let program = project.program(&args.program)?;
    let overrides = project.load_overrides(&args.program)?;
    let analysis_exists = project.analysis_path(&args.program).is_file();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "program": program,
                "binary": project.binary_path(&args.program).ok(),
                "analysis": project.analysis_path(&args.program),
                "analysis_saved": analysis_exists,
                "overrides": overrides,
            }))?
        );
        return Ok(());
    }
    println!("Program: {}", program.id);
    println!("Name: {}", program.display_name);
    println!(
        "Format: {} · {} · {}-bit · entry 0x{:x}",
        program.format, program.architecture, program.bits, program.entry
    );
    println!("SHA-256: {}", program.sha256);
    println!("Source: {}", program.source_path);
    match project.binary_path(&args.program) {
        Ok(path) => println!("Binary: {}", path.display()),
        Err(error) => println!("Binary: missing ({error})"),
    }
    println!(
        "Analysis: {} ({})",
        if analysis_exists { "saved" } else { "missing" },
        project.analysis_path(&args.program).display()
    );
    println!(
        "Functions: {} · instructions: {}",
        program.function_count, program.instruction_count
    );
    println!(
        "Annotations: {} function override(s), {} comment(s), {} type(s), {} bookmark(s)",
        overrides.functions.len(),
        overrides.comments.len(),
        overrides.data_types.len(),
        overrides.bookmarks.len()
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum AnnotationKind {
    Rename,
    Comment,
    Type,
}

fn run_annotation(args: &AnnotationArgs, kind: AnnotationKind, json: bool) -> Result<()> {
    let mut project = open(&args.root)?;
    let address = parse_address(&args.address)?;
    let label = match kind {
        AnnotationKind::Rename => {
            project.rename_function(&args.program, address, &args.value)?;
            "renamed function"
        }
        AnnotationKind::Comment => {
            project.set_comment(&args.program, address, &args.value)?;
            "set comment"
        }
        AnnotationKind::Type => {
            project.set_data_type(&args.program, address, &args.value)?;
            "set data type"
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "program": args.program,
                "address": address,
                "action": label,
                "value": args.value,
            }))?
        );
    } else {
        println!(
            "{} at 0x{address:x} in program {}: {}",
            capitalize(label),
            args.program,
            args.value
        );
    }
    Ok(())
}

fn run_bookmark(args: &BookmarkArgs, json: bool) -> Result<()> {
    let mut project = open(&args.root)?;
    let address = parse_address(&args.address)?;
    project.add_bookmark(&args.program, address, &args.label, &args.note)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "program": args.program,
                "address": address,
                "label": args.label,
                "note": args.note,
            }))?
        );
    } else {
        println!(
            "Bookmarked 0x{address:x} in program {} as '{}'",
            args.program, args.label
        );
    }
    Ok(())
}

fn run_session_save(args: &SessionSaveArgs, json: bool) -> Result<()> {
    let project = open(&args.root)?;
    if let Some(program) = &args.program {
        project.program(program)?;
    }
    let mut session = SessionState::new(&args.name);
    session.program_id = args.program.clone();
    session.selected_function = args.function.as_deref().map(parse_address).transpose()?;
    session.cursor_address = args.cursor.as_deref().map(parse_address).transpose()?;
    session.search_query = args.search.clone();
    session.notes = args.notes.clone();
    project.save_session(&session)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&session)?);
    } else {
        println!("Saved session '{}'", session.name);
    }
    Ok(())
}

fn run_session_load(args: &SessionLoadArgs, json: bool) -> Result<()> {
    let project = open(&args.root)?;
    let session = project.load_session(&args.name)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&session)?);
        return Ok(());
    }
    println!("Session: {}", session.name);
    println!(
        "Program: {}",
        session.program_id.as_deref().unwrap_or("(none)")
    );
    match session.selected_function {
        Some(address) => println!("Selected function: 0x{address:x}"),
        None => println!("Selected function: (none)"),
    }
    match session.cursor_address {
        Some(address) => println!("Cursor: 0x{address:x}"),
        None => println!("Cursor: (none)"),
    }
    if let Some(query) = &session.search_query {
        println!("Search: {query}");
    }
    if !session.notes.is_empty() {
        println!("Notes: {}", session.notes);
    }
    Ok(())
}

fn run_session_list(args: &ProjectRootArgs, json: bool) -> Result<()> {
    let project = open(&args.root)?;
    let sessions = project.list_sessions()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }
    if sessions.is_empty() {
        println!("No saved sessions.");
        return Ok(());
    }
    println!("Sessions:");
    for name in sessions {
        println!("  {name}");
    }
    Ok(())
}

fn run_verify(args: &ProjectRootArgs, json: bool) -> Result<()> {
    let project = open(&args.root)?;
    let report = project.verify();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Verification: {}", if report.ok { "OK" } else { "FAILED" });
        for program in &report.programs {
            println!(
                "  {:<18} {:<28} binary: {:<8} analysis: {:<8}",
                program.id,
                truncate(&program.name, 28),
                if program.binary_ok { "ok" } else { "failed" },
                if program.analysis_ok { "ok" } else { "failed" }
            );
            if let Some(problem) = &program.problem {
                println!("      {problem}");
            }
        }
    }
    if !report.ok {
        bail!("project verification failed");
    }
    Ok(())
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    let mut output: String = value.chars().take(width.saturating_sub(1)).collect();
    output.push('…');
    output
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
