//! The `ghirust` command line application.
//!
//! The CLI is intentionally small and friendly:
//!
//! * `ghirust start` guides a first-time user;
//! * `ghirust search` uses the persistent index and memory-mapped text;
//! * `ghirust export` streams decompiled functions to disk;
//! * `ghirust doctor` explains what is missing in plain language.

mod commands;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use commands::export::ExportArgs;
use commands::search::SearchArgs;

#[derive(Debug, Parser)]
#[command(
    name = "ghirust",
    version,
    about = "Fast, understandable, bounded-memory reverse engineering tooling",
    long_about = "GHIRUST is a Rust-first reverse engineering platform. This binary is the \
                  first working slice: persistent search over exported decompilation and \
                  streaming export of very large function sets.",
    arg_required_else_help = true
)]
struct Cli {
    /// Print extra diagnostics to stderr.
    #[arg(long, global = true)]
    verbose: bool,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Guided setup for first-time users.
    Start,

    /// Identify the format, architecture and language of a binary.
    Inspect(commands::inspect::InspectArgs),

    /// Extract printable ASCII and UTF-16 strings from a binary.
    Strings(commands::strings::StringsArgs),

    /// Validate and inspect a serialized GUIR module.
    Ir(commands::ir::IrArgs),

    /// Search exported decompilation by text, function name or file path.
    Search(SearchArgs),

    /// Build or refresh the persistent search index.
    Index(IndexArgs),

    /// Stream decompiled functions into one file with bounded memory.
    Export(ExportArgs),

    /// Check the local setup and explain how to fix problems.
    Doctor(DoctorArgs),

    /// Explain reverse-engineering terms in plain language.
    Explain(ExplainArgs),
}

#[derive(Debug, Args)]
struct IndexArgs {
    /// Directory containing exported decompilation.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// Index file location (default: <root>/.ghirust/index.json).
    #[arg(long)]
    index: Option<PathBuf>,

    /// Rebuild even when the existing index looks fresh.
    #[arg(long)]
    force: bool,

    /// Include hidden files and directories.
    #[arg(long)]
    include_hidden: bool,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Project directory to inspect.
    #[arg(long, default_value = ".")]
    root: PathBuf,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Term to explain. Omit to list all topics.
    topic: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                let payload = serde_json::json!({ "error": error.to_string() });
                eprintln!("{payload}");
            } else {
                eprintln!("error: {error}");
                for cause in error.chain().skip(1) {
                    eprintln!("  caused by: {cause}");
                }
                eprintln!("hint: run `ghirust doctor` for a setup check, or `ghirust start` for guided help.");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let json = cli.json;
    let verbose = cli.verbose;

    match cli.command {
        Command::Start => commands::start::run(verbose)?,
        Command::Inspect(args) => commands::inspect::run(&args, json)?,
        Command::Strings(args) => commands::strings::run(&args, json)?,
        Command::Ir(args) => commands::ir::run(&args, json)?,
        Command::Search(args) => commands::search::run(&args, json, verbose)?,
        Command::Index(args) => {
            commands::index::run(&args.root, args.index, args.force, args.include_hidden, json)?
        }
        Command::Export(args) => commands::export::run(&args, json, verbose)?,
        Command::Doctor(args) => commands::doctor::run(&args.root, json)?,
        Command::Explain(args) => commands::explain::run(args.topic.as_deref(), json)?,
    }
    Ok(())
}
