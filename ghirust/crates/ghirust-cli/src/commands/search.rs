//! `ghirust search`

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use ghirust_core::index::ensure_index;
use ghirust_core::search::{SearchMode, SearchOptions, search};

use crate::ui;

/// Arguments for `ghirust search`.
#[derive(Debug, Args, Clone)]
pub struct SearchArgs {
    /// Text, function name, or path to find.
    pub query: String,

    /// Directory containing exported decompilation.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Index file location (default: <root>/.ghirust/index.json).
    #[arg(long)]
    pub index: Option<PathBuf>,

    /// Interpretation: auto, text, name, or file.
    #[arg(long, default_value = "auto")]
    pub mode: String,

    /// Ignore case when matching.
    #[arg(long)]
    pub ignore_case: bool,

    /// Maximum number of results.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    /// Rebuild the index before searching.
    #[arg(long)]
    pub rebuild: bool,

    /// Maximum characters shown per result snippet.
    #[arg(long)]
    pub snippet_chars: Option<usize>,
}

/// Execute the search command.
pub fn run(args: &SearchArgs, json: bool, verbose: bool) -> Result<()> {
    let index_path = args
        .index
        .clone()
        .unwrap_or_else(|| args.root.join(".ghirust").join("index.json"));
    let mode = SearchMode::parse(&args.mode).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown mode '{}'; use auto, text, name, or file",
            args.mode
        )
    })?;

    let (index, rebuilt) = ensure_index(&args.root, &index_path, args.rebuild)
        .with_context(|| format!("could not prepare the index for {}", args.root.display()))?;

    if verbose || rebuilt {
        eprintln!(
            "index: {} file(s), {} function(s){}",
            index.files.len(),
            index.functions.len(),
            if rebuilt { " (rebuilt)" } else { "" }
        );
    }

    let options = SearchOptions {
        query: args.query.clone(),
        mode,
        ignore_case: args.ignore_case,
        limit: args.limit,
        snippet_chars: args.snippet_chars.unwrap_or(240),
    };
    let report = search(&index, &options)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.hits.is_empty() {
        println!(
            "No matches for '{}' ({}).",
            report.query,
            mode_name(report.mode)
        );
        println!(
            "Try `ghirust search --mode name {}` or a shorter query.",
            report.query
        );
        return Ok(());
    }

    for hit in &report.hits {
        let symbol = match (&hit.function, &hit.address) {
            (Some(function), Some(address)) => format!("{function} @ {address}"),
            (Some(function), None) => function.clone(),
            (None, _) => String::from("(no enclosing function)"),
        };
        println!("{}:{}:{}  {}", hit.file, hit.line, hit.column, symbol);
        if !hit.text.is_empty() {
            println!("    {}", hit.text);
        }
    }

    let suffix = if report.truncated {
        " · more results available"
    } else {
        ""
    };
    println!(
        "\n{} hit(s) in {} · scanned {}{}",
        report.hits.len(),
        ui::duration_ms(report.elapsed_ms),
        ui::bytes(report.scanned_bytes),
        suffix
    );
    Ok(())
}

fn mode_name(mode: SearchMode) -> &'static str {
    match mode {
        SearchMode::Auto => "auto",
        SearchMode::Name => "function name",
        SearchMode::Text => "text",
        SearchMode::File => "file path",
    }
}
