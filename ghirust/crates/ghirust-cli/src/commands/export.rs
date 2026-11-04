//! `ghirust export`

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use ghirust_core::export::{Compression, ExportOptions, export_input};

use crate::ui;

/// Arguments for `ghirust export`.
#[derive(Debug, Args, Clone)]
pub struct ExportArgs {
    /// NDJSON file or directory of function files.
    pub input: PathBuf,

    /// Final output file.
    #[arg(short, long)]
    pub output: PathBuf,

    /// Gzip-compress the output.
    #[arg(long)]
    pub gzip: bool,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,

    /// Continue an interrupted plain-text export.
    #[arg(long)]
    pub resume: bool,

    /// Do not write the streaming function manifest.
    #[arg(long)]
    pub no_manifest: bool,

    /// Checkpoint interval in MiB of uncompressed output.
    #[arg(long, default_value_t = 8)]
    pub checkpoint_mb: u64,
}

/// Execute the export command.
pub fn run(args: &ExportArgs, json: bool, verbose: bool) -> Result<()> {
    if args.gzip && args.resume {
        anyhow::bail!(
            "--resume is not supported with --gzip; resume a plain export and compress it afterwards"
        );
    }
    if !args.input.exists() {
        anyhow::bail!(
            "input does not exist: {}\nRun `ghirust start` for guided help, or pass a folder produced by the Ghidra bridge.",
            args.input.display()
        );
    }

    if args.gzip
        && args
            .output
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case("gz"))
            != Some(true)
    {
        eprintln!(
            "note: writing gzip data to {} (consider a .gz extension)",
            args.output.display()
        );
    }

    let options = ExportOptions {
        output: args.output.clone(),
        compression: if args.gzip {
            Compression::Gzip
        } else {
            Compression::None
        },
        force: args.force,
        resume: args.resume,
        checkpoint_bytes: args.checkpoint_mb.max(1) * 1024 * 1024,
        write_manifest: !args.no_manifest,
    };

    let report = export_input(&args.input, &options)
        .with_context(|| format!("could not export {}", args.input.display()))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!(
        "Exported {} function(s) in {}.",
        report.records,
        ui::duration_ms(report.elapsed_ms)
    );
    println!(
        "Output: {} · {} text · {} on disk",
        report.output.display(),
        ui::bytes(report.uncompressed_bytes),
        ui::bytes(report.written_bytes)
    );
    if report.resumed_from > 0 {
        println!(
            "Resumed from {} already-exported function(s).",
            report.resumed_from
        );
    }
    if !args.no_manifest {
        println!("Manifest: {}", manifest_path(&args.output).display());
    }
    if verbose {
        let ratio = if report.uncompressed_bytes == 0 {
            0.0
        } else {
            report.written_bytes as f64 / report.uncompressed_bytes as f64 * 100.0
        };
        eprintln!("on-disk ratio: {ratio:.1}% of the text size");
    }
    Ok(())
}

fn manifest_path(output: &Path) -> PathBuf {
    let mut value = output.as_os_str().to_os_string();
    value.push(".manifest.ndjson");
    PathBuf::from(value)
}
