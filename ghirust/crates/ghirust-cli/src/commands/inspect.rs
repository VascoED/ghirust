//! `ghirust inspect`

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use ghirust_core::detect::detect_file;

use crate::ui;

/// Arguments for `ghirust inspect`.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Binary file to inspect.
    pub file: PathBuf,
}

/// Detect format, architecture, sections and likely language.
pub fn run(args: &InspectArgs, json: bool) -> Result<()> {
    let report = detect_file(&args.file)
        .with_context(|| format!("could not inspect {}", args.file.display()))?;

    if json {
        let payload = serde_json::json!({
            "path": args.file,
            "detection": report,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("File: {}", args.file.display());
    println!(
        "Format: {} · {} · {}{}",
        report.format,
        report
            .bits
            .map(|bits| format!("{bits}-bit"))
            .unwrap_or_else(|| "unknown width".to_owned()),
        report
            .endian
            .map(|endian| format!("{endian:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unknown endian".to_owned()),
        report
            .architecture
            .as_deref()
            .map(|architecture| format!(" · {architecture}"))
            .unwrap_or_default()
    );
    if let Some(kind) = &report.kind {
        println!("Kind: {kind}");
    }
    if let Some(os) = &report.os {
        println!("Target OS: {os}");
    }
    if let Some(entry) = report.entry_point {
        println!("Entry point: 0x{entry:x}");
    }
    if let Some(base) = report.image_base {
        println!("Image base: 0x{base:x}");
    }
    match (&report.language, report.language_confidence) {
        (Some(language), confidence) if confidence > 0.0 => {
            println!("Likely language: {language} (confidence {:.0}%)", confidence * 100.0);
        }
        _ => println!("Likely language: not identified"),
    }
    if let Some(compiler) = &report.compiler {
        println!("Compiler/runtime hint: {compiler}");
    }
    println!("Size: {}", ui::bytes(report.file_size));

    if !report.sections.is_empty() {
        println!("\nSections:");
        for section in report.sections.iter().take(64) {
            println!(
                "  {:<18} {:<6} address=0x{:<10x} size={}",
                section.name,
                section.kind,
                section.address,
                ui::bytes(section.size)
            );
        }
        if report.sections.len() > 64 {
            println!("  … {} more section(s)", report.sections.len() - 64);
        }
    }

    if !report.evidence.is_empty() {
        println!("\nEvidence:");
        for evidence in &report.evidence {
            println!("  - {evidence}");
        }
    }
    if !report.warnings.is_empty() {
        println!("\nWarnings:");
        for warning in &report.warnings {
            println!("  - {warning}");
        }
    }
    Ok(())
}
