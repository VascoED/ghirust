//! `ghirust ir validate`

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use ghirust_core::ir::{Module, Severity};

/// Arguments for `ghirust ir`.
#[derive(Debug, Args)]
pub struct IrArgs {
    #[command(subcommand)]
    command: IrCommand,
}

#[derive(Debug, Subcommand)]
enum IrCommand {
    /// Validate a serialized GUIR module.
    Validate {
        /// JSON module produced by a GHIRUST frontend.
        file: PathBuf,
    },
}

/// Execute the IR command.
pub fn run(args: &IrArgs, json: bool) -> Result<()> {
    match &args.command {
        IrCommand::Validate { file } => validate(file, json),
    }
}

fn validate(file: &std::path::Path, json: bool) -> Result<()> {
    let text = fs::read_to_string(file)
        .with_context(|| format!("could not read GUIR module {}", file.display()))?;
    let module = Module::from_json(&text)
        .with_context(|| format!("could not parse GUIR module {}", file.display()))?;
    let issues = module.validate();
    let errors = issues
        .iter()
        .filter(|issue| issue.severity == Severity::Error)
        .count();

    if json {
        let payload = serde_json::json!({
            "file": file,
            "module": module.name,
            "functions": module.functions.len(),
            "issues": issues,
            "valid": errors == 0,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("Module: {} (GUIR v{})", module.name, module.format_version);
        println!("Functions: {}\n", module.functions.len());
        if issues.is_empty() {
            println!("No structural issues found.");
        } else {
            for issue in &issues {
                println!(
                    "{:<7} {:<28} {}",
                    format!("{:?}", issue.severity).to_ascii_lowercase(),
                    issue.code,
                    issue.message
                );
            }
        }
    }

    if errors > 0 {
        anyhow::bail!("GUIR validation failed with {errors} error(s)");
    }
    Ok(())
}
