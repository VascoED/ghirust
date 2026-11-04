//! `ghirust strings`

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use ghirust_core::strings::{StringOptions, extract_strings};

/// Arguments for `ghirust strings`.
#[derive(Debug, Args)]
pub struct StringsArgs {
    /// Binary file to scan.
    pub file: PathBuf,

    /// Minimum number of characters.
    #[arg(long, default_value_t = 4)]
    pub min_length: usize,

    /// Skip UTF-16LE strings.
    #[arg(long)]
    pub no_utf16: bool,

    /// Drop repeated values.
    #[arg(long)]
    pub deduplicate: bool,

    /// Maximum number of strings returned.
    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,
}

/// Extract strings from a binary.
pub fn run(args: &StringsArgs, json: bool) -> Result<()> {
    let records = extract_strings(
        &args.file,
        &StringOptions {
            min_length: args.min_length.max(1),
            utf16: !args.no_utf16,
            deduplicate: args.deduplicate,
            limit: args.limit.max(1),
        },
    )
    .with_context(|| format!("could not extract strings from {}", args.file.display()))?;

    if json {
        let payload = serde_json::json!({
            "path": args.file,
            "count": records.len(),
            "strings": records,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    if records.is_empty() {
        println!(
            "No strings of at least {} character(s) found.",
            args.min_length
        );
        return Ok(());
    }

    for record in &records {
        println!(
            "0x{:08x}  {:<8}  {}",
            record.offset,
            record.encoding.as_str(),
            record.value
        );
    }
    println!("\n{} string(s).", records.len());
    Ok(())
}
