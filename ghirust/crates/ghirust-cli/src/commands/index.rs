//! `ghirust index`

use std::path::{Path, PathBuf};

use anyhow::Result;

use ghirust_core::index::{IndexOptions, build_index};

use crate::ui;

/// Build the search index.
pub fn run(
    root: &Path,
    index: Option<PathBuf>,
    force: bool,
    include_hidden: bool,
    json: bool,
) -> Result<()> {
    let index_path = index.unwrap_or_else(|| root.join(".ghirust").join("index.json"));

    if index_path.exists() && !force {
        let existing = ghirust_core::load_index(&index_path);
        if let Ok(index) = existing {
            if !index.is_stale() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "fresh",
                            "index": index_path,
                            "files": index.files.len(),
                            "functions": index.functions.len(),
                        }))?
                    );
                } else {
                    println!(
                        "Index is already fresh: {} file(s), {} function(s).",
                        index.files.len(),
                        index.functions.len()
                    );
                    println!("Use `ghirust index --force` to rebuild it anyway.");
                }
                return Ok(());
            }
        }
    }

    let options = IndexOptions {
        root: root.to_path_buf(),
        index_path: index_path.clone(),
        include_hidden,
    };
    let report = build_index(&options)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Indexed {} file(s) and {} function(s) in {}.",
            report.files,
            report.functions,
            ui::duration_ms(report.elapsed_ms)
        );
        println!(
            "Scanned {} · index written to {}",
            ui::bytes(report.bytes_scanned),
            report.index_path.display()
        );
        if report.cache_hits > 0 || report.cache_misses > 0 {
            println!(
                "Scan cache: {} hit(s), {} miss(es).",
                report.cache_hits, report.cache_misses
            );
        }
    }
    Ok(())
}
