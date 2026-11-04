//! `ghirust doctor`

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use serde::Serialize;

use ghirust_core::load_index;

use crate::ui;

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    required: bool,
    detail: String,
    fix: String,
}

/// Run environment checks.
pub fn run(root: &Path, json: bool) -> Result<()> {
    let mut checks = Vec::new();

    let root_ok = root.is_dir();
    checks.push(Check {
        name: "project folder",
        ok: root_ok,
        required: true,
        detail: root.display().to_string(),
        fix: "Pass an existing folder with --root, or run the command from your project folder."
            .to_owned(),
    });

    let index_path = root.join(".ghirust").join("index.json");
    let (index_ok, index_detail, index_fix) = inspect_index(&index_path);
    checks.push(Check {
        name: "search index",
        ok: index_ok,
        required: false,
        detail: index_detail,
        fix: index_fix,
    });

    let writable = can_write(root);
    checks.push(Check {
        name: "write access",
        ok: writable,
        required: true,
        detail: if writable {
            format!("can write to {}", root.display())
        } else {
            format!("cannot write to {}", root.display())
        },
        fix: "Run GHIRUST from a folder you own, or fix the folder permissions.".to_owned(),
    });

    let (ghidra_ok, ghidra_detail) = inspect_ghidra();
    checks.push(Check {
        name: "Ghidra bridge",
        ok: ghidra_ok,
        required: false,
        detail: ghidra_detail,
        fix: "Optional. Set GHIDRA_HOME to your Ghidra installation; see integrations/ghidra/README.md."
            .to_owned(),
    });

    let java_ok = Command::new("java")
        .arg("-version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    checks.push(Check {
        name: "Java runtime",
        ok: java_ok,
        required: false,
        detail: if java_ok {
            "java is available on PATH".to_owned()
        } else {
            "java was not found on PATH".to_owned()
        },
        fix: "Install JDK 25 if you want to run Ghidra headless; search and export do not need it."
            .to_owned(),
    });

    if json {
        let payload = serde_json::json!({
            "root": root,
            "checks": checks,
            "ready": checks.iter().filter(|check| check.required).all(|check| check.ok),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("GHIRUST doctor");
    println!("Project: {}\n", root.display());
    for check in &checks {
        let label = if check.required {
            check.name.to_owned()
        } else {
            format!("{} (optional)", check.name)
        };
        println!("{}", ui::check(check.ok, &label, &check.detail));
        if !check.ok {
            println!("      fix: {}", check.fix);
        }
    }

    let required_ok = checks.iter().filter(|check| check.required).all(|check| check.ok);
    println!();
    if required_ok {
        println!("Search and export are ready to use.");
        if !checks.iter().find(|check| check.name == "search index").map(|check| check.ok).unwrap_or(false) {
            println!("Next: `ghirust index` to make the first search fast.");
        }
    } else {
        println!("Fix the required items above, then run `ghirust doctor` again.");
    }
    Ok(())
}

fn inspect_index(path: &Path) -> (bool, String, String) {
    if !path.exists() {
        return (
            false,
            format!("not built yet ({})", path.display()),
            "Run `ghirust index` from the folder that contains your exported code.".to_owned(),
        );
    }
    match load_index(path) {
        Ok(index) => {
            if index.is_stale() {
                (
                    false,
                    format!(
                        "stale: {} file(s), {} function(s)",
                        index.files.len(),
                        index.functions.len()
                    ),
                    "Run `ghirust index --force` to refresh it.".to_owned(),
                )
            } else {
                (
                    true,
                    format!(
                        "fresh: {} file(s), {} function(s)",
                        index.files.len(),
                        index.functions.len()
                    ),
                    String::new(),
                )
            }
        }
        Err(error) => (
            false,
            format!("unreadable: {error}"),
            "Delete the index and run `ghirust index` again.".to_owned(),
        ),
    }
}

fn can_write(root: &Path) -> bool {
    let directory = root.join(".ghirust");
    if fs::create_dir_all(&directory).is_err() {
        return false;
    }
    let probe = directory.join(".doctor-write-test");
    if fs::write(&probe, b"ok").is_err() {
        return false;
    }
    let _ = fs::remove_file(probe);
    true
}

fn inspect_ghidra() -> (bool, String) {
    if let Some(home) = env::var_os("GHIDRA_HOME") {
        let home = PathBuf::from(home);
        let headless = home.join("support").join(if cfg!(windows) {
            "analyzeHeadless.bat"
        } else {
            "analyzeHeadless"
        });
        if headless.is_file() {
            return (true, format!("found at {}", headless.display()));
        }
        return (
            false,
            format!("GHIDRA_HOME is set to {}, but support/analyzeHeadless was not found", home.display()),
        );
    }

    for candidate in ["ghidraRun", "ghidraRun.bat", "analyzeHeadless", "analyzeHeadless.bat"] {
        if which(candidate).is_some() {
            return (true, format!("{candidate} is available on PATH"));
        }
    }
    (false, "not found; set GHIDRA_HOME to your installation".to_owned())
}

fn which(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
