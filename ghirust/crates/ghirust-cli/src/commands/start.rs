//! `ghirust start` — the beginner path.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::Result;

use crate::commands::{doctor, explain, export, search};

/// Run the guided first-use experience.
pub fn run(verbose: bool) -> Result<()> {
    banner();

    if !io::stdin().is_terminal() {
        println!("This wizard needs an interactive terminal.");
        println!("Useful non-interactive commands:");
        println!("  ghirust index --root <folder>");
        println!("  ghirust search <query> --root <folder>");
        println!("  ghirust export <folder-or-ndjson> --output decompiled.c");
        println!("  ghirust doctor");
        return Ok(());
    }

    loop {
        println!("\nWhat do you want to do?");
        println!("  1  Find code or a function");
        println!("  2  Turn a folder of decompiled functions into one file");
        println!("  3  Check my setup");
        println!("  4  Learn a term (function, decompiler, CFG, ...)");
        println!("  5  Quit");
        let choice = ask("Choose", "1")?;

        match choice.as_str() {
            "1" => guided_search(verbose)?,
            "2" => guided_export(verbose)?,
            "3" => doctor::run(std::path::Path::new("."), false)?,
            "4" => guided_glossary()?,
            "5" | "q" | "quit" => break,
            other => println!("'{other}' is not one of the options. Try 1 to 5."),
        }

        if !ask_yes_no("Return to the menu?", true)? {
            break;
        }
    }

    println!("\nDone. Run `ghirust --help` for every command, or `ghirust doctor` if something looks wrong.");
    Ok(())
}

fn banner() {
    println!("GHIRUST 0.1 — first working slice");
    println!("Fast search · friendly setup · bounded-memory export");
    println!();
    println!("This wizard avoids jargon. You can press Enter to accept the value in [brackets].");
}

fn guided_search(verbose: bool) -> Result<()> {
    println!("\nSearch reads decompiled C-like text that was already exported.");
    let root = ask("Folder containing the exported code", ".")?;
    let query = ask("Text or function name to find", "main")?;
    let function_only = ask_yes_no("Is this a function name?", false)?;

    let args = search::SearchArgs {
        query,
        root: PathBuf::from(root),
        index: None,
        mode: if function_only {
            "name".to_owned()
        } else {
            "text".to_owned()
        },
        ignore_case: true,
        limit: 20,
        rebuild: false,
        snippet_chars: Some(200),
    };
    println!("\nPreparing the index (a one-time cost for this folder)...");
    search::run(&args, false, verbose)?;
    println!("\nNext: use `ghirust search name:<part-of-name>` to narrow by symbol, or `ghirust search --help`.");
    Ok(())
}

fn guided_export(verbose: bool) -> Result<()> {
    println!("\nThis combines many small function files into one output without loading everything into RAM.");
    let input = ask(
        "Folder of function files (or an NDJSON file)",
        "ghidra-export",
    )?;
    if !PathBuf::from(&input).exists() {
        println!("\nThat path does not exist yet. If you are starting from a binary, export it first with the Ghidra bridge:");
        println!("  integrations/ghidra/run-export.ps1 <binary> <output-folder>");
        println!("Then run this option again.");
        return Ok(());
    }
    let output = ask("Output file", "decompiled.c")?;
    let gzip = ask_yes_no("Compress the result with gzip?", false)?;

    let args = export::ExportArgs {
        input: PathBuf::from(input),
        output: PathBuf::from(output),
        gzip,
        force: false,
        resume: false,
        no_manifest: false,
        checkpoint_mb: 8,
    };
    export::run(&args, false, verbose)?;
    println!("\nNext: `ghirust index --root .` and then `ghirust search <text>` over the result.");
    Ok(())
}

fn guided_glossary() -> Result<()> {
    explain::run(None, false)?;
    println!();
    let topic = ask("Topic", "decompiler")?;
    explain::run(Some(&topic), false)?;
    Ok(())
}

fn ask(prompt: &str, default: &str) -> Result<String> {
    print!("{prompt} [{default}]: ");
    io::stdout().flush()?;
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Ok(default.to_owned());
    }
    let value = line.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

fn ask_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        print!("{prompt} [{hint}]: ");
        io::stdout().flush()?;
        let mut line = String::new();
        let read = io::stdin().read_line(&mut line)?;
        if read == 0 {
            return Ok(default);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}
