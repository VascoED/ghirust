//! `ghirust analyze`, `functions`, `disasm`, `decompile` and `xrefs`.
//!
//! All commands run the same loader, x86/x86-64 decoder, function discovery,
//! CFG recovery and pseudocode reconstruction used by the GUI. A single analysis
//! can be persisted with `analyze --save` and reused by the other commands with
//! `--analysis`.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

use ghirust_core::analysis::{
    AnalysisOptions, FunctionAnalysis, ProgramAnalysis, analyze_path, analyze_path_managed,
};
use ghirust_core::resources::{ResourceBudget, ResourceManager, ResourceProfile};

/// Resource profile applied to analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    /// Maximum system protection: few workers, small memory budget.
    Conservative,
    /// Balance between speed and stability (default).
    Balanced,
    /// Higher limits, still bounded.
    Performance,
}

/// Shared analysis controls.
#[derive(Debug, Clone, Args)]
pub struct CommonAnalysisArgs {
    /// Reuse a saved analysis JSON instead of analyzing the binary again.
    #[arg(long)]
    pub analysis: Option<PathBuf>,

    /// Maximum number of functions retained.
    #[arg(long, default_value_t = 100_000)]
    pub max_functions: usize,

    /// Skip pseudocode reconstruction.
    #[arg(long)]
    pub no_decompile: bool,

    /// Resource profile for the analysis.
    #[arg(long, value_enum)]
    pub profile: Option<ProfileArg>,

    /// Maximum worker threads for parallel work.
    #[arg(long)]
    pub max_threads: Option<usize>,

    /// Maximum process RAM the engine may commit, in megabytes.
    #[arg(long)]
    pub max_ram_mb: Option<usize>,
}

impl CommonAnalysisArgs {
    fn options(&self) -> AnalysisOptions {
        AnalysisOptions {
            max_functions: self.max_functions,
            decompile: !self.no_decompile,
            ..AnalysisOptions::default()
        }
    }

    /// Build a resource manager from the requested profile/limits. `None`
    /// when no resource arguments were given (plain analysis).
    pub fn resource_manager(&self) -> Option<ResourceManager> {
        let mut budget = match self.profile {
            Some(ProfileArg::Conservative) => ResourceBudget::conservative(),
            Some(ProfileArg::Balanced) => ResourceBudget::balanced(),
            Some(ProfileArg::Performance) => ResourceBudget::performance(),
            None if self.max_threads.is_some() || self.max_ram_mb.is_some() => {
                ResourceBudget::balanced()
            }
            None => return None,
        };
        if let Some(threads) = self.max_threads {
            budget.max_worker_threads = threads.clamp(1, 64);
        }
        if let Some(megabytes) = self.max_ram_mb {
            budget.max_process_ram_bytes = (megabytes * 1024 * 1024).max(64 * 1024 * 1024);
        }
        Some(ResourceManager::new(ResourceProfile::Custom(budget)))
    }

    /// Run the analysis under the resource manager when one is configured.
    pub fn analyze(&self, file: &std::path::Path) -> anyhow::Result<ProgramAnalysis> {
        let options = self.options();
        match self.resource_manager() {
            Some(manager) => analyze_path_managed(file, &options, &manager).map_err(Into::into),
            None => analyze_path(file, &options).map_err(Into::into),
        }
    }
}

/// Arguments for `ghirust analyze`.
#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    /// Binary file to analyze (not required with --analysis).
    pub file: Option<PathBuf>,

    /// Write the complete analysis as JSON.
    #[arg(long)]
    pub save: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonAnalysisArgs,
}

/// Arguments for `ghirust functions`.
#[derive(Debug, Args)]
pub struct FunctionsArgs {
    /// Binary file to analyze (not required with --analysis).
    pub file: Option<PathBuf>,

    /// Maximum functions printed.
    #[arg(long, default_value_t = 200)]
    pub limit: usize,

    #[command(flatten)]
    pub common: CommonAnalysisArgs,
}

/// Arguments for `ghirust disasm`.
#[derive(Debug, Args)]
pub struct DisasmArgs {
    /// Binary file to analyze (not required with --analysis).
    pub file: Option<PathBuf>,

    /// Function name or address (0x... or decimal).
    #[arg(long)]
    pub function: Option<String>,

    /// Maximum instructions printed.
    #[arg(long, default_value_t = 5_000)]
    pub limit: usize,

    #[command(flatten)]
    pub common: CommonAnalysisArgs,
}

/// Arguments for `ghirust decompile`.
#[derive(Debug, Args)]
pub struct DecompileArgs {
    /// Binary file to analyze (not required with --analysis).
    pub file: Option<PathBuf>,

    /// Function name or address (0x... or decimal).
    #[arg(long)]
    pub function: Option<String>,

    /// Maximum functions decompiled.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    /// Write pseudocode to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonAnalysisArgs,
}

/// Arguments for `ghirust xrefs`.
#[derive(Debug, Args)]
pub struct XrefsArgs {
    /// Binary file to analyze (not required with --analysis).
    pub file: Option<PathBuf>,

    /// Only show references to this address or symbol name.
    #[arg(long)]
    pub to: Option<String>,

    /// Maximum references printed.
    #[arg(long, default_value_t = 200)]
    pub limit: usize,

    #[command(flatten)]
    pub common: CommonAnalysisArgs,
}

fn obtain(file: Option<&Path>, common: &CommonAnalysisArgs) -> Result<ProgramAnalysis> {
    if let Some(path) = &common.analysis {
        let reader = BufReader::new(
            File::open(path)
                .with_context(|| format!("could not open saved analysis {}", path.display()))?,
        );
        let analysis: ProgramAnalysis = serde_json::from_reader(reader)
            .with_context(|| format!("could not parse saved analysis {}", path.display()))?;
        // When the binary is also supplied, never trust a saved analysis that
        // belongs to different bytes. That would silently answer questions
        // about the wrong program.
        if let Some(file) = file {
            let hash = ghirust_core::cache::hash_file(file)
                .with_context(|| format!("could not hash {}", file.display()))?;
            if analysis.sha256 != hash {
                bail!(
                    "saved analysis {} belongs to SHA-256 {}, but {} has {}; re-run analysis",
                    path.display(),
                    analysis.sha256,
                    file.display(),
                    hash
                );
            }
        }
        return Ok(analysis);
    }
    let Some(file) = file else {
        bail!("provide a binary path or --analysis <file>");
    };
    common
        .analyze(file)
        .with_context(|| format!("could not analyze {}", file.display()))
}

pub fn run_analyze(args: &AnalyzeArgs, json: bool) -> Result<()> {
    let analysis = obtain(args.file.as_deref(), &args.common)?;
    if let Some(path) = &args.save {
        write_json(path, &analysis)?;
        if !json {
            println!("Saved analysis: {}", path.display());
        }
    }
    if json {
        let summary = serde_json::json!({
            "path": analysis.path,
            "sha256": analysis.sha256,
            "generated_by": analysis.generated_by,
            "format_version": analysis.format_version,
            "loader": analysis.loader,
            "stats": analysis.stats,
            "warnings": analysis.warnings,
            "functions": analysis.functions.iter().take(50).map(function_summary).collect::<Vec<_>>(),
            "saved": args.save,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let loader = &analysis.loader;
    println!("File: {}", analysis.path);
    println!("SHA-256: {}", analysis.sha256);
    println!(
        "Format: {} · {} · {}-bit · {}",
        loader.format, loader.architecture, loader.bits, loader.endian
    );
    println!(
        "Kind: {} · OS: {} · image base 0x{:x} · entry 0x{:x}",
        loader.object_kind,
        loader.os.as_deref().unwrap_or("unknown"),
        loader.image_base,
        loader.entry
    );
    println!(
        "Functions: {} · instructions: {} · blocks: {} · xrefs: {}",
        analysis.stats.functions,
        analysis.stats.instructions,
        analysis.stats.blocks,
        analysis.stats.xrefs
    );
    println!(
        "Seeds: {} · linear sweep: {} instructions · overlap skips: {} · elapsed: {} ms",
        analysis.stats.seeds,
        analysis.stats.linear_scan_instructions,
        analysis.stats.overlapping_functions_skipped,
        analysis.stats.elapsed_ms
    );
    println!(
        "Executable bytes: {} · sections: {} · imports: {} · exports: {} · strings: {}",
        loader.executable_bytes,
        analysis.sections.len(),
        analysis.imports.len(),
        analysis.exports.len(),
        analysis.strings.len()
    );
    if !analysis.functions.is_empty() {
        println!("\nTop functions:");
        for function in analysis.functions.iter().take(25) {
            println!(
                "  0x{:08x}  {:<28} {:<9} confidence {:.0}%  {} insn  {} blocks",
                function.address,
                truncate(&function.name, 28),
                function.discovery,
                function.confidence * 100.0,
                function.instruction_count,
                function.blocks.len()
            );
        }
        if analysis.functions.len() > 25 {
            println!("  … {} more function(s)", analysis.functions.len() - 25);
        }
    }
    if !analysis.warnings.is_empty() {
        println!("\nWarnings ({}):", analysis.warnings.len());
        for warning in analysis.warnings.iter().take(15) {
            println!("  - {warning}");
        }
        if analysis.warnings.len() > 15 {
            println!("  … {} more warning(s)", analysis.warnings.len() - 15);
        }
    }
    if let Some(path) = &args.save {
        println!("\nSaved analysis: {}", path.display());
    }
    Ok(())
}

pub fn run_functions(args: &FunctionsArgs, json: bool) -> Result<()> {
    let analysis = obtain(args.file.as_deref(), &args.common)?;
    if json {
        let functions: Vec<_> = analysis
            .functions
            .iter()
            .take(args.limit)
            .map(function_summary)
            .collect();
        println!("{}", serde_json::to_string_pretty(&functions)?);
        return Ok(());
    }
    println!(
        "{:<12} {:<32} {:<10} {:<6} {:<10} {:<8}",
        "Address", "Name", "Discovery", "Conf", "Size", "Insns"
    );
    for function in analysis.functions.iter().take(args.limit) {
        println!(
            "0x{:08x}  {:<32} {:<10} {:>4.0}%  {:<10} {}",
            function.address,
            truncate(&function.name, 32),
            function.discovery,
            function.confidence * 100.0,
            function.size,
            function.instruction_count
        );
    }
    if analysis.functions.len() > args.limit {
        println!(
            "… {} more function(s); raise --limit to see them",
            analysis.functions.len() - args.limit
        );
    }
    Ok(())
}

pub fn run_disasm(args: &DisasmArgs, json: bool) -> Result<()> {
    let analysis = obtain(args.file.as_deref(), &args.common)?;
    let selected = select_functions(&analysis, args.function.as_deref())?;
    if json {
        let payload: Vec<_> = selected
            .iter()
            .map(|function| {
                serde_json::json!({
                    "address": function.address,
                    "name": function.name,
                    "discovery": function.discovery,
                    "confidence": function.confidence,
                    "blocks": function.blocks,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let mut printed = 0usize;
    for function in selected {
        if printed >= args.limit {
            break;
        }
        println!(
            "\n; {} @ 0x{:x} · {} · confidence {:.0}%",
            function.name,
            function.address,
            function.discovery,
            function.confidence * 100.0
        );
        for block in &function.blocks {
            println!("; block {} @ 0x{:x}", block.id, block.start);
            for instruction in &block.instructions {
                if printed >= args.limit {
                    println!("; instruction limit reached");
                    break;
                }
                let prefix = if instruction.unsupported { "!" } else { " " };
                println!(
                    "  0x{:08x}  {:<24} {}{}",
                    instruction.address, instruction.bytes, prefix, instruction.text
                );
                printed += 1;
            }
            println!(
                "; -> {}",
                block
                    .successors
                    .iter()
                    .map(|target| format!("0x{target:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

pub fn run_decompile(args: &DecompileArgs, json: bool) -> Result<()> {
    let analysis = obtain(args.file.as_deref(), &args.common)?;
    let selected = select_functions(&analysis, args.function.as_deref())?;
    if json {
        let payload: Vec<_> = selected
            .iter()
            .take(args.limit)
            .map(|function| {
                serde_json::json!({
                    "address": function.address,
                    "name": function.name,
                    "discovery": function.discovery,
                    "confidence": function.confidence,
                    "signature": function.decompiled.signature,
                    "text": function.decompiled.text,
                    "warnings": function.decompiled.warnings,
                    "unsupported_instructions": function.decompiled.unsupported_instructions,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let mut buffer = String::new();
    for function in selected.iter().take(args.limit) {
        buffer.push_str(&function.decompiled.text);
        buffer.push('\n');
    }
    if selected.len() > args.limit {
        buffer.push_str(&format!(
            "// {} more function(s) not decompiled; raise --limit\n",
            selected.len() - args.limit
        ));
    }
    if let Some(path) = &args.output {
        let mut writer = BufWriter::new(
            File::create(path).with_context(|| format!("could not create {}", path.display()))?,
        );
        writer.write_all(buffer.as_bytes())?;
        writer.flush()?;
        println!(
            "Wrote {} function(s) to {}",
            selected.len().min(args.limit),
            path.display()
        );
    } else {
        print!("{buffer}");
    }
    Ok(())
}

pub fn run_xrefs(args: &XrefsArgs, json: bool) -> Result<()> {
    let analysis = obtain(args.file.as_deref(), &args.common)?;
    let target = match args.to.as_deref() {
        Some(value) => Some(resolve_value(&analysis, value)?),
        None => None,
    };
    let xrefs: Vec<_> = analysis
        .xrefs
        .iter()
        .filter(|xref| target.map(|target| xref.to == target).unwrap_or(true))
        .take(args.limit)
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&xrefs)?);
        return Ok(());
    }
    if let Some(target) = target {
        println!(
            "References to 0x{target:x} ({}):",
            analysis
                .xrefs
                .iter()
                .filter(|xref| xref.to == target)
                .count()
        );
    } else {
        println!("First {} cross-reference(s):", xrefs.len());
    }
    for xref in &xrefs {
        let name = analysis
            .functions
            .iter()
            .find(|function| function.address == xref.to)
            .map(|function| function.name.as_str())
            .unwrap_or("");
        println!(
            "  0x{:08x} -> 0x{:08x}  {:<6} {}{}",
            xref.from,
            xref.to,
            xref.kind,
            name,
            xref.function
                .map(|function| format!(" (in 0x{function:x})"))
                .unwrap_or_default()
        );
    }
    if analysis.xrefs.len() > xrefs.len() {
        println!("… {} more reference(s)", analysis.xrefs.len() - xrefs.len());
    }
    Ok(())
}

fn write_json(path: &Path, analysis: &ProgramAnalysis) -> Result<()> {
    let mut writer = BufWriter::new(
        File::create(path).with_context(|| format!("could not create {}", path.display()))?,
    );
    serde_json::to_writer(&mut writer, analysis)
        .with_context(|| format!("could not write {}", path.display()))?;
    writer.flush()?;
    Ok(())
}

fn function_summary(function: &FunctionAnalysis) -> serde_json::Value {
    serde_json::json!({
        "address": function.address,
        "name": function.name,
        "discovery": function.discovery,
        "confidence": function.confidence,
        "size": function.size,
        "instructions": function.instruction_count,
        "blocks": function.blocks.len(),
        "calls": function.calls,
        "signature": function.decompiled.signature,
    })
}

fn select_functions<'a>(
    analysis: &'a ProgramAnalysis,
    selector: Option<&str>,
) -> Result<Vec<&'a FunctionAnalysis>> {
    let Some(selector) = selector else {
        return Ok(analysis.functions.iter().collect());
    };
    let value = resolve_value(analysis, selector)?;
    let matches: Vec<&FunctionAnalysis> = analysis
        .functions
        .iter()
        .filter(|function| function.address == value || function.name == selector)
        .collect();
    if matches.is_empty() {
        bail!("no function matching '{selector}' (parsed as 0x{value:x}); see `ghirust functions`");
    }
    Ok(matches)
}

fn resolve_value(analysis: &ProgramAnalysis, value: &str) -> Result<u64> {
    if let Some(name_match) = analysis
        .functions
        .iter()
        .find(|function| function.name == value)
    {
        return Ok(name_match.address);
    }
    if let Some(symbol) = analysis
        .symbols
        .iter()
        .find(|symbol| !symbol.name.is_empty() && symbol.name == value && symbol.address != 0)
    {
        return Ok(symbol.address);
    }
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    parsed.with_context(|| format!("'{value}' is not a function name or address"))
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    let mut output: String = value.chars().take(width.saturating_sub(1)).collect();
    output.push('…');
    output
}
