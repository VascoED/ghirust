//! `ghirust benchmark` — measured analysis benchmarks for objective fixtures.
//!
//! The command runs the real loader/decoder/CFG/pseudocode pipeline and reports
//! only measurements it took. It never reads a stored benchmark result and
//! never estimates numbers that were not produced by this run.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

use ghirust_core::analysis::{AnalysisOptions, analyze_path_managed};
use ghirust_core::resources::{ResourceBudget, ResourceManager, ResourceProfile};

/// Resource profile applied to the benchmark runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    Conservative,
    Balanced,
    Performance,
}

/// Arguments for `ghirust benchmark`.
#[derive(Debug, Args)]
pub struct BenchmarkArgs {
    /// Binary to analyze repeatedly.
    pub file: PathBuf,

    /// Number of measured runs.
    #[arg(long, default_value_t = 5)]
    pub runs: usize,

    /// Maximum number of functions retained.
    #[arg(long, default_value_t = 100_000)]
    pub max_functions: usize,

    /// Skip pseudocode reconstruction (listing/CFG-only benchmark).
    #[arg(long)]
    pub no_decompile: bool,

    /// Also save the last complete analysis as JSON.
    #[arg(long)]
    pub save_analysis: Option<PathBuf>,

    /// Resource profile for the runs.
    #[arg(long, value_enum)]
    pub profile: Option<ProfileArg>,

    /// Maximum worker threads for parallel work.
    #[arg(long)]
    pub max_threads: Option<usize>,
}

#[derive(Debug, Clone)]
struct RunSample {
    wall_ms: u128,
    analysis_ms: u128,
    functions: u64,
    instructions: u64,
    blocks: u64,
    xrefs: u64,
}

pub fn run(args: &BenchmarkArgs, json: bool) -> Result<()> {
    if args.runs == 0 {
        bail!("--runs must be at least 1");
    }
    let metadata = std::fs::metadata(&args.file)
        .with_context(|| format!("could not stat {}", args.file.display()))?;
    if metadata.len() == 0 {
        bail!("{} is empty", args.file.display());
    }
    let options = AnalysisOptions {
        max_functions: args.max_functions,
        decompile: !args.no_decompile,
        ..AnalysisOptions::default()
    };

    // Apply the requested profile/limits; the benchmark measures the engine
    // under the same resource controls users get in the GUI.
    let mut budget = match args.profile {
        Some(ProfileArg::Conservative) => ResourceBudget::conservative(),
        Some(ProfileArg::Balanced) => ResourceBudget::balanced(),
        Some(ProfileArg::Performance) => ResourceBudget::performance(),
        None if args.max_threads.is_some() => ResourceBudget::balanced(),
        None => ResourceBudget::default(),
    };
    if let Some(threads) = args.max_threads {
        budget.max_worker_threads = threads.clamp(1, 64);
    }
    let manager = ResourceManager::new(ResourceProfile::Custom(budget));

    let mut samples = Vec::with_capacity(args.runs);
    let mut last = None;
    for _ in 0..args.runs {
        let started = Instant::now();
        let analysis = analyze_path_managed(&args.file, &options, &manager)
            .with_context(|| format!("could not analyze {}", args.file.display()))?;
        let wall_ms = started.elapsed().as_millis();
        samples.push(RunSample {
            wall_ms,
            analysis_ms: analysis.stats.elapsed_ms,
            functions: analysis.stats.functions,
            instructions: analysis.stats.instructions,
            blocks: analysis.stats.blocks,
            xrefs: analysis.stats.xrefs,
        });
        last = Some(analysis);
    }
    let analysis = last.expect("at least one run");
    if let Some(path) = &args.save_analysis {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let file = std::fs::File::create(path)
            .with_context(|| format!("could not create {}", path.display()))?;
        serde_json::to_writer(std::io::BufWriter::new(file), &analysis)
            .with_context(|| format!("could not write {}", path.display()))?;
    }

    let mut wall: Vec<u128> = samples.iter().map(|sample| sample.wall_ms).collect();
    let mut core: Vec<u128> = samples.iter().map(|sample| sample.analysis_ms).collect();
    wall.sort_unstable();
    core.sort_unstable();
    let median = |values: &[u128]| values[values.len() / 2];
    let minimum = |values: &[u128]| values[0];
    let maximum = |values: &[u128]| values[values.len() - 1];
    let mean = |values: &[u128]| values.iter().sum::<u128>() as f64 / values.len() as f64;

    if json {
        let payload = serde_json::json!({
            "file": args.file,
            "file_bytes": metadata.len(),
            "sha256": analysis.sha256,
            "runs": args.runs,
            "decompile": !args.no_decompile,
            "wall_ms": {
                "min": minimum(&wall),
                "median": median(&wall),
                "mean": mean(&wall),
                "max": maximum(&wall),
            },
            "core_analysis_ms": {
                "min": minimum(&core),
                "median": median(&core),
                "mean": mean(&core),
                "max": maximum(&core),
            },
            "samples": samples.iter().map(|sample| serde_json::json!({
                "wall_ms": sample.wall_ms,
                "analysis_ms": sample.analysis_ms,
                "functions": sample.functions,
                "instructions": sample.instructions,
                "blocks": sample.blocks,
                "xrefs": sample.xrefs,
            })).collect::<Vec<_>>(),
            "stats": analysis.stats,
            "warnings": analysis.warnings,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("Benchmark: {}", args.file.display());
    println!(
        "File: {} bytes · {} run(s) · pseudocode: {}",
        metadata.len(),
        args.runs,
        if args.no_decompile {
            "disabled"
        } else {
            "enabled"
        }
    );
    println!(
        "Recovered: {} functions · {} instructions · {} blocks · {} xrefs",
        analysis.stats.functions,
        analysis.stats.instructions,
        analysis.stats.blocks,
        analysis.stats.xrefs
    );
    println!(
        "Wall time (load + analysis): min {} ms · median {} ms · mean {:.1} ms · max {} ms",
        minimum(&wall),
        median(&wall),
        mean(&wall),
        maximum(&wall)
    );
    println!(
        "Core analysis (no load):      min {} ms · median {} ms · mean {:.1} ms · max {} ms",
        minimum(&core),
        median(&core),
        mean(&core),
        maximum(&core)
    );
    println!("\nPer run:");
    for (index, sample) in samples.iter().enumerate() {
        println!(
            "  #{} wall {} ms · analysis {} ms · {} insn",
            index + 1,
            sample.wall_ms,
            sample.analysis_ms,
            sample.instructions
        );
    }
    if let Some(path) = &args.save_analysis {
        println!("\nSaved analysis: {}", path.display());
    }
    Ok(())
}
