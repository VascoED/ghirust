use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

use ghirust_core::index::{IndexOptions, build_index};
use ghirust_core::search::{SearchOptions, search};
use ghirust_core::strings::{StringOptions, extract_strings};
use serde::Serialize;
use tempfile::tempdir;

#[derive(Serialize)]
struct BenchmarkReport {
    generated_files: usize,
    generated_functions: usize,
    iterations: usize,
    index_elapsed_ms: u128,
    measurements: Vec<Measurement>,
    peak_memory_bytes: Option<u64>,
    cpu_utilization_percent: Option<f64>,
}

#[derive(Serialize)]
struct Measurement {
    case: String,
    median_ms: f64,
    p95_ms: f64,
    results: usize,
    bytes_scanned: u64,
    throughput_mib_per_second: Option<f64>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let file_count = parse_argument(&arguments, 0, 64)?;
    let functions_per_file = parse_argument(&arguments, 1, 128)?;
    let iterations = parse_argument(&arguments, 2, 7)?;
    if file_count == 0 || functions_per_file == 0 || iterations == 0 {
        return Err("files, functions-per-file, and iterations must be positive".into());
    }

    let temp = tempdir()?;
    let root = temp.path();
    let function_count = file_count.saturating_mul(functions_per_file);
    create_project(root, file_count, functions_per_file)?;
    let index_report = build_index(&IndexOptions::new(root))?;
    let index_path = index_report.index_path;
    let index = ghirust_core::load_index(&index_path)?;
    let mut measurements = Vec::new();

    for (label, query) in [
        ("text", "text:GHIRUST_BENCHMARK_TEXT_SENTINEL".to_owned()),
        (
            "function_name",
            "name:benchmark_function_00000000".to_owned(),
        ),
        ("function_address", "name:0x00400000".to_owned()),
        ("project_path", "file:source-00000".to_owned()),
    ] {
        measurements.push(measure_search(label, &index, &query, iterations)?);
    }

    for prefix in ["b", "be", "benchmark", "benchmark_function_"] {
        measurements.push(measure_search(
            &format!("incremental_name_{prefix}"),
            &index,
            &format!("name:{prefix}"),
            iterations,
        )?);
    }

    let string_bytes = create_string_sample(root)?;
    measurements.push(measure_strings(
        &root.join("strings.bin"),
        string_bytes,
        iterations,
    )?);

    let report = BenchmarkReport {
        generated_files: file_count,
        generated_functions: function_count,
        iterations,
        index_elapsed_ms: index_report.elapsed_ms,
        measurements,
        peak_memory_bytes: None,
        cpu_utilization_percent: None,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_argument(
    arguments: &[String],
    index: usize,
    default: usize,
) -> Result<usize, Box<dyn Error>> {
    arguments
        .get(index)
        .map(|value| value.parse::<usize>())
        .transpose()
        .map(|value| value.unwrap_or(default))
        .map_err(Into::into)
}

fn create_project(
    root: &Path,
    file_count: usize,
    functions_per_file: usize,
) -> Result<(), Box<dyn Error>> {
    for file_index in 0..file_count {
        let path = root.join(format!("source-{file_index:05}.c"));
        let mut writer = BufWriter::new(File::create(path)?);
        for function_in_file in 0..functions_per_file {
            let function_id = file_index * functions_per_file + function_in_file;
            let address = 0x0040_0000u64 + function_id as u64 * 16;
            writeln!(
                writer,
                "// Function: benchmark_function_{function_id:08} @ 0x{address:08x}"
            )?;
            writeln!(
                writer,
                "int benchmark_function_{function_id:08}(void) {{ return GHIRUST_BENCHMARK_TEXT_SENTINEL; }}"
            )?;
        }
        writer.flush()?;
    }
    Ok(())
}

fn create_string_sample(root: &Path) -> Result<u64, Box<dyn Error>> {
    let path = root.join("strings.bin");
    let mut writer = BufWriter::new(File::create(&path)?);
    for index in 0..10_000 {
        writeln!(writer, "GHIRUST_STRING_SENTINEL_{index:05}")?;
    }
    writer.flush()?;
    Ok(fs::metadata(path)?.len())
}

fn measure_search(
    case: &str,
    index: &ghirust_core::SearchIndex,
    query: &str,
    iterations: usize,
) -> Result<Measurement, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(iterations);
    let mut results = 0;
    let mut bytes_scanned = 0;
    for _ in 0..iterations {
        let started = Instant::now();
        let report = search(
            index,
            &SearchOptions {
                query: query.to_owned(),
                limit: 1_000,
                ..SearchOptions::default()
            },
        )?;
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
        results = report.hits.len();
        bytes_scanned = report.scanned_bytes;
    }
    Ok(measurement(case, samples, results, bytes_scanned))
}

fn measure_strings(
    path: &Path,
    bytes: u64,
    iterations: usize,
) -> Result<Measurement, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(iterations);
    let mut results = 0;
    for _ in 0..iterations {
        let started = Instant::now();
        let records = extract_strings(
            path,
            &StringOptions {
                deduplicate: true,
                ..StringOptions::default()
            },
        )?;
        results = records
            .iter()
            .filter(|record| record.value.contains("GHIRUST_STRING_SENTINEL"))
            .count();
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    Ok(measurement(
        "extract_and_search_strings",
        samples,
        results,
        bytes,
    ))
}

fn measurement(
    case: &str,
    mut samples: Vec<f64>,
    results: usize,
    bytes_scanned: u64,
) -> Measurement {
    samples.sort_by(f64::total_cmp);
    let median_ms = percentile(&samples, 0.50);
    let p95_ms = percentile(&samples, 0.95);
    let throughput_mib_per_second =
        (median_ms > 0.0).then(|| bytes_scanned as f64 / (1024.0 * 1024.0) / (median_ms / 1_000.0));
    Measurement {
        case: case.to_owned(),
        median_ms,
        p95_ms,
        results,
        bytes_scanned,
        throughput_mib_per_second,
    }
}

fn percentile(samples: &[f64], percentile: f64) -> f64 {
    let index = ((samples.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len().saturating_sub(1));
    samples[index]
}
