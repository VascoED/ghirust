//! End-to-end objective test against a real PE DLL compiled from known Rust
//! source. The test never asserts fabricated results: it compiles the fixture
//! with the local toolchain, analyzes the resulting machine code and checks the
//! recovered names, instructions, CFG shape and pseudocode.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::SystemTime;

use ghirust_core::analysis::{AnalysisOptions, ProgramAnalysis, analyze_path};

fn objective_source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("tests")
        .join("objectives")
        .join("source")
        .join("demo.rs")
}

fn build_demo() -> Option<PathBuf> {
    let source = objective_source();
    if !source.exists() {
        eprintln!("objective source missing: {}", source.display());
        return None;
    }
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("target")
        .join("objective-fixtures");
    fs::create_dir_all(&output_dir).ok()?;
    let dll = output_dir.join("demo.dll");
    if dll.exists() && !is_stale(&source, &dll) {
        return Some(dll);
    }
    let status = Command::new("rustc")
        .arg("--edition")
        .arg("2024")
        .arg("-O")
        .arg("--crate-type")
        .arg("cdylib")
        .arg("--crate-name")
        .arg("demo")
        .arg(&source)
        .arg("-o")
        .arg(&dll)
        .status();
    match status {
        Ok(status) if status.success() && dll.exists() => Some(dll),
        Ok(status) => {
            eprintln!("rustc fixture build failed with {status}");
            None
        }
        Err(error) => {
            eprintln!("rustc unavailable for objective fixture: {error}");
            None
        }
    }
}

fn is_stale(source: &Path, output: &Path) -> bool {
    let modified = |path: &Path| -> Option<SystemTime> { fs::metadata(path).ok()?.modified().ok() };
    match (modified(source), modified(output)) {
        (Some(source), Some(output)) => source > output,
        _ => true,
    }
}

fn demo_dll() -> Option<&'static Path> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE.get_or_init(build_demo).as_deref()
}

fn analyze_demo() -> Option<ProgramAnalysis> {
    let dll = demo_dll()?;
    let analysis =
        analyze_path(dll, &AnalysisOptions::default()).expect("the real PE fixture must analyze");
    Some(analysis)
}

fn function<'a>(
    analysis: &'a ProgramAnalysis,
    name: &str,
) -> &'a ghirust_core::analysis::FunctionAnalysis {
    analysis
        .functions
        .iter()
        .find(|function| function.name == name)
        .unwrap_or_else(|| panic!("function {name} was not discovered"))
}

#[test]
fn real_pe_dll_is_disassembled_and_decompiled() {
    let Some(analysis) = analyze_demo() else {
        eprintln!("skipping objective test: no usable toolchain/fixture");
        return;
    };

    assert_eq!(analysis.loader.format, "PE");
    assert_eq!(analysis.loader.architecture, "X86_64");
    assert_eq!(analysis.loader.bits, 64);
    assert!(analysis.stats.functions >= 6);
    assert!(analysis.stats.instructions > 0);
    assert!(analysis.stats.xrefs > 0);
    assert!(analysis.stats.linear_scan_instructions > 0);
    assert_eq!(
        analysis.stats.functions,
        analysis.functions.len() as u64,
        "statistics must match the retained function list"
    );

    for name in [
        "demo_add",
        "demo_classify",
        "demo_max",
        "demo_fact",
        "demo_mix",
        "demo_sum_loop",
    ] {
        let function = function(&analysis, name);
        assert_eq!(function.discovery, "export");
        assert!(function.confidence >= 0.9);
        assert!(!function.blocks.is_empty());
        assert!(function.instruction_count > 0);
        assert!(
            function.blocks.iter().any(|block| block
                .instructions
                .iter()
                .any(|instruction| instruction.size > 0 && !instruction.bytes.is_empty())),
            "{name} has no encoded instruction listing"
        );
    }

    let add = function(&analysis, "demo_add");
    assert!(
        add.decompiled.text.contains("a0 + a1"),
        "{}",
        add.decompiled.text
    );
    assert!(add.decompiled.text.contains("return"));

    let classify = function(&analysis, "demo_classify");
    assert_eq!(
        classify.decompiled.parameters.len(),
        1,
        "only the first argument is semantically used: {}",
        classify.decompiled.signature
    );
    assert!(
        classify.decompiled.text.contains("!= 0"),
        "{}",
        classify.decompiled.text
    );

    let max = function(&analysis, "demo_max");
    assert!(
        max.decompiled.text.contains("a0 > a1") || max.decompiled.text.contains("if"),
        "{}",
        max.decompiled.text
    );

    let fact = function(&analysis, "demo_fact");
    assert!(
        fact.decompiled.text.contains("while"),
        "factorial loop must be structured: {}",
        fact.decompiled.text
    );
    assert!(
        fact.decompiled.text.contains("rax * rdx"),
        "loop body multiplication must be reconstructed: {}",
        fact.decompiled.text
    );
    assert!(
        fact.decompiled.text.contains("rdx + 1"),
        "loop increment must be reconstructed: {}",
        fact.decompiled.text
    );

    let sum = function(&analysis, "demo_sum_loop");
    assert!(
        !sum.decompiled.unsupported_instructions.is_empty(),
        "auto-vectorized SSE instructions must be reported, never silently ignored"
    );
    assert!(
        sum.decompiled
            .warnings
            .iter()
            .any(|warning| warning.contains("paddq") || warning.contains("movq")),
        "SSE limitations must appear in warnings: {:?}",
        sum.decompiled.warnings
    );
}

#[test]
fn cfg_blocks_are_well_formed_and_successors_are_reachable() {
    let Some(analysis) = analyze_demo() else {
        return;
    };
    for function in &analysis.functions {
        let starts: Vec<u64> = function.blocks.iter().map(|block| block.start).collect();
        for block in &function.blocks {
            assert!(
                !block.instructions.is_empty(),
                "empty block at 0x{:x}",
                block.start
            );
            let mut previous = block.start;
            for instruction in &block.instructions {
                assert_eq!(
                    instruction.address, previous,
                    "instructions must be contiguous inside a block"
                );
                previous = previous.saturating_add(instruction.size as u64);
            }
            assert_eq!(
                block.end, previous,
                "block end must equal the end of its last instruction"
            );
            for successor in &block.successors {
                assert!(
                    starts.contains(successor)
                        || analysis
                            .functions
                            .iter()
                            .any(|other| other.address == *successor),
                    "successor 0x{successor:x} is neither a block in this function nor a known function entry"
                );
            }
        }
    }
    for xref in &analysis.xrefs {
        assert!(xref.from > 0, "xref source must be a real address");
        assert!(xref.to > 0, "xref target must be a real address");
        assert!(
            matches!(xref.kind.as_str(), "call" | "jump" | "data" | "string"),
            "unexpected xref kind {}",
            xref.kind
        );
    }
}

#[test]
fn analysis_roundtrips_through_json_without_loss() {
    let Some(analysis) = analyze_demo() else {
        return;
    };
    let json = serde_json::to_vec(&analysis).expect("analysis must serialize");
    let restored: ProgramAnalysis =
        serde_json::from_slice(&json).expect("analysis must deserialize");
    assert_eq!(restored.sha256, analysis.sha256);
    assert_eq!(restored.stats.functions, analysis.stats.functions);
    assert_eq!(restored.stats.instructions, analysis.stats.instructions);
    assert_eq!(restored.functions.len(), analysis.functions.len());
    assert_eq!(restored.xrefs.len(), analysis.xrefs.len());
    let original = function(&analysis, "demo_fact");
    let roundtrip = restored
        .functions
        .iter()
        .find(|function| function.name == "demo_fact")
        .expect("demo_fact must survive serialization");
    assert_eq!(original.decompiled.text, roundtrip.decompiled.text);
}
