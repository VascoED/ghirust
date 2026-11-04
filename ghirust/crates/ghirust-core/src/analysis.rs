//! Whole-program analysis: function discovery, x86-64 decoding, basic blocks,
//! control-flow edges and cross-references.
//!
//! The pipeline is deliberately explicit:
//!
//! ```text
//! loader -> linear sweep (seeds) -> recursive CFG walk -> decoded functions
//!        -> GUIR module + pseudocode reconstruction
//! ```
//!
//! Function discovery is conservative. It uses entry points, exports, symbols,
//! direct call targets and aligned prologue patterns. Every function carries the
//! evidence that produced it and a confidence value; heuristics are never
//! presented as confirmed boundaries.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::Instant;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind,
    Register,
};
use serde::{Deserialize, Serialize};

use crate::cache::hash_file;
use crate::error::{GhirustError, Result};
use crate::ir;
use crate::loader::{LoadedProgram, LoaderSummary, load_or_hint};
use crate::pseudocode::{self, DecompiledFunction};
use crate::resources::{Priority, ReservationRequest, ResourceManager};
use crate::strings::StringRecord;

/// Analysis bounds. All are hard limits so a malformed input cannot exhaust
/// memory or keep the UI blocked forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Maximum number of functions retained.
    pub max_functions: usize,
    /// Maximum instructions decoded per function.
    pub max_instructions_per_function: usize,
    /// Maximum basic blocks per function.
    pub max_blocks_per_function: usize,
    /// Maximum instructions decoded by the initial linear sweep.
    pub max_linear_scan_instructions: usize,
    /// Maximum prologue candidates accepted from the sweep.
    pub max_prologue_candidates: usize,
    /// Analyze prologue patterns in addition to symbols and call targets.
    pub discover_prologues: bool,
    /// Maximum strings retained in the analysis.
    pub max_strings: usize,
    /// Maximum xrefs retained.
    pub max_xrefs: usize,
    /// Decompile functions after recovery.
    pub decompile: bool,
    /// Cooperative stop flag from the resource manager: checked periodically
    /// during the sweep and function decoding. Not serialized.
    #[serde(skip)]
    pub stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Throttle flag from the resource manager: long loops yield while set.
    /// Not serialized.
    #[serde(skip)]
    pub throttle_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl AnalysisOptions {
    /// Whether a cooperative stop has been requested.
    pub fn stop_requested(&self) -> bool {
        self.stop_flag
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Whether long loops should yield to relieve pressure.
    pub fn throttled(&self) -> bool {
        self.throttle_flag
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Yield to the scheduler when throttling is active.
    pub fn cooperative_point(&self) {
        if self.throttled() {
            std::thread::yield_now();
        }
    }
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_functions: 100_000,
            max_instructions_per_function: 250_000,
            max_blocks_per_function: 25_000,
            max_linear_scan_instructions: 20_000_000,
            max_prologue_candidates: 50_000,
            discover_prologues: true,
            max_strings: 50_000,
            max_xrefs: 2_000_000,
            decompile: true,
            stop_flag: None,
            throttle_flag: None,
        }
    }
}

/// One decoded instruction in the public listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingInstruction {
    /// Virtual address.
    pub address: u64,
    /// Encoded length in bytes.
    pub size: u8,
    /// Encoded bytes as lowercase hexadecimal.
    pub bytes: String,
    /// Full Intel-syntax text.
    pub text: String,
    /// Mnemonic only.
    pub mnemonic: String,
    /// Operand text only.
    pub operands: String,
    /// `next`, `call`, `jump`, `conditional`, `return`, `indirect`, ...
    pub flow: String,
    /// Direct call target.
    pub call_target: Option<u64>,
    /// Direct branch target.
    pub branch_target: Option<u64>,
    /// Absolute data address referenced by a RIP-relative operand.
    pub memory_reference: Option<u64>,
    /// Whether the lifter/models do not understand this instruction.
    pub unsupported: bool,
}

/// One recovered basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnalysis {
    /// Block index inside its function.
    pub id: u32,
    /// Start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Successor block addresses.
    pub successors: Vec<u64>,
    /// How the block ends.
    pub terminator: String,
    /// Conditional-branch mnemonic, when applicable.
    pub condition: Option<String>,
    /// Instructions in execution order.
    pub instructions: Vec<ListingInstruction>,
}

/// One cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Xref {
    /// Source address.
    pub from: u64,
    /// Destination address.
    pub to: u64,
    /// `call`, `jump`, `data`, or `string`.
    pub kind: String,
    /// Owning function, when known.
    pub function: Option<u64>,
}

/// Discovered function with listing, CFG and pseudocode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalysis {
    /// Stable index in the analysis.
    pub id: u32,
    /// Display name.
    pub name: String,
    /// Start address.
    pub address: u64,
    /// Recovered size in bytes.
    pub size: u64,
    /// Exclusive end address.
    pub end: u64,
    /// How the function was found (`entry`, `export`, `symbol`, `call`, `prologue`).
    pub discovery: String,
    /// Confidence in the boundary and name.
    pub confidence: f32,
    /// Number of decoded instructions.
    pub instruction_count: u64,
    /// Basic blocks.
    pub blocks: Vec<BlockAnalysis>,
    /// Direct call destinations.
    pub calls: Vec<u64>,
    /// Recovered signature and pseudocode.
    pub decompiled: DecompiledFunction,
}

/// Aggregate analysis statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisStats {
    /// Functions retained.
    pub functions: u64,
    /// Instructions decoded inside recovered functions.
    pub instructions: u64,
    /// Basic blocks recovered.
    pub blocks: u64,
    /// Cross-references retained.
    pub xrefs: u64,
    /// Instructions visited by the linear seed sweep.
    pub linear_scan_instructions: u64,
    /// Number of seeds considered.
    pub seeds: u64,
    /// Functions whose seed was a direct call target found inside decoded code.
    pub functions_from_calls: u64,
    /// Functions skipped because their range overlapped a higher-confidence one.
    pub overlapping_functions_skipped: u64,
    /// Whether any bound was reached.
    pub truncated: bool,
    /// Analysis wall-clock time.
    pub elapsed_ms: u128,
}

/// Complete analysis of one binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramAnalysis {
    /// Analysis format version.
    pub format_version: u32,
    /// Tool identifier.
    pub generated_by: String,
    /// Source path.
    pub path: String,
    /// SHA-256 of the input.
    pub sha256: String,
    /// Loader metadata.
    pub loader: LoaderSummary,
    /// Sections.
    pub sections: Vec<crate::loader::LoadedSection>,
    /// Imports.
    pub imports: Vec<crate::loader::ImportRecord>,
    /// Exports.
    pub exports: Vec<crate::loader::ExportRecord>,
    /// Symbols used or observed.
    pub symbols: Vec<crate::loader::SymbolRecord>,
    /// Strings extracted from the image.
    pub strings: Vec<StringRecord>,
    /// Recovered functions.
    pub functions: Vec<FunctionAnalysis>,
    /// Cross-references.
    pub xrefs: Vec<Xref>,
    /// Statistics.
    pub stats: AnalysisStats,
    /// GUIR module lifted from the same decoded CFG.
    pub ir: ir::Module,
    /// Limitations and non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Current analysis format version.
pub const ANALYSIS_VERSION: u32 = 1;

/// Decoded instruction retained for the decompiler stage.
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    /// Raw iced-x86 instruction.
    pub instruction: Instruction,
    /// Display text.
    pub text: String,
    /// Encoded bytes.
    pub bytes: Vec<u8>,
}

/// Terminator of a decoded basic block.
#[derive(Debug, Clone)]
pub enum DecodedTerminator {
    /// Falls through to the next block (kept for completeness).
    Fallthrough(u64),
    /// Unconditional direct jump.
    Jump(u64),
    /// Conditional branch: taken target plus fallthrough.
    Conditional {
        /// Branch mnemonic.
        mnemonic: Mnemonic,
        /// Target when the condition is true.
        target: u64,
        /// Address of the next instruction.
        fallthrough: u64,
    },
    /// Return.
    Return,
    /// Indirect jump with an unresolved target.
    IndirectJump,
    /// Tail call: a direct `call` whose return address is the call target
    /// itself, or a jump to a known function entry. The function ends here;
    /// control does not continue to the next instruction.
    TailCall(u64),
    /// Trap or invalid instruction.
    Unreachable,
}

/// One decoded basic block.
#[derive(Debug, Clone)]
pub struct DecodedBlock {
    /// Start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Decoded instructions.
    pub instructions: Vec<DecodedInstruction>,
    /// How control leaves this block.
    pub terminator: DecodedTerminator,
}

/// Internal decoded function passed to the pseudocode stage.
#[derive(Debug, Clone)]
pub struct DecodedFunction {
    /// Start address.
    pub address: u64,
    /// Display name.
    pub name: String,
    /// Discovery source.
    pub discovery: String,
    /// Confidence.
    pub confidence: f32,
    /// Basic blocks in address order.
    pub blocks: Vec<DecodedBlock>,
    /// Direct call targets.
    pub calls: Vec<u64>,
    /// Non-fatal decoding problems.
    pub warnings: Vec<String>,
    /// Number of instructions.
    pub instruction_count: u64,
}

impl DecodedFunction {
    /// Exclusive end address.
    pub fn end(&self) -> u64 {
        self.blocks
            .iter()
            .map(|block| block.end)
            .max()
            .unwrap_or(self.address)
    }

    /// Find the block containing an address.
    pub fn block_at(&self, address: u64) -> Option<&DecodedBlock> {
        self.blocks
            .iter()
            .find(|block| block.start == address)
            .or_else(|| {
                self.blocks
                    .iter()
                    .find(|block| address >= block.start && address < block.end)
            })
    }
}

/// Load and analyze a binary.
pub fn analyze_path(path: &Path, options: &AnalysisOptions) -> Result<ProgramAnalysis> {
    let program = load_or_hint(path)?;
    analyze_program(&program, options)
}

/// Analyze a binary under a [`ResourceManager`] budget. The reservation is
/// held for the whole run and released automatically; a watcher flips the
/// cooperative throttle/stop flags as pressure changes.
pub fn analyze_path_managed(
    path: &Path,
    options: &AnalysisOptions,
    manager: &ResourceManager,
) -> Result<ProgramAnalysis> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let size = std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    // Rough, deliberately conservative estimate of working memory.
    let estimate = (size as usize * 8).clamp(16 * 1024 * 1024, 512 * 1024 * 1024);
    let request = ReservationRequest::new(format!("analyze {}", path.display()), Priority::High)
        .with_ram(estimate)
        .cancellable(true);
    let reservation = manager
        .reserve(&request)
        .map_err(|error| GhirustError::message(error.to_string()))?;

    let mut options = options.clone();
    let stop = manager.critical_stop_token();
    options.stop_flag = Some(stop.arc());
    let throttle = Arc::new(AtomicBool::new(false));
    options.throttle_flag = Some(Arc::clone(&throttle));

    // Watcher: mirrors the manager's pressure into the throttle flag until
    // the analysis finishes.
    let done = Arc::new(AtomicBool::new(false));
    let manager = manager.clone();
    let watcher_done = Arc::clone(&done);
    let watcher = std::thread::Builder::new()
        .name("ghirust-pressure-watcher".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                if watcher_done.load(Ordering::Acquire) {
                    break;
                }
                let throttling = manager.should_throttle();
                throttle.store(throttling, Ordering::Release);
            }
        })
        .ok();

    let _reservation = reservation;
    let result = analyze_path(path, &options);
    done.store(true, Ordering::Release);
    if let Some(handle) = watcher {
        let _ = handle.join();
    }
    result
}

/// Analyze an already loaded binary.
pub fn analyze_program(
    program: &LoadedProgram,
    options: &AnalysisOptions,
) -> Result<ProgramAnalysis> {
    let started = Instant::now();
    if !matches!(
        program.architecture.as_str(),
        "X86_64" | "I386" | "X86" | "x86_64" | "x86"
    ) {
        return Err(GhirustError::message(format!(
            "the current disassembler backend supports x86/x86-64 only; {} is {}",
            program.path.display(),
            program.architecture
        )));
    }
    let bits = program.bits;
    if bits != 64 && bits != 32 {
        return Err(GhirustError::message(format!(
            "unsupported x86 pointer width: {bits}"
        )));
    }

    let mut warnings = program.warnings.clone();
    let seeds_result = discover_seeds(program, options, &mut warnings);
    let linear_scan_instructions = seeds_result.linear_scan_instructions;
    let mut seeds = seeds_result.seeds;
    if seeds.len() > options.max_functions {
        warnings.push(format!(
            "function seed limit reached: {} of {} candidates retained",
            options.max_functions,
            seeds.len()
        ));
        seeds.truncate(options.max_functions);
    }
    let seed_count = seeds.len() as u64;

    let mut decoded_functions: Vec<DecodedFunction> = Vec::new();
    let mut claimed_blocks: Vec<(u64, u64)> = Vec::new();
    let mut skipped_overlaps = 0u64;
    let mut functions_from_calls = 0u64;

    // Code ranges used to accept direct call targets as new seeds.
    let code_ranges: Vec<(u64, u64)> = program
        .sections
        .iter()
        .filter(|section| section.executable)
        .map(|section| (section.address, section.address + section.virtual_size))
        .collect();
    let in_code = |address: u64| {
        code_ranges
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    };

    // Recursive worklist: decoded functions contribute their direct call
    // targets as new seeds, so functions reachable only through calls (for
    // example __chkstk after a call) are recovered like Ghidra does.
    let mut queue: VecDeque<Seed> = seeds.iter().cloned().collect();
    let mut queued: HashSet<u64> = seeds.iter().map(|seed| seed.address).collect();
    // Any known seed stops a tail jump: following it would swallow the next
    // function's body or an epilogue fragment.
    let mut known_starts: HashSet<u64> = queued.clone();
    while let Some(seed) = queue.pop_front() {
        if options.stop_requested() {
            warnings.push("analysis stopped: cooperative stop requested".to_owned());
            break;
        }
        options.cooperative_point();
        if options.max_functions > 0 && decoded_functions.len() >= options.max_functions {
            break;
        }
        if claimed_blocks
            .iter()
            .any(|(start, end)| seed.address >= *start && seed.address < *end)
        {
            skipped_overlaps += 1;
            continue;
        }
        match decode_function(program, &seed, options, bits, &known_starts) {
            Ok(Some(function)) => {
                for &target in &function.calls {
                    if target != 0 && in_code(target) && queued.insert(target) {
                        functions_from_calls += 1;
                        known_starts.insert(target);
                        queue.push_back(Seed {
                            address: target,
                            name: format!("FUN_{target:x}"),
                            discovery: "call".to_owned(),
                            confidence: 0.75,
                        });
                    }
                }
                for block in &function.blocks {
                    claimed_blocks.push((block.start, block.end));
                }
                decoded_functions.push(function);
            }
            Ok(None) => {}
            Err(error) => warnings.push(format!(
                "function at 0x{:x} could not be decoded: {error}",
                seed.address
            )),
        }
    }

    decoded_functions.sort_by_key(|function| function.address);
    // Recompute IDs and remove seeds that are entirely contained in another
    // function discovered later but with a higher-priority discovery source.
    decoded_functions.dedup_by_key(|function| function.address);

    // Normalize unconditional jumps that land strictly inside another
    // function's block into tail calls. These are shared epilogues: the jump
    // leaves this function and must not be reported as an intra-function edge.
    let block_interiors: Vec<(u64, u64)> = decoded_functions
        .iter()
        .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end)))
        .collect();
    for function in &mut decoded_functions {
        let own_starts: HashSet<u64> = function.blocks.iter().map(|block| block.start).collect();
        for block in &mut function.blocks {
            if let DecodedTerminator::Jump(target) = block.terminator
                && !own_starts.contains(&target)
                && block_interiors
                    .iter()
                    .any(|(start, end)| target > *start && target < *end)
            {
                block.terminator = DecodedTerminator::TailCall(target);
            }
        }
    }

    let mut functions = Vec::with_capacity(decoded_functions.len());
    let mut ir_module = ir::Module::new(
        program
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("program")
            .to_owned(),
    );
    let mut xrefs = BTreeSet::new();
    let mut stats = AnalysisStats {
        seeds: seed_count,
        linear_scan_instructions,
        functions_from_calls,
        overlapping_functions_skipped: skipped_overlaps,
        ..AnalysisStats::default()
    };

    for (index, decoded) in decoded_functions.iter().enumerate() {
        let decompiled = if options.decompile {
            pseudocode::decompile_function(program, decoded)
        } else {
            DecompiledFunction::not_decompiled()
        };
        if !decompiled.warnings.is_empty() {
            warnings.extend(
                decompiled
                    .warnings
                    .iter()
                    .take(4)
                    .map(|warning| format!("{}: {warning}", decoded.name)),
            );
        }

        let blocks = listing_blocks(decoded);
        let ir_function = lift_ir(decoded, index as u32);
        ir_module.functions.push(ir_function);

        let mut calls = decoded.calls.clone();
        calls.sort_unstable();
        calls.dedup();
        for call in &calls {
            xrefs.insert(Xref {
                from: decoded.address,
                to: *call,
                kind: "call".to_owned(),
                function: Some(decoded.address),
            });
        }
        for block in &decoded.blocks {
            collect_block_xrefs(decoded.address, block, &mut xrefs);
        }

        stats.instructions += decoded.instruction_count;
        stats.blocks += blocks.len() as u64;
        functions.push(FunctionAnalysis {
            id: index as u32,
            name: decoded.name.clone(),
            address: decoded.address,
            size: decoded.end().saturating_sub(decoded.address),
            end: decoded.end(),
            discovery: decoded.discovery.clone(),
            confidence: decoded.confidence,
            instruction_count: decoded.instruction_count,
            blocks,
            calls,
            decompiled,
        });
    }

    let xrefs: Vec<Xref> = xrefs.into_iter().take(options.max_xrefs).collect();
    if xrefs.len() >= options.max_xrefs {
        warnings.push(format!(
            "cross-reference limit reached: {} retained",
            options.max_xrefs
        ));
        stats.truncated = true;
    }
    let issues = ir_module.validate();
    let ir_errors = issues
        .iter()
        .filter(|issue| issue.severity == ir::Severity::Error)
        .count();
    if ir_errors > 0 {
        warnings.push(format!(
            "GUIR validation found {ir_errors} error(s); the module is still stored for inspection"
        ));
    }

    stats.functions = functions.len() as u64;
    stats.xrefs = xrefs.len() as u64;
    stats.elapsed_ms = started.elapsed().as_millis();

    let mut strings = program.strings.clone();
    strings.truncate(options.max_strings);

    Ok(ProgramAnalysis {
        format_version: ANALYSIS_VERSION,
        generated_by: format!("GHIRUST {}", env!("CARGO_PKG_VERSION")),
        path: program.path.display().to_string(),
        sha256: hash_file(&program.path)?,
        loader: LoaderSummary::from(program),
        sections: program.sections.clone(),
        imports: program.imports.clone(),
        exports: program.exports.clone(),
        symbols: program.symbols.clone(),
        strings,
        functions,
        xrefs,
        stats,
        ir: ir_module,
        warnings,
    })
}

/// Analyze every function again with a different name map. Used by project
/// renames without re-running discovery.
pub fn redecompile(
    analysis: &ProgramAnalysis,
    names: &BTreeMap<u64, String>,
) -> Result<ProgramAnalysis> {
    let program = load_or_hint(Path::new(&analysis.path))?;
    let mut updated = analysis.clone();
    let known_starts: HashSet<u64> = updated
        .functions
        .iter()
        .map(|function| function.address)
        .collect();
    for function in &mut updated.functions {
        if let Some(name) = names.get(&function.address) {
            function.name = name.clone();
        }
        if let Ok(Some(decoded)) = decode_function(
            &program,
            &Seed {
                address: function.address,
                name: function.name.clone(),
                discovery: function.discovery.clone(),
                confidence: function.confidence,
            },
            &AnalysisOptions::default(),
            program.bits,
            &known_starts,
        ) {
            function.decompiled = pseudocode::decompile_function(&program, &decoded);
        }
    }
    Ok(updated)
}

#[derive(Debug, Clone)]
struct Seed {
    address: u64,
    name: String,
    discovery: String,
    confidence: f32,
}

struct SeedResult {
    seeds: Vec<Seed>,
    linear_scan_instructions: u64,
}

fn discover_seeds(
    program: &LoadedProgram,
    options: &AnalysisOptions,
    warnings: &mut Vec<String>,
) -> SeedResult {
    let mut seeds: Vec<Seed> = Vec::new();
    let executable: Vec<&crate::loader::LoadedSection> = program
        .sections
        .iter()
        .filter(|section| section.executable)
        .collect();
    if executable.is_empty() {
        warnings.push("no executable sections found".to_owned());
        return SeedResult {
            seeds,
            linear_scan_instructions: 0,
        };
    }

    let mut names: BTreeMap<u64, (String, String, f32)> = BTreeMap::new();
    for symbol in &program.symbols {
        if symbol.address == 0 || !executable.iter().any(|s| s.contains(symbol.address)) {
            continue;
        }
        let entry = names.entry(symbol.address).or_insert_with(|| {
            (
                symbol.name.clone(),
                symbol.source.clone(),
                if symbol.source == "export" {
                    0.95
                } else if symbol.source == "entry" {
                    0.99
                } else {
                    0.9
                },
            )
        });
        if symbol.source == "export" && entry.1 != "entry" {
            entry.0 = symbol.name.clone();
            entry.1 = "export".to_owned();
            entry.2 = 0.95;
        }
    }

    let mut seen = HashSet::new();
    let mut push = |address: u64,
                    discovery: &str,
                    confidence: f32,
                    seeds: &mut Vec<Seed>,
                    names: &BTreeMap<u64, (String, String, f32)>| {
        if !seen.insert(address) {
            return;
        }
        let (name, source, name_confidence) = names
            .get(&address)
            .cloned()
            .unwrap_or_else(|| (format!("FUN_{address:x}"), discovery.to_owned(), 0.0));
        seeds.push(Seed {
            address,
            name,
            discovery: if source.is_empty() {
                discovery.to_owned()
            } else {
                source
            },
            confidence: confidence.max(name_confidence),
        });
    };

    if program.entry != 0 && executable.iter().any(|s| s.contains(program.entry)) {
        push(program.entry, "entry", 0.99, &mut seeds, &names);
    }
    for (address, (_, source, confidence)) in &names {
        push(*address, source, *confidence, &mut seeds, &names);
    }

    let mut call_targets: BTreeSet<u64> = BTreeSet::new();
    let mut jump_targets: BTreeSet<u64> = BTreeSet::new();
    let mut prologue_candidates: BTreeSet<u64> = BTreeSet::new();
    let mut scanned = 0u64;
    for section in &executable {
        if scanned >= options.max_linear_scan_instructions as u64 {
            warnings.push("linear seed sweep stopped at the instruction limit".to_owned());
            break;
        }
        let Some(bytes) = program.code_slice(section.address) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            program.bits as u32,
            bytes,
            section.address,
            DecoderOptions::NONE,
        );
        let mut after_terminator = true;
        while decoder.can_decode() {
            if scanned >= options.max_linear_scan_instructions as u64 {
                break;
            }
            if scanned % 512 == 0 {
                if options.stop_requested() {
                    warnings.push("linear sweep stopped: cooperative stop requested".to_owned());
                    break;
                }
                options.cooperative_point();
            }
            let instruction = decoder.decode();
            scanned += 1;
            if instruction.is_invalid() {
                after_terminator = true;
                continue;
            }
            let flow = instruction.flow_control();
            if matches!(flow, FlowControl::Call | FlowControl::IndirectCall) {
                let target = instruction.near_branch_target();
                if target != 0
                    && instruction.op_count() > 0
                    && instruction.op_kind(0) == OpKind::NearBranch64
                    && executable.iter().any(|s| s.contains(target))
                {
                    call_targets.insert(target);
                }
            }
            // Direct branch targets become low-confidence seeds too. Most
            // land inside an already-claimed function and are skipped; the
            // ones outside are shared return thunks and handler functions.
            if matches!(
                flow,
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
            ) && instruction.op_count() > 0
                && instruction.op_kind(0) == OpKind::NearBranch64
            {
                let target = instruction.near_branch_target();
                if target != 0 && executable.iter().any(|s| s.contains(target)) {
                    jump_targets.insert(target);
                }
            }
            if options.discover_prologues
                && after_terminator
                && instruction.ip() % 16 == 0
                && is_prologue_start(&instruction)
            {
                prologue_candidates.insert(instruction.ip());
            }
            // Padding (int3/nop) between functions must not reset the
            // "after terminator" state, otherwise the following prologue is
            // missed. Real terminators still do reset it.
            if !matches!(instruction.mnemonic(), Mnemonic::Nop | Mnemonic::Int3) {
                after_terminator = matches!(
                    flow,
                    FlowControl::Return
                        | FlowControl::UnconditionalBranch
                        | FlowControl::IndirectBranch
                        | FlowControl::Exception
                        // A thunk can end in `call` whose fallthrough is
                        // padding followed by the next function.
                        | FlowControl::Call
                );
            }
        }
    }

    for target in call_targets.iter() {
        push(*target, "call", 0.75, &mut seeds, &names);
    }
    for target in jump_targets.iter() {
        push(*target, "jump", 0.6, &mut seeds, &names);
    }
    if options.discover_prologues {
        for candidate in prologue_candidates
            .iter()
            .take(options.max_prologue_candidates)
        {
            push(*candidate, "prologue", 0.55, &mut seeds, &names);
        }
        if prologue_candidates.len() > options.max_prologue_candidates {
            warnings.push(format!(
                "prologue candidate limit reached: {} retained",
                options.max_prologue_candidates
            ));
        }
    }
    warnings.push(format!(
        "linear sweep decoded {scanned} instruction(s) across {} executable section(s)",
        executable.len()
    ));
    SeedResult {
        seeds,
        linear_scan_instructions: scanned,
    }
}

fn is_prologue_start(instruction: &Instruction) -> bool {
    let callee_saved = |register: Register| {
        matches!(
            register,
            Register::RBP
                | Register::RBX
                | Register::RSI
                | Register::RDI
                | Register::R12
                | Register::R13
                | Register::R14
                | Register::R15
        )
    };
    matches!(
        instruction.mnemonic(),
        Mnemonic::Push | Mnemonic::Mov | Mnemonic::Sub | Mnemonic::Lea
    ) && match instruction.mnemonic() {
        Mnemonic::Push => {
            instruction.op_kind(0) == OpKind::Register && callee_saved(instruction.op_register(0))
        }
        Mnemonic::Mov => {
            // `mov rbp, rsp` establishes a frame pointer.
            (instruction.op_count() >= 2
                && instruction.op_kind(0) == OpKind::Register
                && instruction.op_register(0) == Register::RBP
                && instruction.op_kind(1) == OpKind::Register
                && instruction.op_register(1) == Register::RSP)
                // `mov [rsp+disp], reg` spills an argument or callee-saved
                // register; common for functions compiled without a frame.
                || (instruction.op_count() >= 2
                    && instruction.op_kind(0) == OpKind::Memory
                    && instruction.memory_base() == Register::RSP
                    && instruction.op_kind(1) == OpKind::Register)
        }
        Mnemonic::Sub => {
            instruction.op_kind(0) == OpKind::Register
                && instruction.op_register(0) == Register::RSP
        }
        Mnemonic::Lea => {
            instruction.op_count() >= 2
                && instruction.op_kind(0) == OpKind::Register
                && instruction.op_register(0) == Register::RSP
        }
        _ => false,
    }
}

fn decode_function(
    program: &LoadedProgram,
    seed: &Seed,
    options: &AnalysisOptions,
    bits: u8,
    known_starts: &HashSet<u64>,
) -> Result<Option<DecodedFunction>> {
    let mut warnings = Vec::new();
    let mut blocks: BTreeMap<u64, DecodedBlock> = BTreeMap::new();
    let mut pending: VecDeque<u64> = VecDeque::new();
    let mut calls: BTreeSet<u64> = BTreeSet::new();
    pending.push_back(seed.address);
    let mut instruction_total = 0u64;

    while let Some(block_start) = pending.pop_front() {
        if blocks.contains_key(&block_start) {
            continue;
        }
        if !program
            .section_at(block_start)
            .map(|section| section.executable && section.contains(block_start))
            .unwrap_or(false)
        {
            warnings.push(format!(
                "block target 0x{block_start:x} is outside executable data"
            ));
            continue;
        }
        if blocks.len() >= options.max_blocks_per_function {
            warnings.push(format!(
                "block limit ({}) reached",
                options.max_blocks_per_function
            ));
            break;
        }
        let Some(code) = program.code_slice(block_start) else {
            warnings.push(format!("no file-backed code at 0x{block_start:x}"));
            continue;
        };
        let mut decoder = Decoder::with_ip(bits as u32, code, block_start, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        let mut cursor = block_start;
        let mut terminator = DecodedTerminator::Fallthrough(cursor);
        let mut block_ended = false;
        let mut block_bytes = 0u64;
        let mut suppress_successors = false;
        while decoder.can_decode() {
            if instruction_total >= options.max_instructions_per_function as u64 {
                warnings.push(format!(
                    "instruction limit ({}) reached",
                    options.max_instructions_per_function
                ));
                terminator = DecodedTerminator::Unreachable;
                block_ended = true;
                break;
            }
            let instruction = decoder.decode();
            if instruction.is_invalid() || instruction.len() == 0 {
                warnings.push(format!("invalid instruction at 0x{:x}", instruction.ip()));
                terminator = DecodedTerminator::Unreachable;
                block_ended = true;
                break;
            }
            if instruction_total % 512 == 0 {
                if options.stop_requested() {
                    warnings.push(format!(
                        "decoding stopped at 0x{:x}: cooperative stop requested",
                        instruction.ip()
                    ));
                    terminator = DecodedTerminator::Unreachable;
                    block_ended = true;
                    break;
                }
                options.cooperative_point();
            }
            let bytes = match program.read_virtual(instruction.ip(), instruction.len()) {
                Some(bytes) => bytes,
                None => {
                    warnings.push(format!(
                        "instruction at 0x{:x} crosses section data",
                        instruction.ip()
                    ));
                    terminator = DecodedTerminator::Unreachable;
                    block_ended = true;
                    break;
                }
            };
            let text = format_instruction(&instruction);
            let next = instruction.ip() + instruction.len() as u64;
            cursor = next;
            block_bytes += instruction.len() as u64;
            instruction_total += 1;
            let flow = instruction.flow_control();
            let record = DecodedInstruction {
                instruction,
                text,
                bytes,
            };
            // Normalize call targets that iced records as branch operands.
            if matches!(flow, FlowControl::Call | FlowControl::IndirectCall)
                && instruction.op_count() > 0
                && instruction.op_kind(0) == OpKind::NearBranch64
            {
                let target = instruction.near_branch_target();
                if target != 0 {
                    calls.insert(target);
                }
            }
            instructions.push(record);
            // Bound pathological blocks made only of prefixes/nops.
            if instructions.len() > 100_000 || block_bytes > 8 * 1024 * 1024 {
                warnings.push(format!(
                    "block at 0x{block_start:x} exceeded the size limit"
                ));
                terminator = DecodedTerminator::Unreachable;
                block_ended = true;
                break;
            }
            // A direct call whose return address equals its target never
            // returns here: it is a tail call and the function ends.
            if flow == FlowControl::Call
                && instruction.op_count() > 0
                && instruction.op_kind(0) == OpKind::NearBranch64
                && instruction.near_branch_target() == next
            {
                terminator = DecodedTerminator::TailCall(instruction.near_branch_target());
                block_ended = true;
                break;
            }
            match flow {
                FlowControl::UnconditionalBranch => {
                    let target = instruction.near_branch_target();
                    if instruction.op_kind(0) == OpKind::NearBranch64 {
                        // A jump into a known function entry is a tail jump;
                        // do not follow it and swallow the target function.
                        if target != seed.address && known_starts.contains(&target) {
                            suppress_successors = true;
                        }
                        terminator = DecodedTerminator::Jump(target);
                    } else {
                        terminator = DecodedTerminator::IndirectJump;
                    }
                    block_ended = true;
                    break;
                }
                FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => {
                    let target = instruction.near_branch_target();
                    if instruction.op_kind(0) == OpKind::NearBranch64 {
                        terminator = DecodedTerminator::Conditional {
                            mnemonic: instruction.mnemonic(),
                            target,
                            fallthrough: cursor,
                        };
                    } else {
                        terminator = DecodedTerminator::Unreachable;
                    }
                    block_ended = true;
                    break;
                }
                FlowControl::Return => {
                    terminator = DecodedTerminator::Return;
                    block_ended = true;
                    break;
                }
                FlowControl::Exception | FlowControl::Interrupt => {
                    terminator = DecodedTerminator::Unreachable;
                    block_ended = true;
                    break;
                }
                FlowControl::IndirectBranch => {
                    terminator = DecodedTerminator::IndirectJump;
                    block_ended = true;
                    break;
                }
                _ => {}
            }
        }
        if !block_ended {
            terminator = DecodedTerminator::Fallthrough(cursor);
        }
        let successors = if suppress_successors {
            Vec::new()
        } else {
            terminator_successors(&terminator)
        };
        let block = DecodedBlock {
            start: block_start,
            end: cursor,
            instructions,
            terminator,
        };
        blocks.insert(block_start, block);
        for successor in successors {
            if program
                .section_at(successor)
                .map(|section| section.executable)
                .unwrap_or(false)
                && !blocks.contains_key(&successor)
            {
                pending.push_back(successor);
            }
        }
    }

    if blocks.is_empty() {
        return Ok(None);
    }
    let blocks = split_overlapping_blocks(blocks);
    let instruction_count: u64 = blocks
        .values()
        .map(|block| block.instructions.len() as u64)
        .sum();
    let blocks: Vec<DecodedBlock> = blocks.into_values().collect();
    let mut name = seed.name.clone();
    if name.trim().is_empty() {
        name = format!("FUN_{:x}", seed.address);
    }
    Ok(Some(DecodedFunction {
        address: seed.address,
        name,
        discovery: seed.discovery.clone(),
        confidence: seed.confidence,
        blocks,
        calls: calls.into_iter().collect(),
        warnings,
        instruction_count,
    }))
}

/// Recursive descent can decode a branch target as part of an earlier block
/// when the target is reached only later. Split such blocks at the target so
/// every basic block has a single entry and the CFG is faithful.
fn split_overlapping_blocks(
    mut blocks: BTreeMap<u64, DecodedBlock>,
) -> BTreeMap<u64, DecodedBlock> {
    loop {
        let mut targets: BTreeSet<u64> = blocks.keys().copied().collect();
        for block in blocks.values() {
            targets.extend(terminator_successors(&block.terminator));
        }
        let mut split: Option<(u64, u64)> = None;
        'search: for block in blocks.values() {
            if let Some(target) = targets
                .iter()
                .find(|target| **target > block.start && **target < block.end)
                && block
                    .instructions
                    .iter()
                    .any(|item| item.instruction.ip() == *target)
            {
                split = Some((block.start, *target));
                break 'search;
            }
        }
        let Some((start, target)) = split else {
            break;
        };
        let Some(mut block) = blocks.remove(&start) else {
            break;
        };
        let Some(index) = block
            .instructions
            .iter()
            .position(|item| item.instruction.ip() == target)
        else {
            blocks.insert(start, block);
            break;
        };
        let tail_instructions = block.instructions.split_off(index);
        let original_terminator = block.terminator.clone();
        let original_end = block.end;
        block.end = target;
        block.terminator = DecodedTerminator::Fallthrough(target);
        blocks.insert(start, block);
        // A block at the split point may already have been decoded through
        // another predecessor. Keep the existing block when it exists; both
        // decode the same instruction stream from the same address.
        blocks.entry(target).or_insert(DecodedBlock {
            start: target,
            end: original_end,
            instructions: tail_instructions,
            terminator: original_terminator,
        });
    }
    blocks
}

fn terminator_successors(terminator: &DecodedTerminator) -> Vec<u64> {
    match terminator {
        DecodedTerminator::Fallthrough(target) => vec![*target],
        DecodedTerminator::Jump(target) => vec![*target],
        DecodedTerminator::Conditional {
            target,
            fallthrough,
            ..
        } => vec![*target, *fallthrough],
        _ => Vec::new(),
    }
}

fn format_instruction(instruction: &Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_uppercase_hex(false);
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);
    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
}

fn listing_blocks(decoded: &DecodedFunction) -> Vec<BlockAnalysis> {
    let mut output = Vec::with_capacity(decoded.blocks.len());
    for (id, block) in decoded.blocks.iter().enumerate() {
        let instructions = block
            .instructions
            .iter()
            .map(|item| listing_instruction(&item.instruction, &item.text, &item.bytes))
            .collect();
        let (terminator, condition) = match &block.terminator {
            DecodedTerminator::Fallthrough(_) => ("fallthrough".to_owned(), None),
            DecodedTerminator::Jump(_) => ("jump".to_owned(), None),
            DecodedTerminator::Conditional { mnemonic, .. } => (
                "conditional".to_owned(),
                Some(format!("{mnemonic:?}").to_ascii_lowercase()),
            ),
            DecodedTerminator::Return => ("return".to_owned(), None),
            DecodedTerminator::IndirectJump => ("indirect_jump".to_owned(), None),
            DecodedTerminator::TailCall(target) => {
                ("tail_call".to_owned(), Some(format!("0x{target:x}")))
            }
            DecodedTerminator::Unreachable => ("unreachable".to_owned(), None),
        };
        output.push(BlockAnalysis {
            id: id as u32,
            start: block.start,
            end: block.end,
            successors: terminator_successors(&block.terminator),
            terminator,
            condition,
            instructions,
        });
    }
    output
}

fn listing_instruction(instruction: &Instruction, text: &str, bytes: &[u8]) -> ListingInstruction {
    let flow = format!("{:?}", instruction.flow_control()).to_ascii_lowercase();
    let call_target = if matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) && instruction.op_count() > 0
        && instruction.op_kind(0) == OpKind::NearBranch64
    {
        Some(instruction.near_branch_target())
    } else {
        None
    };
    let branch_target = if matches!(
        instruction.flow_control(),
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
    ) && instruction.op_count() > 0
        && instruction.op_kind(0) == OpKind::NearBranch64
    {
        Some(instruction.near_branch_target())
    } else {
        None
    };
    let memory_reference = if instruction.is_ip_rel_memory_operand() {
        Some(instruction.ip_rel_memory_address())
    } else {
        None
    };
    let unsupported = !supported_mnemonic(instruction.mnemonic());
    let operands = text
        .split_once(' ')
        .map(|(_, operands)| operands.to_owned())
        .unwrap_or_default();
    let mnemonic = format!("{:?}", instruction.mnemonic()).to_ascii_lowercase();
    ListingInstruction {
        address: instruction.ip(),
        size: instruction.len() as u8,
        bytes: bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        text: text.to_owned(),
        mnemonic,
        operands,
        flow,
        call_target,
        branch_target,
        memory_reference,
        unsupported,
    }
}

fn supported_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Mov
            | Mnemonic::Lea
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Imul
            | Mnemonic::Mul
            | Mnemonic::Idiv
            | Mnemonic::Div
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Not
            | Mnemonic::Neg
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Movzx
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Nop
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Leave
            | Mnemonic::Ret
            | Mnemonic::Call
            | Mnemonic::Jmp
            | Mnemonic::Cdqe
            | Mnemonic::Cwde
            | Mnemonic::Cdq
            | Mnemonic::Cqo
            | Mnemonic::Endbr64
            | Mnemonic::Setne
            | Mnemonic::Sete
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jrcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jcxz
    )
}

fn collect_block_xrefs(function: u64, block: &DecodedBlock, xrefs: &mut BTreeSet<Xref>) {
    for item in &block.instructions {
        let instruction = &item.instruction;
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) && instruction.op_count() > 0
            && instruction.op_kind(0) == OpKind::NearBranch64
        {
            let target = instruction.near_branch_target();
            xrefs.insert(Xref {
                from: instruction.ip(),
                to: target,
                kind: "call".to_owned(),
                function: Some(function),
            });
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
        ) && instruction.op_count() > 0
            && instruction.op_kind(0) == OpKind::NearBranch64
        {
            let target = instruction.near_branch_target();
            xrefs.insert(Xref {
                from: instruction.ip(),
                to: target,
                kind: "jump".to_owned(),
                function: Some(function),
            });
        }
        if instruction.is_ip_rel_memory_operand() {
            xrefs.insert(Xref {
                from: instruction.ip(),
                to: instruction.ip_rel_memory_address(),
                kind: "data".to_owned(),
                function: Some(function),
            });
        }
    }
    for successor in terminator_successors(&block.terminator) {
        xrefs.insert(Xref {
            from: block.end,
            to: successor,
            kind: "jump".to_owned(),
            function: Some(function),
        });
    }
}

fn lift_ir(decoded: &DecodedFunction, id: u32) -> ir::Function {
    let mut function = ir::Function {
        id,
        name: decoded.name.clone(),
        address: Some(decoded.address),
        entry: Some(0),
        blocks: Vec::new(),
        parameters: None,
        confidence: decoded.confidence,
        metadata: BTreeMap::new(),
    };
    function
        .metadata
        .insert("discovery".to_owned(), decoded.discovery.clone());
    function.metadata.insert(
        "instruction_count".to_owned(),
        decoded.instruction_count.to_string(),
    );
    let block_ids: HashMap<u64, u32> = decoded
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index as u32))
        .collect();
    for (index, block) in decoded.blocks.iter().enumerate() {
        let mut ir_block = ir::BasicBlock {
            id: index as u32,
            instructions: Vec::new(),
            terminator: ir::Terminator::Unreachable,
            address: Some(block.start),
        };
        for item in &block.instructions {
            let instruction = &item.instruction;
            let op = lift_op(instruction.mnemonic());
            let operands = lift_operands(instruction);
            ir_block.instructions.push(ir::Instruction {
                address: Some(instruction.ip()),
                op,
                operands,
                result: None,
            });
        }
        ir_block.terminator = match &block.terminator {
            DecodedTerminator::Fallthrough(target) => block_ids
                .get(target)
                .map(|target| ir::Terminator::Fallthrough(*target))
                .unwrap_or(ir::Terminator::Fallthrough(0)),
            DecodedTerminator::Jump(target) => block_ids
                .get(target)
                .map(|target| ir::Terminator::Jump(*target))
                .unwrap_or(ir::Terminator::Unreachable),
            DecodedTerminator::Conditional {
                target,
                fallthrough,
                ..
            } => {
                let then_block = block_ids.get(target).copied().unwrap_or(0);
                let else_block = block_ids.get(fallthrough).copied().unwrap_or(0);
                ir::Terminator::Branch {
                    condition: 0,
                    then_block,
                    else_block,
                }
            }
            DecodedTerminator::Return => ir::Terminator::Return(None),
            DecodedTerminator::TailCall(_) => ir::Terminator::Return(None),
            DecodedTerminator::IndirectJump | DecodedTerminator::Unreachable => {
                ir::Terminator::Unreachable
            }
        };
        function.blocks.push(ir_block);
    }
    function
}

fn lift_op(mnemonic: Mnemonic) -> ir::Op {
    match mnemonic {
        Mnemonic::Nop => ir::Op::Nop,
        Mnemonic::Mov | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movzx => ir::Op::Mov,
        Mnemonic::Lea => ir::Op::Lea,
        Mnemonic::Add => ir::Op::Add,
        Mnemonic::Sub => ir::Op::Sub,
        Mnemonic::Imul | Mnemonic::Mul => ir::Op::Mul,
        Mnemonic::Div => ir::Op::Div,
        Mnemonic::Idiv => ir::Op::Div,
        Mnemonic::And | Mnemonic::Test => ir::Op::And,
        Mnemonic::Or => ir::Op::Or,
        Mnemonic::Xor => ir::Op::Xor,
        Mnemonic::Not => ir::Op::Not,
        Mnemonic::Shl | Mnemonic::Sal => ir::Op::Shl,
        Mnemonic::Shr => ir::Op::Shr,
        Mnemonic::Sar => ir::Op::Sar,
        Mnemonic::Cmp => ir::Op::Cmp,
        Mnemonic::Call => ir::Op::Call,
        Mnemonic::Neg => ir::Op::Unknown("neg".to_owned()),
        other => ir::Op::Unknown(format!("{other:?}").to_ascii_lowercase()),
    }
}

fn lift_operands(instruction: &Instruction) -> Vec<ir::Operand> {
    let mut operands = Vec::new();
    for index in 0..instruction.op_count() {
        match instruction.op_kind(index) {
            OpKind::Register => {
                operands.push(ir::Operand::Register(
                    format!("{:?}", instruction.op_register(index)).to_ascii_lowercase(),
                ));
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                operands.push(ir::Operand::Address(instruction.near_branch_target()));
            }
            OpKind::Memory => {
                operands.push(ir::Operand::Memory(Box::new(ir::MemoryOperand {
                    base: register_name(instruction.memory_base()),
                    index: register_name(instruction.memory_index()),
                    scale: instruction.memory_index_scale(),
                    displacement: instruction.memory_displacement64(),
                    size: instruction.memory_size().size() as u16,
                })));
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                operands.push(ir::Operand::Immediate(instruction.immediate(index) as i64));
            }
            _ => {}
        }
    }
    operands
}

fn register_name(register: Register) -> Option<String> {
    if register == Register::None {
        None
    } else {
        Some(format!("{register:?}").to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_empty_analysis_limits_cleanly() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("empty.exe");
        fs::write(&path, b"").unwrap();
        assert!(analyze_path(&path, &AnalysisOptions::default()).is_err());
    }

    #[test]
    fn prologue_detection_requires_known_shapes() {
        let mut decoder =
            Decoder::with_ip(64, &[0x55, 0x48, 0x89, 0xe5], 0x1000, DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert!(is_prologue_start(&instruction));
        let mut decoder = Decoder::with_ip(64, &[0x90], 0x1000, DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert!(!is_prologue_start(&instruction));
    }
}
