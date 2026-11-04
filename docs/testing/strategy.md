# Testing Strategy

GHIRUST distinguishes four kinds of evidence:

1. **Unit tests** for parsers, invariants and pure algorithms.
2. **Integration tests** for real files, the project store, the GUI task API and
   CLI-visible workflows.
3. **Objective tests** against a binary compiled from known source, so recovered
   functions and pseudocode can be checked against intended behavior.
4. **Measured benchmarks** recorded with the exact command, input hash and
   environment.

The project does not treat a successful compilation, a plausible screenshot or a
copied number as validation.

## Test suites

| Suite | Location | What it proves |
|---|---|---|
| Core unit tests | `ghirust/crates/ghirust-core/src/**` | Cache, detection, IR validation, pseudocode helpers, analysis limits, project persistence and recovery, resource safety and program search |
| Export integration | `ghirust/crates/ghirust-core/tests/export.rs` | NDJSON/directory export, gzip, resume fingerprints, traversal rejection, bounded manifest streaming |
| Search integration | `ghirust/crates/ghirust-core/tests/search.rs` | Indexing, text/name/address/path search, limits, ordering, cache diagnostics |
| Objective binary | `ghirust/crates/ghirust-core/tests/real_binary.rs` | Real PE loading, function recovery, CFG invariants on every function, pseudocode assertions, JSON roundtrip |
| GUI task API | `ghirust/crates/ghirust-gui/tests/api.rs` | Background inspection, real analysis, indexing/search, export errors through the same API the window uses |
| Behavior harness | `tests/objectives/run_behavior.ps1` | Loads the fixture DLLs and checks the documented expected outputs of every export (50/50 checks) |
| Resource safety | `ghirust-core/src/resources.rs`, `telemetry.rs`, `ghirust-gui/tests/api.rs` | Budget refusals, RAII reservation release, pressure admission and recovery, pool priorities/pause/resume/cancel, safety floors, real telemetry values, no fabricated GPU metrics |
| Program search core | `ghirust-core/src/program_search.rs` | Bounded searches over a real `ProgramAnalysis`: program/decompiled text, labels, xrefs, scalars, strings, instruction patterns, exact matches, memory bytes, encoded strings, result truncation |
| Ghidra comparison | `tests/objectives/tools/compare.py` | Runs Ghidra 12.2 headless export and the real GHIRUST analysis on the same binary, normalizes to RVAs and compares metadata, functions, instructions, blocks, edges and decompiled text; artifacts stored in `tests/objectives/results/` |
| CLI smoke | manual/recorded runs | Project lifecycle, annotations, sessions, verification, saved-analysis hash rejection |

## Objective fixture policy

- The source is stored under `tests/objectives/source/`; four DLLs exist:
  `demo.dll` (Rust), `demo_features.dll` (Rust), `demo_cpp.dll` (C++),
  `demo_bridge.dll` (Rust↔C++ interop).
- Binaries are compiled from known source with the recorded toolchains
  (`build_fixtures.ps1`); `manifest.json` records compiler, flags, SHA-256,
  expected functions and result links.
- The Rust fixture is rebuilt during `real_binary` tests when the source is
  newer. A process-wide `OnceLock` serializes fixture construction to avoid
  concurrent Windows linker races.
- Tests assert only what the engine can actually recover. SSE/AVX limitations
  are asserted to be reported, not hidden.
- Ghidra output is stored only when a runnable Ghidra installation produced
  it; `tools/compare.py` never edits Ghidra exports.

## Current automated result

Command:

```powershell
cargo test --workspace
```

Result on 2026-11-04 (Windows, Rust MSVC toolchain):

| Target | Passed | Ignored |
|---|---:|---:|
| `ghirust-core` library unit tests | 54 | 0 |
| `export.rs` integration tests | 10 | 1 |
| `real_binary.rs` objective tests | 3 | 0 |
| `search.rs` integration tests | 12 | 0 |
| `ghirust-gui` library unit tests | 0 | 0 |
| `ghirust-gui` binary unit tests | 8 | 0 |
| `ghirust-gui` API integration tests | 6 | 0 |
| **Total** | **93** | **1** |

The ignored export test writes more than 100 MiB and is opt-in. It validates
streaming output assembly, not decompilation or peak process memory.

The GUI binary unit tests cover the screen state machine, the centralized theme
and the program-search state; the core library tests add the program-search and
telemetry/resource suites. No tests were skipped because of missing fixtures in
this run. The Ghidra comparisons run through `tools/compare.py` against the
installed Ghidra 12.2 and their artifacts are stored under
`tests/objectives/results/`.

## What is not covered

- Ghidra behavioral/semantic decompiler equivalence (side-by-side data exists;
  automatic semantic equivalence is not verified).
- Automated rendering/visual tests for egui panels and the CFG graph.
- ELF, Mach-O and WebAssembly objective fixtures and comparisons.
- Large real-world binaries (no 30 MB DLL available).
- Full CLI argument/output snapshot tests.
- Fuzzing of the loader or decoder.
- Disk-full, power-loss and antivirus-lock scenarios beyond the simulated
  backup/temporary-file recovery test.
- ARM/AArch64 decoding or decompilation.
- CPU/GPU scheduling or system telemetry.
