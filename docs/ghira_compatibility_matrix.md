# GHIRA / Ghidra Compatibility Matrix

Updated: 2026-11-04

This matrix records what GHIRUST actually implements and how it was validated.
States and promotion rules are at the bottom. All comparison evidence cited
here was produced by `tests/objectives/tools/compare.py` against Ghidra 12.2
PUBLIC and JDK 25, and is stored under `tests/objectives/results/`. Local
installation paths are intentionally omitted.

States: `NOT_IMPLEMENTED`, `IN_PROGRESS`, `IMPLEMENTED`, `TESTED`,
`VERIFIED_COMPATIBLE`, `NOT_APPLICABLE`.

| Capability | Ghidra reference (representative) | GHIRUST implementation | State | Evidence and limits |
|---|---|---|---|---|
| PE loading and metadata | Ghidra loader infrastructure; `Ghidra/Features/FileFormats` | `ghirust-core/src/loader.rs` via `object` 0.37 | `VERIFIED_COMPATIBLE` | Side-by-side on 4 PE DLLs (`tests/objectives/results/*/comparison.json`). `demo.dll`: sections 5/5 common, imports 17/17 exact, exports 6/6 common, entry RVAs comparable, strings 32 common. Ghidra additionally defines header/`.bss` blocks GHIRUST reports as sections only. Scope: PE x86-64 metadata. |
| ELF loading | Same loader infrastructure | `loader.rs` via `object` | `IMPLEMENTED` | Backend compiles; no ELF objective fixture or comparison exists yet. |
| Mach-O loading | Same loader infrastructure | `loader.rs` via `object` | `IMPLEMENTED` | Backend only; no Mach-O fixture analyzed. |
| WebAssembly loading | Ghidra WASM loader modules | `loader.rs` via `object` | `IMPLEMENTED` | Metadata loading only; no WASM disassembly/decompilation. |
| x86 / x86-64 instruction decoding | `Ghidra/Processors/x86` | `analysis.rs` using `iced-x86` 1.22 | `TESTED` | On the 53 common functions of `demo.dll`: 875/875 instruction addresses agree, 778/875 mnemonics agree (89%). Mismatches are documented aliases/operand-style differences. |
| Function discovery | Auto-analysis managers | `analysis.rs`: entry/exports/symbols/calls/branches/prologues seeds, recursive call-target worklist, tail-call stops, block-interval overlap | `TESTED` | `demo.dll`: Ghidra 57 vs GHIRUST 57 functions, 53 common addresses (4 only Ghidra: guard thunks reached via indirect tables; 4 only GHIRUST: shared-epilogue fragments, `jump` discovery, 60% confidence). Larger Rust/C++ DLLs: GHIRUST over-recovers (468 vs 385, 461 vs 444). |
| Basic-block / CFG recovery | Ghidra program model and decompiler CFG | `analysis.rs` recursive descent, block splitting, tail-call/jump normalization | `TESTED` | On `demo.dll` matched functions: 242/249 Ghidra CFG edges common; GHIRUST has 253. `cfg_blocks_are_well_formed_and_successors_are_reachable` enforces block invariants on every recovered function. |
| Cross-references | Ghidra reference manager | `analysis.rs` call/jump/data/string xrefs | `TESTED` | Real fixture xrefs recorded and asserted by address and kind. Data/string references are approximate. |
| GUIR / intermediate representation | Ghidra p-code | `ir.rs` + lifting in `analysis.rs` | `IMPLEMENTED` | Validation and JSON roundtrip tests pass. It is not Ghidra p-code and has no semantic equivalence test. |
| C-like pseudocode reconstruction | `Ghidra/Features/Decompiler` | `pseudocode.rs` heuristic expression/statement reconstruction | `IN_PROGRESS` | Objective assertions pass for the exported functions of `demo.dll` and `demo_features.dll`. Auto-vectorized SSE code is reported as unsupported, never guessed. No semantic equivalence test against Ghidra output. |
| Parameter and return-type recovery | Ghidra decompiler calling conventions | `pseudocode.rs` Win64/SysV register mapping, used-parameter pruning | `IN_PROGRESS` | Used parameters reconstructed for `demo_add`, `demo_classify`, `demo_fact`. No aggregate/pointer type recovery. |
| Data-flow and type analysis | Ghidra decompiler data-flow | Expression environment in `pseudocode.rs` | `IN_PROGRESS` | Straight-line and loop-carried data flow; no SSA, alias analysis or struct recovery. |
| Persistent projects | `Ghidra/Framework/Project`, `ProgramDB` | `project.rs` | `TESTED` | Import/analyze/reopen/overrides/sessions/duplicates/recovery covered by unit tests. |
| User renames, comments, types, bookmarks | Ghidra program database annotations | `project.rs` `UserOverrides` | `TESTED` | Overlay applied over saved analysis; roundtrip tested. |
| Saved sessions | Ghidra tool state | `project.rs` `SessionState` | `TESTED` | Save/list/load/path-traversal rejection tested. |
| Project integrity verification | Ghidra project consistency | `project.rs` `verify()` | `TESTED` | SHA-256 checks; CLI rejects mismatched saved analyses. |
| Native desktop CodeBrowser | Ghidra CodeBrowser tool | `ghirust/crates/ghirust-gui` (see the dedicated rows below for the reorganized layout) | `IMPLEMENTED` | Listing, pseudocode, summary, symbols, xrefs, warnings and layered CFG graph against the real analysis. Task API tested; no visual automation. |
| CFG graph view | Ghidra function graph | `render_cfg_graph` in `ghirust-gui` | `IMPLEMENTED` | Layered BFS layout, limited to 200 blocks. |
| Whole-program call graph | Ghidra graph services | None | `NOT_IMPLEMENTED` | Calls stored per function and as xrefs; no call-graph visualization. |
| Search over indexed exported text | Ghidra search plugins | `index.rs`, `search.rs`, GUI search | `TESTED` | 12 search tests; searches exports, not live program memory. |
| Streaming export | Ghidra exporters | `export.rs` | `TESTED` | 10 integration tests; one opt-in >100 MiB synthetic test. |
| Persistent scan cache | Ghidra cached artifacts | `cache.rs` | `TESTED` | Persistence/eviction/truncation/corruption covered. |
| String extraction | `DefinedStringsPlugin` | `strings.rs` | `TESTED` | ASCII/UTF-16 extraction tests. Compared against Ghidra defined strings: 32 common values; GHIRUST scans raw bytes and finds more (105 vs 34). |
| Benchmark harness | Ghidra analysis timing (not an official API) | `ghirust benchmark` CLI | `TESTED` | Measured samples stored under `tests/objectives/benchmarks/` and `tests/objectives/results/*/ghirust.benchmark.json`. |
| Ghidra headless bridge | Headless analyzer and `DecompInterface` | `tests/objectives/ghidra/ExportProgram.java` + PowerShell runner | `TESTED` | Executed end to end with Ghidra 12.2: program, memory, imports, functions with blocks/instructions/edges, decompiled C and strings exported as NDJSON for 4 DLLs. |
| Automated Ghidra vs GHIRUST comparison | Not a Ghidra feature | `tests/objectives/tools/compare.py` | `TESTED` | Four reproducible comparisons stored in `tests/objectives/results/` with normalized RVAs, per-function instruction/block/edge tables and Markdown reports. |
| Ghidra behavioral equivalence | Decompiler and program-model behavior | None | `NOT_IMPLEMENTED` | Side-by-side data exists for 4 fixtures; full behavioral equivalence (types, structs, semantics) is not verified. |
| Large-binary comparison | Ghidra large-program workflows | None | `NOT_IMPLEMENTED` | No 30 MB DLL or >100 MB decompilation input available. |
| GUI localization | Ghidra localization resources | `tr()` in `ghirust-gui` | `IN_PROGRESS` | Navigation, CodeBrowser tabs and key panels localized (pt-PT, pt-BR, en-US, ru-RU); menu and panel contents partial. |
| Resource budget and reservations | Ghidra does not expose an equivalent API | `ghirust-core/src/resources.rs`: `ResourceManager`, `Reservation` (RAII), budgets, safety floors | `TESTED` | 10 unit tests: RAM cap, task cap, pressure admission, recovery, release-on-drop, safety floors. CLI `--profile`/`--max-threads`/`--max-ram-mb` verified on real DLLs. |
| CPU scheduling with priorities | Ghidra background task management | `CpuPool` + GUI task priorities (`CRITICAL_UI`..`BACKGROUND`) | `TESTED` | Priority order, pause/resume, cancellation of queued jobs and bounded-queue backpressure covered by unit tests; GUI task-priority plumbing covered by API tests. |
| Adaptive pressure protection | Ghidra does not expose an equivalent API | `PressureState` (`NORMAL`..`RECOVERY`) + cooperative throttle/stop in analysis loops | `TESTED` | Deterministic state transitions tested with injected metrics; cooperative stops wired into the sweep and decode loops (checked every 512 instructions). |
| Real telemetry (CPU/RAM) | Ghidra `SystemInfo`-style monitors | `ghirust-core/src/telemetry.rs` via `sysinfo` | `TESTED` | Unit tests assert real system values; GUI Resource Monitor shows CPU %, process RAM, budgets and reservations. |
| GPU telemetry and VRAM | Not a Ghidra feature | None | `NOT_IMPLEMENTED` | No GPU backend and no NVML/DXGI; the GUI renders GPU/VRAM as `Unavailable`, never estimates. |
| Project Window | Ghidra Project Window | `Screen::Project` in `ghirust-gui` | `IMPLEMENTED` | Toolbar, Tool Chest (unavailable tools disabled), Active Project tree/table with filter, Running Tools, status bar; project store read/write via `ghirust_core::project`. No visual automation. |
| Analysis Options dialog | Ghidra Analysis Options | `AnalysisForm` in `ghirust-gui` | `IMPLEMENTED` | Analyzer checklist with descriptions, Quick/Standard/Deep presets, function limit, resource profile, Select All/Deselect/Reset/Analyze/Cancel; maps to real `AnalysisOptions`. |
| CodeBrowser layout (Listing + Decompile side by side) | Ghidra CodeBrowser | Reorganized CodeBrowser with left tabs (Functions/Symbols/Program Trees/Data Types), center Listing with Back/Forward/Go-to, right Decompile, bottom Tasks/Console/Summary/Graph/Xrefs/Resource Monitor/Problems | `IMPLEMENTED` | Works against the real analysis; navigation history functional. No automated layout tests. |
| Search For Strings window | Ghidra `Search → For Strings...` | `Search For Strings` window | `IMPLEMENTED` | Minimum length, UTF-16, deduplicate, filter, CSV export; reuses `extract_strings`. |
| Task Manager | Ghidra Task dialog | Task panel: label, status, priority, elapsed, stage, cancellation | `IMPLEMENTED` | Real task states from the task runner; cancellation only where the core supports it. |
| Resource Monitor | Not a Ghidra feature | Resource Monitor panel/window with CPU/RAM/budgets/reservations and sparkline history | `IMPLEMENTED` | Real measurements only; GPU unavailable. |
| Resource Settings | Not a Ghidra feature | Resource Settings window (profile + limits), persisted | `IMPLEMENTED` | Limits applied by the manager, not just displayed; safety floors enforced. |
| GUI screen state machine | Not a Ghidra feature (Ghidra workspace switching) | `Screen`/`ImportFlow`/`FlowAction`/`TransitionReason` in `ghirust-gui` | `TESTED` | Unit tests cover inspection → options → analysis → CodeBrowser, stale-task handling, duplicate refusal, cancel and close-program flows. No visual automation. |
| GUI centralized theme | Ghidra look and feel | `theme::Palette` (Dark/Light) in `ghirust-gui` | `IMPLEMENTED` | Semantic tokens only; pressure states and component colors mapped through the palette; dark/light contrast tested. |
| Program Search (implemented modes) | Ghidra `Search` menu | `ghirust-core/src/program_search.rs` + Program Search screen in `ghirust-gui` | `TESTED` | 11 tests over the real objective DLL for implemented modes; results navigate to CodeBrowser; max-results truncation reported; Index scope and Search & Replace not implemented (labelled). |
| Native C++ acceleration | Ghidra native components | None | `NOT_APPLICABLE` | No measured hotspot justifies a C++ component. No C++ performance claim. |
| GPU acceleration | Not a Ghidra feature | None | `NOT_APPLICABLE` | No measured workload and no GPU backend. No GPU claim. |
| Multi-architecture decoding | Ghidra processor modules | x86/x86-64 only | `NOT_IMPLEMENTED` | Other architectures detected/loaded but not decoded. |
| C++ name demangling | `Ghidra/Features/GnuDemangler`, Microsoft demangler | None | `NOT_IMPLEMENTED` | `demo_cpp.dll` comparison: Ghidra demangles `cpp_scale` overloads; GHIRUST reports raw mangled export names. |

## Promotion rules

1. `TESTED` requires automated tests on real fixtures, executed and recorded.
2. `VERIFIED_COMPATIBLE` requires a real side-by-side Ghidra comparison whose
   stored artifacts support the stated scope. Currently only PE metadata
   loading meets that bar.
3. Performance numbers are recorded with hardware, command lines, input hashes
   and run counts; numbers from other machines are never copied in.
4. Unsupported instructions and heuristic limits stay visible in analysis
   warnings; they are never treated as successful decompilation.
