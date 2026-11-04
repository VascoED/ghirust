# GHIRUST Development Status

Updated: 2026-11-04

Evidence-based status. Capability states follow the definitions in
[`docs/ghira_compatibility_matrix.md`](docs/ghira_compatibility_matrix.md).

## Resource safety (new in this increment)

- **`ResourceManager`** (`ghirust-core/src/resources.rs`): budgets, RAII
  reservations, `Conservative/Balanced/Performance/Custom` profiles,
  `NORMAL/WARNING/HIGH_PRESSURE/CRITICAL/RECOVERY` pressure states and
  safety floors that no configuration can disable.
- **`CpuPool`**: bounded, priority-aware pool with pause/resume and
  cooperative cancellation of queued jobs; bounded queue (backpressure).
- **Real telemetry** (`ghirust-core/src/telemetry.rs`, `sysinfo`): CPU %,
  system/process RAM, logical CPUs. GPU/VRAM are reported as `Unavailable`
  (no GPU backend, no NVML/DXGI) — never fabricated.
- **Engine integration**: `analyze_path_managed` holds a reservation, wires
  throttle/stop flags into the sweep and decode loops (cooperative points
  every 512 instructions); search runs on a bounded rayon pool
  (default `logical/2`, 1..=4) instead of every core.
- **GUI**: tasks reserve budgets with priorities and are refused with a
  structured `resource_limit_refused` error; Resource Monitor shows real
  CPU/RAM/budgets/reservations with sparkline history; Resource Settings
  persists and applies limits.
- **CLI**: `--profile conservative|balanced|performance`, `--max-threads N`,
  `--max-ram-mb N` on `analyze`/`benchmark`.

## GUI reorganization (Ghidra 12.2-style)

- **Project Window**: toolbar, Tool Chest, Active Project (tree/table,
  filter, per-program metadata), Running Tools, status bar. Opens real
  project stores and imports binaries.
- **Analysis Options**: analyzer checklist with descriptions, Quick/Standard/
  Deep presets, function limit, resource profile; maps to real options.
- **CodeBrowser**: left tabs (Functions/Symbols/Program Trees/Data Types),
  center Listing with Back/Forward/Go-to, right Decompile panel, bottom tabs
  (Tasks/Console/Summary/Graph/Xrefs/Resource Monitor/Problems).
- **Menus** (File/Edit/Project/Tools/Window/Help) with working commands;
  unimplemented entries are disabled and labelled.
- **Search For Strings** window (min length, UTF-16, deduplicate, filter,
  CSV export) and **Resource Settings** window.
- Documentation: `docs/architecture/{resource_management,cpu_scheduler,
  gpu_scheduler,memory_management,gui_architecture}.md`,
  `docs/testing/{resource_stress_tests,gui_validation}.md`.

## Verified project state

- Rust workspace under `ghirust/`: `ghirust-core` (loaders, x86/x86-64
  disassembly, function/CFG/xref recovery, GUIR lifting, heuristic pseudocode,
  projects, detection, strings, cache, indexing, search, streaming export),
  `ghirust-cli` and the native eframe/egui `ghirust-gui` CodeBrowser.
- **Ghidra 12.2 PUBLIC is validated.** Headless analysis runs with JDK
  25.0.4.1; `ExportProgram.java` exports program metadata, memory, imports,
  functions (blocks, instructions, CFG edges), decompiled C and strings as
  NDJSON.
- **Four real side-by-side comparisons** are stored under
  `tests/objectives/results/` for `demo.dll`, `demo_features.dll`,
  `demo_cpp.dll` and `demo_bridge.dll` (normalized RVAs, per-function
  instruction/block/edge tables, Markdown reports).
- Original Ghidra source under `ghira_original_source_code/` is used as an API
  reference only; nothing is copied into the Rust crates. `README` and
  `README_2.md` remain the original specification documents.

## Fixtures

| Fixture | Language | Compiler | Size | SHA-256 (short) |
|---|---|---|---|---|
| `demo.dll` | Rust | rustc 1.98.1 | 9,728 B | `8e333cc5…` |
| `demo_features.dll` | Rust | rustc 1.98.1, panic=abort | 116,736 B | `36af896e…` |
| `demo_cpp.dll` | C++ | MSVC 19.51.36260, /O2 /EHsc | 119,808 B | `ea8badac…` |
| `demo_bridge.dll` | Rust→C++→Rust interop | rustc 1.98.1 | 9,216 B | `17491795…` |

Sources, build commands, expected functions and result links are in
`tests/objectives/manifest.json`. `build_fixtures.ps1` rebuilds everything;
`run_behavior.ps1` loads the DLLs and checks the documented outputs:
**50/50 runtime checks passed** (`tests/objectives/results/behavior.json`).

## Real comparison results (Ghidra 12.2, 2026-11-04)

| Fixture | Ghidra functions | GHIRUST functions | Common addresses |
|---|---:|---:|---:|
| demo | 57 | 57 | 53 |
| demo_features | 385 | 468 | 327 |
| demo_cpp | 444 | 461 | 401 |
| demo_bridge | 55 | 52 | 49 |

`demo.dll` detail: 875/875 common instruction addresses, 778/875 mnemonic
agreement, 242/249 Ghidra CFG edges common, imports 17/17 exact, sections 5/5
common. Ghidra headless (import + auto-analysis + export): 36.6 s wall;
GHIRUST release: 8 ms median per run (3 runs). Full reports:
`tests/objectives/results/*/comparison.md`.

Documented asymmetries: GHIRUST jump seeds add shared-epilogue fragments
(weak `jump` discovery); Ghidra recovers guard thunks GHIRUST misses; Ghidra
demangles C++ names while GHIRUST reports mangled exports; GHIRUST string
extraction scans raw bytes and finds more strings.

## Function discovery improvements in this increment

Measured on `demo.dll` (before → after):

- Functions recovered: 19 → 57 (Ghidra: 57), common addresses 19 → 53.
- Instructions inside recovered functions: 442 → 898.

Mechanisms added:

1. Tail-call detection: `call` whose return address equals its target ends the
   function; `jmp` into a known function entry stops the walk.
2. Recursive call-target worklist: decoded functions contribute their direct
   call targets as new seeds.
3. Padding-aware sweep: `int3`/`nop` padding no longer resets the
   function-boundary state; `call` is treated as a thunk terminator.
4. Extended prologue patterns: `push` of any callee-saved register,
   `mov [rsp+disp], reg` spills.
5. Branch targets as low-confidence seeds (discovery `jump`, 60%).
6. Block-interval overlap (instead of full-span) so tail jumps no longer hide
   later functions.
7. Jumps into the interior of another function's block are normalized to
   `TailCall` terminators.

Regression tests cover the CFG invariants on every recovered function.

## Validation

- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — **93 passed, 1 ignored** (opt-in >100 MiB
  streaming export test). Core unit tests now include 10 resource-manager and
  2 telemetry tests; the new `program_search` suite adds 11 tests over the real
  objective DLL; the GUI binary unit tests add the state-machine, theme and
  search-state coverage; the GUI API suite includes resource-budget application.
- Release builds of `ghirust-cli` and `ghirust-gui` succeed.
- CLI smoke: `benchmark --profile conservative --max-threads 1` and
  `analyze --profile balanced` complete under their budgets.
- GUI smoke: import flow state machine, theme palette, program search and task
  API tests green in `cargo test --workspace -p ghirust-gui`.

## GUI interface increment (state machine, theme, program search)

- **Screen state machine**: `Screen` (Project, Analysis, CodeBrowser, Functions,
  ProgramSearch, Search, Strings, Command Center, Settings), `ImportFlow`
  (Idle/Inspecting/Options/Analyzing), `FlowAction` and `TransitionReason` live
  in `ghirust-gui/src/state.rs`; transitions go through
  `transition_to(Screen, reason)`, stale task results are ignored, duplicate
  imports are refused, cancel returns to the previous screen, close program
  clears program-bound state.
- **Theme**: centralized `theme::Palette` (Dark/Light) with semantic tokens
  (background, panel, surface, border, text, accent, selection, success,
  warning, error, info, link, code background, pressure colors); applied through
  `egui::Visuals`/`style`; no raw colors outside the module.
- **Program Search**: dedicated screen running bounded searches over the real
  `ProgramAnalysis` (`program_search` module): Program Text, Decompiled Text,
  Labels, Direct References, Scalars, Strings, Instruction Patterns, Matching
  Instructions, Memory, Encoded Strings (UTF-16LE, partial); max-results
  truncation reported; results navigate to CodeBrowser.
- **Import flow**: binary import starts inspection → Analysis Options →
  (Analyze → CodeBrowser); Cancel cancels without starting analysis; Open
  Project of a non-project folder asks for confirmation before indexing.

## Known blockers and missing validation

1. **Behavioral decompiler equivalence.** Side-by-side decompiled C is stored,
   but semantic equivalence (types, structs, control structure) against Ghidra
   is not verified. Pseudocode remains heuristic.
2. **Guard thunks and indirect call tables.** `__guard_check_icall`,
   `_guard_dispatch_icall` style functions are not recovered (indirect
   references).
3. **No large binary.** No 30 MB DLL or >100 MB decompilation input; all
   fixtures are < 120 KB.
4. **Peak memory is not measured** by the comparison tool (no psutil
   integration); recorded as unavailable, never invented.
5. **GPU backend and GPU telemetry.** Not implemented; rendered unavailable.
6. **GUI visual automation.** Layout/resizing behavior has no automated
   visual tests (manual validation documented in
   `docs/testing/gui_validation.md`).
7. **C++ demangling** is not implemented.
8. **Per-artifact cache budgets** (disassembly/pseudocode/CFG/strings) — a
   single cache limit exists today.
9. Only x86/x86-64 machine code is decoded.

## Next priorities

1. Per-artifact cache budgets and peak-memory capture in the comparison
   harness.
2. Improve decompiler structure recovery (switch tables, struct access, tail
   call merging) using the stored comparison reports as acceptance criteria.
3. Demangle C++ export names (matching the stored `demo_cpp` comparison).
4. Add ELF/Mach-O fixtures and comparisons once fixtures exist.
5. Obtain a large real DLL and record a measured benchmark with peak memory.
6. Implement a GPU backend only with a measurable advantage and full
   VRAM budgeting (see `docs/architecture/gpu_scheduler.md`).
