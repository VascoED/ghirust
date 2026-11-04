# Desktop CodeBrowser

The desktop application is a native eframe/egui window in
`ghirust/crates/ghirust-gui`. It runs the same analysis engine as the CLI.

## Screen state machine

The window owns an explicit state machine (`ghirust-gui/src/state.rs`):

- `Screen` — one of Project, Analysis, CodeBrowser, Functions, ProgramSearch,
  Search, Strings, Command Center, Settings. Only one screen renders content at
  a time; transitions always go through `transition_to(Screen, reason)`.
- `ImportFlow` — Idle → Inspecting → Options → Analyzing → (CodeBrowser on
  success). Stale task events (older task ids) are ignored; duplicate imports of
  the same binary are refused.
- `FlowAction` — OpenOptions, AnalysisReady, IgnoreStale, None.
- `TransitionReason` — UserAction, ImportStarted, ImportCancelled,
  AnalysisFinished, ProgramClosed, Navigation.

Closing a program clears binary, analysis, selection, navigation, search report
and the import flow, returning to the Project screen.

## Opening a binary

Opening a file (dialog or drag-and-drop) starts two background tasks:

1. **Inspect** — lightweight format detection and string extraction.
2. **Analyze** — full loader, disassembly, function/CFG recovery, xrefs and
   pseudocode reconstruction.

When the inspection task completes, the Analysis Options modal opens with the
file path and the Standard preset. `Analyze` starts the analysis task under the
chosen resource budget; when it finishes the window transitions to the
CodeBrowser. `Cancel` returns to the previous screen without starting an
analysis.

Opening a directory that is not a GHIRUST project store asks for confirmation
before indexing it as an exported-source project; it is never indexed silently.

## CodeBrowser layout

```text
┌──────────────────────┬─────────────────────────────────────────────┐
│ Function list        │ Listing | Pseudocode                        │
│ filter               │ selected function header                    │
│ 0x... name  N insn   │                                             │
│ ...                  │ disassembly blocks or reconstructed C       │
│                      ├─────────────────────────────────────────────┤
│                      │ Summary | CFG graph | Symbols | Xrefs |     │
│                      │ Strings | Warnings                          │
│                      │ filter + scrollable detail panel            │
└──────────────────────┴─────────────────────────────────────────────┘
```

### Function list

Every recovered function is shown with address, name and instruction count.
The filter matches names and hexadecimal addresses. Selecting a function updates
the listing, pseudocode and CFG graph.

### Listing

Instructions are grouped by basic block. Each block header shows the block ID,
start address, terminator and successor addresses. Instructions show address,
encoded bytes and Intel-syntax text. Unsupported instructions are prefixed with
`!` and colored yellow. Direct call/branch/data targets are annotated.

### Pseudocode

The panel shows the reconstructed signature and body. If instructions lacked a
semantic model, a limitation banner lists them and the warnings panel contains
the per-instruction diagnostics.

### CFG graph

A deterministic layered layout groups blocks by breadth-first depth from the
entry block. Edges are drawn from each block to its successors, so branches fan
out and loops appear as backward edges. The graph is limited to 200 blocks.

### Detail tabs

- **Summary** — loader metadata, section table, imports/exports/symbol/string
  counts and analysis statistics.
- **Symbols** — symbols with filters plus imports and exports.
- **Xrefs** — call/jump/data/string references with source and target names.
- **Strings** — extracted ASCII/UTF-16 strings with offsets and encodings.
- **Warnings** — program and selected-function diagnostics.

## Theme and colors

All widget colors come from the centralized semantic palette in
`ghirust/crates/ghirust-gui/src/theme.rs` (`Palette::dark` / `Palette::light`).
No UI code outside the module creates raw `Color32` values; semantic states
(resource pressure NORMAL/WARNING/HIGH_PRESSURE/CRITICAL/RECOVERY, unsupported
instructions, errors, success, selection) map to palette tokens.

## Program search

The dedicated Program Search screen runs bounded searches over a complete
`ProgramAnalysis` through `ghirust-core/src/program_search.rs`:

- **Program Text**, **Decompiled Text**, **Labels**, **Direct References**,
  **Scalars**, **Strings**, **Instruction Patterns**, **Matching
  Instructions**, **Memory** and **Encoded Strings (UTF-16LE only, partial)**.
- Each mode declares exactly what it searches; unsupported approaches are not
  offered (the menu entries that would need them stay disabled and labelled).
- Results are capped by `max_results`; hitting the cap sets `truncated` and the
  UI shows a truncation notice.
- Results navigate to the CodeBrowser address/function on click.

## Background tasks

`TaskManager` in `ghirust/crates/ghirust-gui/src/lib.rs` owns a worker thread per
operation and reports `Started`, `Progress`, `Completed`, `Failed` and
`Cancelled` events. The GUI drains events about every 150 ms. Errors carry a
machine-readable code, a human-readable message and a suggested action.

Cancellation is only offered for operations that check the cancellation token
at a safe stage boundary. Analysis, indexing and export are not interrupted
mid-operation; the UI states this instead of pretending to cancel instantly.

## Localization and theme

Navigation and CodeBrowser tab labels are translated for pt-PT, pt-BR, en-US
and ru-RU. Panel contents and error text are not fully localized yet. Theme
preferences (dark/light) and language are persisted by eframe storage.

## Build and run

From `ghirust/`:

```powershell
cargo run --locked -p ghirust-gui
cargo build --release --locked -p ghirust-gui
cargo test --locked -p ghirust-gui
```

On Windows the MSVC toolchain and Windows SDK are required. On Linux, eframe
needs an X11/Wayland backend and the desktop portal used by `rfd`.

## Validation limits

The GUI task API is covered by integration tests, including a real analysis of
the objective PE DLL. The rendered widgets, graph layout and desktop window
behavior are not covered by automated visual tests. No GPU or system telemetry
monitor is connected; unavailable metrics are labeled unavailable.
