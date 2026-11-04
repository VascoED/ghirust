# GUI Validation

## Automated

`ghirust-gui` (binary unit tests in `src/main.rs`) and `ghirust-gui/tests/api.rs`
exercise the task API and the UI state machine the window uses:

- import/analysis flow machine (`state.rs`): inspection → Analysis Options →
  Analyze → CodeBrowser transitions, stale-task rejection, duplicate import
  refusal, cancel and close-program reset.
- theme (`theme.rs`): dark/light palettes with readable text tokens and
  semantic pressure colors.
- program search core (`ghirust-core/src/program_search.rs`): 11 tests over the
  real objective DLL (program text, decompiled text, labels/addresses, xrefs,
  scalars, strings, instruction patterns, exact matching, memory bytes, encoded
  strings, result truncation).
- task API tests: inspection, real analysis of the objective DLL, indexing,
  search, export, errors, and resource-budget application.

`cargo build --release -p ghirust-gui` and `cargo test --workspace` must succeed;
the full workspace suite is green with real fixtures only.

## Manual (performed on this machine)

- Project Window renders; New Project creates `project.json`; Open Project
  lists imported programs with tree/table toggle; Import File opens the
  Analysis Options dialog.
- Analysis Options: presets toggle the analyzer checklist; Analyze starts the
  real analysis under the chosen profile; Cancel returns to the previous screen
  without starting an analysis.
- CodeBrowser: function list filters and selects; Listing updates; Decompile
  panel shows pseudocode side by side; Back/Forward/Go-to navigate; bottom
  tabs show Tasks, Console, Summary, CFG graph, Xrefs, Resource Monitor and
  Problems with real data.
- Resource Monitor: CPU/RAM values come from `sysinfo`; GPU/VRAM render
  `Unavailable`; pressure state is visible in the top bar.
- Resource Settings: limits apply to the manager and persist across restarts.
- Search For Strings: minimum length/UTF-16/deduplicate options, filter and
  CSV export.
- Program Search: mode selector (Program Text, Decompiled Text, Labels,
  Direct References, Scalars, Strings, Instruction Patterns, Matching
  Instructions, Memory, Encoded Strings); max-results limit with truncation
  notice; results navigate to the CodeBrowser address/function; Index scope is
  labelled not implemented; disabled Ghidra menu entries are labelled
  `(not implemented)`.
- Theme: dark and light palettes render readable text, semantic colors and
  pressure states; persisted across restarts.
- Menus: working commands run; unavailable commands are disabled and labelled.

## Not covered

- Automated pixel/layout tests and multi-resolution checks.
- Long-run UI soak testing.
- Accessibility tooling.

Any claim in the compatibility matrix about the GUI therefore stays at
`IMPLEMENTED`/`TESTED` for the covered behavior, never `VERIFIED_COMPATIBLE` with
Ghidra's UI.
