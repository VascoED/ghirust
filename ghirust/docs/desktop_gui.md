# Desktop GUI

The current desktop interface is documented in
[`docs/architecture/gui.md`](../../docs/architecture/gui.md).

## Quick state

| Area | State |
|---|---|
| Native window | eframe/egui, background task API |
| Screen state machine | Project / Analysis / CodeBrowser / Functions / ProgramSearch / Search / Strings / Command Center / Settings; explicit transitions (`state.rs`) |
| Binary opening | Dialog, drag-and-drop, inspection → Analysis Options → Analyze → CodeBrowser; Cancel returns without analysis; Close Program clears state |
| CodeBrowser | Function list, listing, pseudocode, CFG graph, symbols, xrefs, strings, warnings |
| Program Search | Bounded search over the current `ProgramAnalysis`; implemented modes tested, Index scope and Search & Replace not implemented |
| Exported-source project | Persistent indexing, search, streaming export |
| Theme | Centralized `Palette` (Dark/Light); semantic tokens only; pressure states mapped |
| Localization | Navigation and CodeBrowser tabs: pt-PT, pt-BR, en-US, ru-RU; partial |
| System telemetry / scheduler | Real `sysinfo` CPU/RAM telemetry; resource budgets, priorities; GPU unavailable |

## Build and test

From the `ghirust/` workspace directory:

```powershell
cargo run --locked -p ghirust-gui
cargo test --locked -p ghirust-gui
```

The GUI compiles and its task API, state machine, theme and program-search
coverage are tested via `cargo test --workspace`. The window has not been
exercised as an automated visual test, and this environment has no GPU telemetry
backend.
