# GUI Architecture

The desktop application is organized like Ghidra 12.2's main workspaces,
with GHIRUST's own identity. Layout is a work in progress; everything shown
below exists in `ghirust/crates/ghirust-gui`.

## Screens

The application uses an explicit screen state machine (`Screen`,
`ImportFlow`, `FlowAction`, `TransitionReason` in
`ghirust/crates/ghirust-gui/src/state.rs`). Only one screen renders content at
a time; the Project Window, Analysis Options, CodeBrowser and Program Search are
distinct screens reached through explicit transitions, and stale task results
are ignored by task id.

| Screen | Contents |
|---|---|
| **Project Window** | Toolbar (New/Open Project, Import File, Open CodeBrowser, Settings), Tool Chest (CodeBrowser, Program Analysis, Search, Strings, Resource Monitor; unavailable tools are disabled and labelled), Active Project (tree/table toggle, filter, per-program name/format/arch/functions/analyzed/hash), Running Tools, status bar |
| **Analysis Options** | Analyzer checklist with descriptions and resource notes; presets Quick/Standard/Deep; function limit; resource profile; Select All / Deselect All / Reset / Analyze / Cancel |
| **CodeBrowser** | Left: Functions (filter, selectable rows) / Symbols / Program Trees / Data Types tabs · Center: Listing with Back/Forward/Go-to navigation · Right: Decompile panel · Bottom: Tasks / Console / Summary / Graph / Xrefs / Resource Monitor / Problems tabs |
| **Program Search** | Dedicated screen over the current `ProgramAnalysis`: mode selector (Program Text, Decompiled Text, Labels, Direct References, Scalars, Strings, Instruction Patterns, Matching Instructions, Memory, Encoded Strings partial), max-results limit, preview results, navigation to CodeBrowser; Index scope and Search & Replace are not implemented |
| **Command Center / Task panel** | Real task states (label, status, priority, elapsed, stage); cancellation only where the core supports it |
| **Search / Strings** | Search For Strings window: minimum length, UTF-16, deduplicate, filter, CSV export |
| **Settings** | Language/theme plus Resource Settings (profile, worker threads, concurrent tasks, RAM cap, CPU ceiling, cache limit) — applied to the ResourceManager and persisted |

## Menus

`File`, `Edit`, `Project`, `Tools`, `Window`, `Help` are present with working
commands; anything not implemented (Undo/Redo, Function/Call Graph, Memory
Map, Script Manager, Parse C Source) is shown disabled and labelled
`(not implemented)`.

## Telemetry in the GUI

CPU (system %), process RAM, budgets, active tasks and reservations come from
real measurements (`sysinfo`). GPU/VRAM render `Unavailable`. Pressure state
is visible in the top bar and the Resource Monitor (with sparkline history of
CPU and process RAM).

## What is not automated

Pixel-level layout, resizing and window behavior have no visual test harness.
`docs/testing/gui_validation.md` lists the manual validation performed and
what remains open.
