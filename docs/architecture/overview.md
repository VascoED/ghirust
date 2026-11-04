# Architecture Overview

GHIRUST is a Rust workspace that turns a binary file into a navigable program
model and C-like pseudocode. The same core is used by the CLI and the desktop
application; the GUI does not reimplement analysis.

## Workspace layout

```text
ghirust/
  crates/
    ghirust-core/   loader, disassembly, CFG, IR, pseudocode, projects, search, export
    ghirust-cli/    command-line interface
    ghirust-gui/    native eframe/egui desktop application
tests/
  objectives/       known source, compiled PE fixture, reports, benchmarks, Ghidra prototype
docs/
  architecture/     this directory
  testing/          test strategy and objective fixtures
  benchmarks/       benchmark methodology and measured results
  ghira_compatibility_matrix.md
```

## Data flow

```text
file bytes
   │
   ▼
loader.rs ──────────────► LoadedProgram
  object crate              sections, imports, exports, symbols, strings,
  memory-mapped image       virtual reads, zero-fill for BSS-like tails
   │
   ▼
analysis.rs ────────────► ProgramAnalysis
  iced-x86 decoder          seeds → function discovery → recursive CFG
  xref collection           GUIR lifting → statistics and warnings
   │
   ▼
pseudocode.rs ──────────► DecompiledFunction
  expression environment    signature, statements, parameters, locals,
  CFG structuring           warnings, unsupported instructions
   │
   ├────────► CLI JSON/text
   ├────────► project.rs project.json + analysis.json + user.json
   └────────► ghirust-gui CodeBrowser panels
```

## Design rules

1. **No fabricated program state.** A feature that is unsupported is reported
   as unsupported. The decompiler emits warnings for instructions without a
   semantic model instead of inventing expressions.
2. **One engine, multiple front ends.** CLI and GUI call `analyze_path` and the
   project API in `ghirust-core`.
3. **Bounded memory.** Export, search and analysis all respect explicit limits.
   The loader maps files instead of copying them.
4. **Evidence before claims.** Compatibility states and benchmark numbers are
   backed by tests or measured runs recorded in this repository.
5. **Rust first.** C++ and GPU components are absent because no measured
   hotspot justifies them and no C/C++ compiler is available in this
   environment.

## Crates

### ghirust-core

| Module | Responsibility |
|---|---|
| `loader.rs` | PE/ELF/Mach-O/WASM metadata, sections, symbols, imports, exports, string extraction, virtual reads |
| `analysis.rs` | Seed discovery, recursive-descent decoding, function boundaries, basic blocks, xrefs, GUIR lifting |
| `pseudocode.rs` | Expression AST, symbolic register/stack environment, calling conventions, control-flow structuring, C-like rendering |
| `ir.rs` | GUIR module, blocks, operations and validation |
| `project.rs` | Project manifest, imported programs, saved analysis, user overrides, sessions, atomic writes and recovery |
| `detect.rs` | Lightweight format/architecture detection |
| `strings.rs` | ASCII and UTF-16LE string extraction |
| `index.rs`, `search.rs` | Persistent index over exported source text |
| `export.rs` | Streaming consolidation with gzip and resume checkpoints |
| `cache.rs` | Content-addressed persistent cache |
| `filemap.rs` | Memory-mapped file access |

### ghirust-cli

Commands are intentionally composable: every analysis command can either
analyze a binary or reuse a saved analysis with `--analysis`. Project commands
persist results and user annotations.

### ghirust-gui

The GUI runs operations on background threads through `TaskManager`. The
CodeBrowser reads the resulting `ProgramAnalysis` and displays:

- function list with filter;
- disassembly listing per basic block;
- reconstructed pseudocode with warnings;
- summary, symbols/imports/exports, xrefs, strings and warnings panels;
- a layered CFG graph for the selected function.

## Current boundaries

- Only x86 and x86-64 machine code is decoded.
- Pseudocode is heuristic and limited to scalar integer/control-flow patterns
  plus basic memory loads and stores.
- SSE/AVX/x87/string/system instructions are reported as unsupported models.
- No Ghidra runtime comparison has been executed.
- No large (>10 MB) real binary benchmark exists yet.
- The GUI is compiled and its task API is tested; it has not been exercised on
  every desktop environment.
