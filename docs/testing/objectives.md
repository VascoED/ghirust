# Objective Fixtures and Reports

## Known-source binaries

Four DLLs with known source live under `tests/objectives/`:

| Fixture | Source | Language | Coverage |
|---|---|---|---|
| `demo.dll` | `source/demo.rs` | Rust | Arithmetic, branches, loops, vectorized loop |
| `demo_features.dll` | `source/rust/demo_features.rs` | Rust | Arithmetic, many args, if/else, for/while, recursion, arrays, slices, strings, structs, tagged enums, methods, pointers, memory ops, SSE-generating float loop |
| `demo_cpp.dll` | `source/cpp/demo_cpp.cpp` | C++ (MSVC 19.51) | Arithmetic, branches, loops, recursion, classes (ctor/dtor), structs, arrays, templates, overloads (mangled exports), inheritance, pointers, exceptions, Rust interop |
| `demo_bridge.dll` | `source/rust/demo_bridge.rs` | Rust↔C++ interop | `bridge_roundtrip` crosses Rust → C++ → Rust |

Checksums, compilers, build commands, expected functions and results are
recorded in `tests/objectives/manifest.json`.

## Rebuild and behavior verification

```powershell
powershell -ExecutionPolicy Bypass -File tests\objectives\build_fixtures.ps1
powershell -ExecutionPolicy Bypass -File tests\objectives\run_behavior.ps1
```

The behavior harness loads every DLL and calls the exports with known inputs:
**50/50 checks pass** (`results/behavior.json`). This is the reference against
which recovered pseudocode can be judged.

## Ghidra comparison

`tools/compare.py` runs the Ghidra 12.2 headless exporter
(`ghidra/ExportProgram.java`) and the real GHIRUST analysis on the same binary,
normalizes both to RVAs and stores:

- `results/<fixture>/ghidra.ndjson` — Ghidra program/memory/imports/functions
  (blocks, instructions, CFG edges) + decompiled C + strings;
- `results/<fixture>/ghirust.analysis.json` — complete GHIRUST analysis;
- `results/<fixture>/comparison.json` and `comparison.md` — normalized
  comparison;
- `results/<fixture>/functions.csv` — per-function rows.

Latest summary (2026-11-04):

| Fixture | Ghidra | GHIRUST | Common |
|---|---:|---:|---:|
| demo | 57 | 57 | 53 |
| demo_features | 385 | 468 | 327 |
| demo_cpp | 444 | 461 | 401 |
| demo_bridge | 55 | 52 | 49 |

## Report integrity

Every stored analysis is bound to its binary SHA-256; the CLI and
`ghirust project verify` reject mismatched analyses. Ghidra outputs are never
edited: if the binary changes, regenerate the comparison.
