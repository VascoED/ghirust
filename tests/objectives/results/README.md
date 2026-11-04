# Objective Results

Real Ghidra 12.2 vs GHIRUST comparison artifacts. Each subdirectory contains:

| File | Content |
|---|---|
| `ghidra.ndjson` | Raw Ghidra headless export (`ExportProgram.java`) |
| `ghidra.log` | Full Ghidra headless log |
| `ghirust.analysis.json` | Complete GHIRUST analysis |
| `ghirust.benchmark.json` | GHIRUST per-run samples |
| `comparison.json` | Machine-readable normalized comparison |
| `comparison.md` | Human-readable report |
| `functions.csv` | Per-function rows |
| `environment.json` | Tool versions and hardware |

## Current runs (2026-11-04, Ghidra 12.2 PUBLIC, JDK 25, rustc 1.98.1)

| Fixture | Ghidra functions | GHIRUST functions | Common addresses |
|---|---:|---:|---:|
| `demo` | 57 | 57 | 53 |
| `demo_features` | 385 | 468 | 327 |
| `demo_cpp` | 444 | 461 | 401 |
| `demo_bridge` | 55 | 52 | 49 |

Also present: `behavior.json`, produced by `run_behavior.ps1`
(50/50 runtime checks against the documented expected values).

## Reproduce

```powershell
# Rebuild all fixtures
powershell -ExecutionPolicy Bypass -File tests\objectives\build_fixtures.ps1

# Verify runtime behavior
powershell -ExecutionPolicy Bypass -File tests\objectives\run_behavior.ps1

# Compare one fixture
$env:JAVA_HOME = '$JAVA_HOME'
python tests\objectives\tools\compare.py --binary tests\objectives\binaries\demo.dll `
  --ghidra-home 'C:\...\ghidra_12.2_PUBLIC' --runs 3
```

## Known asymmetries (documented, not hidden)

- GHIRUST jump-target seeds produce a few shared-epilogue fragments (weak
  `jump` discovery, 60% confidence); Ghidra merges shared returns.
- Ghidra recovers guard thunks (`__guard_check_icall`, `_guard_dispatch_icall`)
  that GHIRUST currently misses (indirect call tables).
- Ghidra demangles C++ export names; GHIRUST reports raw mangled names.
- Ghidra defines more strings through its type system; GHIRUST scans raw bytes.
