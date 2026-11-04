# Objective Comparison Tool

`compare.py` orchestrates a reproducible Ghidra 12.2 vs GHIRUST comparison.

## What it does

1. Validates the environment (Ghidra home, JDK, GHIRUST binary).
2. Captures OS, CPU, tool versions, input size and SHA-256.
3. Runs Ghidra headless (`analyzeHeadless.bat` + `ExportProgram.java`) and
   stores the NDJSON export plus the full log.
4. Runs `ghirust benchmark` (real analysis, N runs, per-run samples) and
   stores the complete analysis and the benchmark JSON.
5. Normalizes both outputs to relative virtual addresses (RVA).
6. Compares: format/architecture/entry/exports, sections, imports, strings,
   function entry addresses, instruction addresses, mnemonics, basic blocks,
   CFG edges and decompiled text (lexical similarity only).
7. Writes `comparison.json`, `comparison.md`, `functions.csv` and
   `environment.json`.

## Usage

From the repository root:

```powershell
$env:JAVA_HOME = '$JAVA_HOME'
python tests\objectives\tools\compare.py `
  --binary tests\objectives\binaries\demo.dll `
  --ghidra-home 'C:\...\ghidra_12.2_PUBLIC' `
  --runs 3
```

Options:

| Option | Meaning |
|---|---|
| `--binary` | File to analyze (required) |
| `--name` | Result directory name (default: file stem) |
| `--ghidra-home` | Ghidra install (required, or `GHIDRA_HOME`) |
| `--java-home` | JDK directory (default: `JAVA_HOME` or `java` on PATH) |
| `--ghirust` | CLI binary (default: release build, built if missing) |
| `--runs` | GHIRUST benchmark runs (default 3) |
| `--output-dir` | Base result directory (default `tests/objectives/results`) |
| `--reuse-ghidra` | Reuse an existing `ghidra.ndjson` instead of re-running Ghidra |

## Honesty rules

- Addresses are compared as RVAs computed from each tool's own image base.
- Lexical similarity of decompiled text is **not** semantic equivalence.
- Anything not measured (for example peak memory) is recorded as `null` with a
  reason in `comparison.json`.
- Ghidra outputs are never edited; a comparison is only complete when the
  stored artifacts exist next to the report.
