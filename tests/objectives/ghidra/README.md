# Ghidra Bridge

Validated environment: **Ghidra 12.2 PUBLIC**, JDK 25. Headless analysis
works end to end.

## Files

| File | Purpose | Status |
|---|---|---|
| `ExportProgram.java` | Ghidra headless `GhidraScript`: exports program metadata, memory blocks, imports, functions with basic blocks/instructions/CFG edges, decompiled C and defined strings as NDJSON | Compiled and executed successfully on `demo.dll` |
| `ExportFunctions.java` | Earlier minimal exporter (functions + decompiled C only) | Retained; still valid |
| `run_ghidra_export.ps1` | Checks Java/`GHIDRA_HOME`, runs `analyzeHeadless.bat` with `ExportProgram.java` | Validated |
| `../tools/compare.py` | Python orchestrator: Ghidra export → GHIRUST analysis → normalized comparison → JSON/Markdown/CSV reports | Validated |

## Manual export

```powershell
$env:JAVA_HOME = 'C:\path\to\jdk-25'
$env:GHIDRA_HOME = 'C:\path\to\ghidra_12.2_PUBLIC'
.\run_ghidra_export.ps1 -Binary ..\binaries\demo.dll -Output .\demo.ghidra.ndjson
```

## Automated comparison

From the repository root:

```powershell
$env:JAVA_HOME = 'C:\path\to\jdk-25'
python tests\objectives\tools\compare.py `
  --binary tests\objectives\binaries\demo.dll `
  --ghidra-home $env:GHIDRA_HOME `
  --runs 3
```

Results land in `tests/objectives/results/demo/`.

## Provenance and licensing

The Java scripts are original code linking against the Ghidra API at runtime.
No Ghidra source file is copied into GHIRUST. Ghidra remains under its own
license and must be installed separately. `ghira_original_source_code/` in the
repository root is the reference tree used for API consultation only.
