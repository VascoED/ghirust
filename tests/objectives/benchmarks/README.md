# Objective Benchmarks

This directory contains measured GHIRUST benchmark output, not fabricated or
estimated numbers.

| File | Profile | Input | Runs |
|---|---|---|---|
| `demo.ghirust.benchmark.release.json` | release | `tests/objectives/binaries/demo.dll` | 5 |
| `demo.ghirust.benchmark.debug.json` | dev | same | 5 |

Input SHA-256:
`8e333cc5e9f91a82c675beaf108e8cfccb33e9d5e2c34e8c8fb30705cedd8773`

Each JSON file contains:

- input path, size and SHA-256;
- all per-run wall and core-analysis timings;
- minimum, median, mean and maximum;
- recovered function/instruction/block/xref counts;
- analysis warnings.

Methodology: `docs/benchmarks/methodology.md`.
Results discussion: `docs/benchmarks/results.md`.

## Reproduce

```powershell
cargo run --release -p ghirust-cli -- benchmark `
  ../tests/objectives/binaries/demo.dll --runs 5 --json
```

Run commands from the `ghirust/` workspace directory.

## Missing comparisons

There are no Ghidra results here. The environment has no Java/JDK and the
Ghidra bridge prototype has never executed. Do not add a comparison file until
it was produced by a real Ghidra run on the same input.
