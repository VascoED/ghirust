# Benchmark Methodology

## Goals

The benchmark harness answers a narrow question: **how long does the current
GHIRUST engine take to load, decode, recover functions/CFGs, collect xrefs and
reconstruct pseudocode for a specific binary?** It is not a Ghidra comparison
and not a general performance claim.

## Harness

```text
ghirust benchmark <binary> [--runs N] [--no-decompile]
                  [--max-functions N] [--save-analysis <path>] [--json]
```

Each run calls `ghirust_core::analysis::analyze_path` afresh. Two timings are
reported:

- **wall_ms** — from before loading to after analysis returns;
- **core_analysis_ms** — the engine's `stats.elapsed_ms`, which starts after the
  loader has produced a `LoadedProgram`.

The harness also records the input size and SHA-256, recovered function,
instruction, block and xref counts, and every per-run sample. It never reads a
stored result file and never fills in a missing metric.

## Recording rules

1. Run the command on the machine being reported.
2. Record the exact command line, git revision or working-tree state, profile
   (`dev` or `release`), Rust version and input SHA-256.
3. Keep all samples, not just the best run.
4. Report the profile and timer resolution. Current timings are whole
   milliseconds, so values of 1 ms are at the timer resolution.
5. Do not extrapolate from small fixtures to large binaries.
6. Label synthetic export tests as synthetic; they do not measure the
   decompiler.

## Environment used for the recorded results

| Item | Value |
|---|---|
| OS | Windows 10 Home, version 2009, AMD64 |
| Processor identifier | `Intel64 Family 6 Model 186 Stepping 2, GenuineIntel` |
| Logical processors | 16 |
| Rust | `rustc 1.98.1 (48a229cea 2026-09-01)` |
| Cargo | `cargo 1.98.1 (797e8a9bc 2026-08-05)` |
| Input | `tests/objectives/binaries/demo.dll`, 9,728 bytes |
| Input SHA-256 | `8e333cc5e9f91a82c675beaf108e8cfccb33e9d5e2c34e8c8fb30705cedd8773` |

WMI queries failed in this sandbox, so the processor is recorded by its
`PROCESSOR_IDENTIFIER` string and logical count rather than a marketing name.
Peak memory was not measured; no process-memory monitor is integrated.

## Reproduce

From `ghirust/`:

```powershell
cargo run --release -p ghirust-cli -- benchmark `
  ../tests/objectives/binaries/demo.dll --runs 5 --json
```

The saved outputs are:

- `tests/objectives/benchmarks/demo.ghirust.benchmark.debug.json`
- `tests/objectives/benchmarks/demo.ghirust.benchmark.release.json`
