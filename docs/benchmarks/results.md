# Measured GHIRUST Results

These results were measured on the environment described in
[`methodology.md`](methodology.md). They cover small objective DLLs. They do
not predict performance on large binaries.

## Ghidra 12.2 vs GHIRUST, same input, same machine (2026-11-04)

Input: `tests/objectives/binaries/demo.dll`, 9,728 bytes, SHA-256
`8e333cc5e9f91a82c675beaf108e8cfccb33e9d5e2c34e8c8fb30705cedd8773`.

| Tool | Measurement | Value |
|---|---|---|
| Ghidra 12.2 headless | Import + full auto-analysis + export (wall) | 36.6 s (1 run) |
| GHIRUST 0.1.0 release | 3 runs, wall samples | 11/7/7 ms, median 7 ms |
| GHIRUST 0.1.0 release | Recovered | 57 functions, 898 instructions, 221 blocks, 591 xrefs |

This is not a "GHIRUST is faster than Ghidra" claim: Ghidra's JVM startup,
full program model and decompiler analysis do far more work. It is the
recorded wall time of both tools on the same fixture.

## Objective DLL — release profile

Command:

```powershell
cargo run --release -p ghirust-cli -- benchmark `
  ../tests/objectives/binaries/demo.dll --runs 5 --json
```

Input: 9,728 bytes, SHA-256
`8e333cc5e9f91a82c675beaf108e8cfccb33e9d5e2c34e8c8fb30705cedd8773`

Recovered per run: 19 functions, 442 instructions, 105 blocks, 291 xrefs
(recorded before the function-discovery improvements; the current engine
recovers 57 functions — see `tests/objectives/results/demo/` for fresh
samples).

| Metric | Value |
|---|---:|
| Wall time min | 1 ms |
| Wall time median | 1 ms |
| Wall time mean | 1.6 ms |
| Wall time max | 3 ms |
| Core analysis min | 1 ms |
| Core analysis median | 1 ms |
| Core analysis mean | 1.4 ms |
| Core analysis max | 3 ms |

Raw samples (wall / core): 3/3, 1/1, 1/1, 1/1, 2/1 ms.

Source: `tests/objectives/benchmarks/demo.ghirust.benchmark.release.json`.

## Objective DLL — debug profile

Same command without `--release`:

| Metric | Value |
|---|---:|
| Wall time min | 5 ms |
| Wall time median | 5 ms |
| Wall time mean | 6.2 ms |
| Wall time max | 10 ms |
| Core analysis min | 4 ms |
| Core analysis median | 4 ms |
| Core analysis mean | 5.0 ms |
| Core analysis max | 8 ms |

Raw samples (wall / core): 10/8, 5/4, 5/4, 5/4, 6/5 ms.

Source: `tests/objectives/benchmarks/demo.ghirust.benchmark.debug.json`.

## Interpretation

- The release profile is several times faster on this fixture, as expected.
- Whole-millisecond timers make the 1 ms release median coarse; the actual
  load-and-analyze time may be below 1 ms.
- The fixture is tiny (9.7 KB, 442 instructions). It exercises every pipeline
  stage but says nothing about scaling, cache behavior on huge images, memory
  ceilings or adversarial binaries.
- The linear seed sweep visited 1,328 instructions; 23 overlapping function
  candidates were skipped.

## Previous synthetic export benchmark (not decompilation)

Earlier documentation records an opt-in export test that assembled
134,254,315 bytes from 1,024 synthetic functions. That test validates streaming
output writing and resume/checkpoint behavior. It is **not** a decompiler
benchmark, does not use a real DLL and does not measure peak RAM. It remains
ignored by default because it writes more than 100 MiB.

## Not measured

- A real 30 MB DLL or any binary larger than the objective fixtures.
- Peak process memory / RSS.
- CPU utilization, GPU utilization or VRAM.
- Ghidra per-phase timings (only total wall time was recorded).
- Concurrency or multi-file analysis throughput.
- Cold vs warm OS file cache beyond the repeated runs.

No number in this file was estimated or copied from another machine.
