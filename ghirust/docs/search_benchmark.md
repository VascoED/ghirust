# Reproducible search benchmark

The benchmark generates an exported-source corpus, builds the normal
persistent index, and measures repeated text, function-name, address, path,
incremental-prefix, and string-extraction/search queries. It writes one JSON
report with the generated corpus dimensions, index time, median and p95 query
latency, bytes scanned, and calculated throughput.

Run from the Rust workspace directory:

```powershell
cargo run --release --locked -p ghirust-core --example search_benchmark
cargo run --release --locked -p ghirust-core --example search_benchmark -- 256 256 9
```

The optional arguments are file count, functions per file, and repetitions.
The benchmark uses a temporary synthetic corpus; it is not a real binary,
decompilation, or a Ghidra comparison. The current search API returns complete
results rather than progressive results, so the prefix cases are repeated
queries that approximate keystroke prefixes, not a GUI incremental-search
benchmark. CPU utilization and peak memory are emitted as `null` because the
harness does not collect those operating-system metrics. Compare runs on the
same host and record the actual command, runtime, power mode, and cache
conditions; generated data and OS page cache affect results.
