# Memory Management

## Existing bounds (enforced)

- **Loader**: memory-mapped file access (`filemap.rs`); sections are read as
  offsets into the map; BSS-like tails are synthesized as zeros. No full-file
  copies.
- **Analysis**: hard limits on functions, instructions per function, blocks
  per function, sweep instructions, prologue candidates, strings and xrefs
  (`AnalysisOptions`). Hitting a limit sets `stats.truncated` and a warning.
- **Export**: streaming consolidation; the output is never materialized in
  RAM (`export.rs`).
- **Search**: path-ordered bounded batches; result limits; `snippet_chars`
  bounds per hit.
- **Cache**: content-addressed persistent cache with explicit byte limits and
  LRU eviction (`cache.rs`).
- **Resource budget**: `max_process_ram_bytes` is enforced before tasks start
  (reservations) and monitored while they run (pressure states, cooperative
  stop at critical pressure).

## What is not yet implemented

- Per-artifact cache budgets (disassembly vs pseudocode vs CFG vs strings) —
  a single cache limit exists today.
- Automatic discarding of intermediate representations after use; the GUI
  keeps one `ProgramAnalysis` in memory, which is acceptable for the current
  fixture sizes and documented for large files.
- Peak-RSS measurement in the comparison harness (recorded as unavailable).

## Policy

No intermediate representation is kept in RAM beyond the configured limits;
no cache grows without bound; and the OS is always left with headroom
because budgets are floors-and-ceilings by construction.
