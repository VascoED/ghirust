# CPU Scheduler

## Current implementation

- **`CpuPool`** (`ghirust-core/src/resources.rs`): a bounded thread pool with a
  priority max-heap, a queue bounded at `workers * 4` (backpressure via
  `PoolError::Saturated`), pause/resume through a condition variable and
  cooperative cancellation of queued jobs. Workers are joined on drop.
- **Priorities**: `CRITICAL_UI` (listing navigation), `INTERACTIVE`
  (inspection/search), `HIGH` (analysis/decompilation), `NORMAL` (export),
  `LOW` (indexing), `BACKGROUND` (cache cleanup).
- **GUI tasks** run one thread each but are capped by
  `max_concurrent_tasks`; additional work is refused with a clear error.
- **Search parallelism** runs on a bounded rayon pool
  (`ghirust_core::search::search_worker_limit`), never on every core.
- **Cooperative throttling**: analysis loops yield or stop when the resource
  manager reports pressure (see `resource_management.md`).

## Design rules

- Never oversubscribe: worker limits are a fraction of logical CPUs by
  default (`Balanced` = logical/4, clamped 2..=8).
- The GUI thread never runs analysis; all heavy work is off-thread.
- Cancellation is cooperative only, at documented safe boundaries; the UI
  says so instead of pretending to interrupt instantly.
- Pause/resume is implemented at the pool level; pausing a running analysis
  mid-decode is not supported and is not claimed.

## Tests

`resources::tests` cover priority ordering, pause (no jobs start while
paused), resume, cancellation of queued jobs, and the bounded queue
backpressure path. GUI task-priority plumbing is exercised by the API tests.
