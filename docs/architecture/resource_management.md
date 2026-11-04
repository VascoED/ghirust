# Resource Management

`ghirust-core/src/resources.rs` is the central authority for CPU/RAM budgets
and pressure-driven throttling. No heavy operation starts without a
reservation from the [`ResourceManager`].

## Components

| Component | Role |
|---|---|
| `ResourceManager` | Budgets, reservations, pressure state, cooperative stop/throttle signals |
| `Reservation` | RAII guard: releases budget on drop (panic/cancel included) |
| `CancellationToken` | Cooperative cancellation at safe stage boundaries |
| `CpuPool` | Bounded, priority-aware thread pool with pause/resume/cancel |
| `ResourceBudget` | Hard limits: workers, concurrent tasks, process RAM, CPU ceiling, cache |
| `ResourceProfile` | `Conservative` / `Balanced` (default) / `Performance` / `Custom` |
| `PressureState` | `NORMAL` → `WARNING` → `HIGH_PRESSURE` → `CRITICAL` → `RECOVERY` |

## Rules (enforced in code, not just the UI)

1. Never reserve more RAM than the budget allows.
2. Never start more than `max_concurrent_tasks` at once.
3. Never occupy every core: worker limits default to a fraction of the machine.
4. Keep resources for the OS: RAM/CPS ceilings are hard limits.
5. `CRITICAL` refuses every new task; `HIGH_PRESSURE` admits only
   `Priority::High` and above.
6. Reservations are released on drop — a panic cannot leave one stuck
   (`reservations_released` counts releases for leak detection).
7. Budgets are normalized to safety floors: at least 1 worker, ≥64 MiB RAM,
   CPU ceiling ≤ 95%. No user configuration can disable all protection.

## Pressure model

`ResourceManager::update(&Metrics)` computes the state from real measurements:

| Condition | State |
|---|---|
| process RAM ≥ 90% of budget, or available RAM < 256 MiB, or CPU ≥ 95% (when auto-throttle is on) | `CRITICAL` |
| process RAM ≥ 75%, or available RAM < 768 MiB, or CPU ≥ ceiling | `HIGH_PRESSURE` |
| process RAM ≥ 60%, or available RAM < 1.5 GiB, or CPU ≥ 85% of ceiling | `WARNING` |
| otherwise | `NORMAL` |

Exiting `CRITICAL` always passes through one `RECOVERY` step before `NORMAL`,
so workers are not all re-activated at once.

## Engine integration

- `analyze_path_managed(path, options, &manager)` holds a reservation for the
  whole run, wires a pressure watcher into `AnalysisOptions::stop_flag` /
  `throttle_flag`, and the sweep/decoding loops check them at cooperative
  points (every 512 instructions) — the analysis slows down or stops cleanly
  instead of starving the machine.
- Search runs on a bounded rayon pool (`search_worker_limit`, default
  `logical/2` clamped to 1..=4), never on the global pool with every core.
- The GUI `TaskManager` reserves per task with priorities
  (`CRITICAL_UI/INTERACTIVE/HIGH/NORMAL/LOW/BACKGROUND`) and refuses with a
  structured `resource_limit_refused` error when the budget does not allow it.

## Measured, configurable, never fabricated

The CLI exposes `--profile conservative|balanced|performance`,
`--max-threads N` and `--max-ram-mb N` on `analyze`/`benchmark`. The GUI
Resource Settings window edits the same budget, persisted per user and applied
by the manager — not just displayed.

GPU/VRAM: there is no GPU backend and no vendor telemetry API linked. GPU
metrics are reported as unavailable; there is no simulated GPU budget.
