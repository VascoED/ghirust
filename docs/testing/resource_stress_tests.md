# Resource Stress Tests

The goal of these tests is to prove the preventive mechanisms, **not** to
provoke a system-wide exhaustion. No test attempts to exhaust the computer.

## Automated (run by `cargo test`)

`ghirust-core/src/resources.rs`:

- `reservations_release_budget_on_drop` — RAII release, including the leak
  counter.
- `memory_budget_refuses_oversized_reservations` — RAM cap enforced.
- `task_limit_is_enforced` — concurrent-task cap enforced; release allows
  reuse.
- `critical_pressure_refuses_everything` — CRITICAL refuses even
  `CRITICAL_UI`; `must_stop` is reported.
- `high_pressure_admits_only_high_priority` — priority admission under
  pressure.
- `recovery_takes_one_step_before_normal` — no instant re-activation.
- `cpu_pool_runs_jobs_in_priority_order` — priority scheduling.
- `cpu_pool_does_not_start_jobs_while_paused` / resume — pause semantics.
- `cpu_pool_cancels_queued_jobs` — cooperative cancellation.
- `budgets_always_keep_safety_floors` — impossible configs are normalized.

`ghirust-core/src/telemetry.rs`:

- real system values reported (RAM > 0, logical CPUs ≥ 1, process RAM > 0);
- GPU metrics are never fabricated.

`ghirust-gui/tests/api.rs`:

- `resource_budget_is_applied_by_the_task_manager` — budget applies and
  safety floors survive invalid configurations.

## CLI smoke (recorded)

```powershell
ghirust benchmark tests\objectives\binaries\demo.dll --runs 2 `
  --profile conservative --max-threads 1 --json
ghirust analyze tests\objectives\binaries\demo_cpp.dll --profile balanced
```

Both complete under their budgets; analyses still finish on the fixtures.

## Not performed (deliberately)

- No deliberate RAM/VRAM exhaustion of the machine.
- No sustained soak test (hours) — pending a longer CI slot.
- No simulated GPU pressure — there is no GPU backend to pressure.
- Peak-RSS tracking is not wired (no psutil in the harness); recorded as
  unavailable.

## How to extend

Add scenarios that raise pressure **inside the budget** (small synthetic
metrics are already injectable through `ResourceManager::update(&Metrics)`),
assert the state transitions and that tasks are refused/slowed, then return to
`NORMAL` and assert recovery. Keep any process-level stress opt-in and bounded.
