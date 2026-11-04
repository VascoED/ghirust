//! Central resource management: budgets, reservations and cooperative
//! throttling.
//!
//! Every heavy operation must pass through [`ResourceManager::reserve`] before
//! it starts. Reservations are RAII guards: they release their budget on drop,
//! including on panic or cancellation, so a failed task can never leave a
//! reservation permanently stuck.
//!
//! The manager never touches the operating system directly. It receives real
//! measurements from [`crate::telemetry`] through [`ResourceManager::update`]
//! and derives a [`PressureState`] from them. Under pressure it:
//!
//! * refuses new heavy tasks (`Critical`),
//! * admits only high-priority tasks (`HighPressure`),
//! * reports [`ResourceManager::should_throttle`] so long loops can slow down
//!   or stop cooperatively.
//!
//! The default profile is [`ResourceProfile::Balanced`]. Profiles always keep
//! safety floors: at least one worker, a CPU ceiling of at most 95% and a RAM
//! budget of at least 64 MiB.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering as MemOrder};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;

/// Task priority. Higher variants run first and are admitted under pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Immediate UI feedback: listing navigation, text input.
    CriticalUi,
    /// User-triggered actions that must feel instant.
    Interactive,
    /// Expensive user-triggered work, e.g. decompiling the selected function.
    High,
    /// Ordinary analysis.
    Normal,
    /// Background indexing.
    Low,
    /// Cache cleanup and maintenance.
    Background,
}

impl Priority {
    fn rank(self) -> u8 {
        match self {
            Priority::CriticalUi => 6,
            Priority::Interactive => 5,
            Priority::High => 4,
            Priority::Normal => 3,
            Priority::Low => 2,
            Priority::Background => 1,
        }
    }
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Resource protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureState {
    Normal,
    Warning,
    HighPressure,
    Critical,
    Recovery,
}

impl PartialOrd for PressureState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.to_u8().cmp(&other.to_u8()))
    }
}

impl PressureState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => PressureState::Normal,
            1 => PressureState::Warning,
            2 => PressureState::HighPressure,
            3 => PressureState::Critical,
            _ => PressureState::Recovery,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            PressureState::Normal => 0,
            PressureState::Warning => 1,
            PressureState::HighPressure => 2,
            PressureState::Critical => 3,
            PressureState::Recovery => 4,
        }
    }
}

/// Resource profile. `Balanced` is the default.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResourceProfile {
    Conservative,
    Balanced,
    Performance,
    Custom(ResourceBudget),
}

/// Hard limits applied by the [`ResourceManager`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceBudget {
    /// Maximum worker threads available to heavy operations.
    pub max_worker_threads: usize,
    /// Maximum tasks running concurrently.
    pub max_concurrent_tasks: usize,
    /// Maximum process RAM the engine may commit, in bytes.
    pub max_process_ram_bytes: usize,
    /// CPU ceiling as a fraction of total capacity (0.0 ..= 0.95).
    pub cpu_ceiling: f32,
    /// Maximum cache size, in bytes.
    pub cache_limit_bytes: usize,
    /// Whether load is reduced automatically when pressure rises.
    pub auto_throttle: bool,
    /// Whether tasks stop (instead of merely slowing) at critical pressure.
    pub pause_on_critical: bool,
}

impl ResourceBudget {
    pub fn conservative() -> Self {
        Self {
            max_worker_threads: 2,
            max_concurrent_tasks: 2,
            max_process_ram_bytes: 512 * 1024 * 1024,
            cpu_ceiling: 0.5,
            cache_limit_bytes: 64 * 1024 * 1024,
            auto_throttle: true,
            pause_on_critical: true,
        }
    }

    pub fn balanced() -> Self {
        let logical = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4);
        Self {
            max_worker_threads: (logical / 4).clamp(2, 8),
            max_concurrent_tasks: 4,
            max_process_ram_bytes: 1024 * 1024 * 1024,
            cpu_ceiling: 0.75,
            cache_limit_bytes: 128 * 1024 * 1024,
            auto_throttle: true,
            pause_on_critical: true,
        }
    }

    pub fn performance() -> Self {
        let logical = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4);
        Self {
            max_worker_threads: (logical / 2).clamp(2, 12),
            max_concurrent_tasks: 8,
            max_process_ram_bytes: 2 * 1024 * 1024 * 1024,
            cpu_ceiling: 0.9,
            cache_limit_bytes: 256 * 1024 * 1024,
            auto_throttle: true,
            pause_on_critical: true,
        }
    }

    /// Clamp to safety floors so no configuration can remove all protection.
    fn normalized(mut self) -> Self {
        self.max_worker_threads = self.max_worker_threads.clamp(1, 64);
        self.max_concurrent_tasks = self.max_concurrent_tasks.clamp(1, 32);
        self.max_process_ram_bytes = self.max_process_ram_bytes.max(64 * 1024 * 1024);
        self.cache_limit_bytes = self.cache_limit_bytes.max(8 * 1024 * 1024);
        if !(0.1..=0.95).contains(&self.cpu_ceiling) {
            self.cpu_ceiling = self.cpu_ceiling.clamp(0.1, 0.95);
        }
        self
    }
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::balanced()
    }
}

/// What a task asks for before it starts.
#[derive(Debug, Clone)]
pub struct ReservationRequest {
    /// Human-readable task name.
    pub name: String,
    /// Task priority.
    pub priority: Priority,
    /// Estimated additional process RAM, in bytes.
    pub estimated_ram_bytes: usize,
    /// Requested worker threads (informational; capped by the budget).
    pub threads: usize,
    /// Whether the task checks a cancellation token at safe boundaries.
    pub cancellable: bool,
    /// Whether the task can make progress in small steps.
    pub incremental: bool,
}

impl ReservationRequest {
    pub fn new(name: impl Into<String>, priority: Priority) -> Self {
        Self {
            name: name.into(),
            priority,
            estimated_ram_bytes: 64 * 1024 * 1024,
            threads: 1,
            cancellable: false,
            incremental: false,
        }
    }

    pub fn with_ram(mut self, bytes: usize) -> Self {
        self.estimated_ram_bytes = bytes;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    pub fn cancellable(mut self, cancellable: bool) -> Self {
        self.cancellable = cancellable;
        self
    }

    pub fn incremental(mut self, incremental: bool) -> Self {
        self.incremental = incremental;
        self
    }
}

/// Why a reservation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// The system is under too much pressure or the budget is exhausted.
    Refused(String),
    /// Internal lock was poisoned (should never happen; reports honestly).
    Poisoned,
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::Refused(reason) => {
                write!(formatter, "resource reservation refused: {reason}")
            }
            ResourceError::Poisoned => write!(formatter, "resource manager state is unavailable"),
        }
    }
}

impl std::error::Error for ResourceError {}

/// Cooperative cancellation token shared between the manager and a task.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(MemOrder::Acquire)
    }

    pub fn cancel(&self) {
        self.flag.store(true, MemOrder::Release);
    }

    /// The underlying flag, for wiring into analysis options.
    pub fn arc(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }
}

/// RAII reservation. Releasing (drop) returns the budget even after a panic
/// or a cancellation, so no reservation can be left stuck.
#[derive(Debug)]
pub struct Reservation {
    inner: Arc<ManagerInner>,
    estimated_ram: usize,
    /// Cancellation token handed to the task, when it is cancellable.
    pub token: CancellationToken,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.inner.active_tasks.fetch_sub(1, MemOrder::Release);
        self.inner
            .reserved_ram
            .fetch_sub(self.estimated_ram, MemOrder::Release);
        self.inner.released.fetch_add(1, MemOrder::Relaxed);
    }
}

#[derive(Debug)]
struct ManagerInner {
    budget: RwLock<ResourceBudget>,
    profile: AtomicU8,
    state: AtomicU8,
    active_tasks: AtomicUsize,
    reserved_ram: AtomicUsize,
    released: AtomicU64,
    created: AtomicU64,
}

/// Central authority for CPU/RAM budgets and pressure-driven throttling.
#[derive(Debug, Clone)]
pub struct ResourceManager {
    inner: Arc<ManagerInner>,
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self::new(ResourceProfile::Balanced)
    }
}

impl ResourceManager {
    pub fn new(profile: ResourceProfile) -> Self {
        let budget = match profile {
            ResourceProfile::Conservative => ResourceBudget::conservative(),
            ResourceProfile::Balanced => ResourceBudget::balanced(),
            ResourceProfile::Performance => ResourceBudget::performance(),
            ResourceProfile::Custom(budget) => budget,
        }
        .normalized();
        let profile_id = match profile {
            ResourceProfile::Conservative => 0,
            ResourceProfile::Balanced => 1,
            ResourceProfile::Performance => 2,
            ResourceProfile::Custom(_) => 3,
        };
        Self {
            inner: Arc::new(ManagerInner {
                budget: RwLock::new(budget),
                profile: AtomicU8::new(profile_id),
                state: AtomicU8::new(PressureState::Normal.to_u8()),
                active_tasks: AtomicUsize::new(0),
                reserved_ram: AtomicUsize::new(0),
                released: AtomicU64::new(0),
                created: AtomicU64::new(0),
            }),
        }
    }

    pub fn budget(&self) -> ResourceBudget {
        *self
            .inner
            .budget
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Apply a new budget (normalized to safety floors).
    pub fn set_budget(&self, budget: ResourceBudget) {
        let mut guard = self
            .inner
            .budget
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = budget.normalized();
        self.inner.profile.store(3, MemOrder::Release);
    }

    /// Current pressure state.
    pub fn pressure(&self) -> PressureState {
        PressureState::from_u8(self.inner.state.load(MemOrder::Acquire))
    }

    pub fn active_tasks(&self) -> usize {
        self.inner.active_tasks.load(MemOrder::Acquire)
    }

    pub fn reserved_ram_bytes(&self) -> usize {
        self.inner.reserved_ram.load(MemOrder::Acquire)
    }

    /// Number of reservations released since creation (leak counter).
    pub fn reservations_created(&self) -> u64 {
        self.inner.created.load(MemOrder::Relaxed)
    }

    /// Number of reservations released since creation.
    pub fn reservations_released(&self) -> u64 {
        self.inner.released.load(MemOrder::Relaxed)
    }

    /// Worker-thread limit for heavy operations.
    pub fn worker_limit(&self) -> usize {
        self.budget().max_worker_threads
    }

    /// Acquire a budget reservation, or refuse with a reason. Tasks must not
    /// start heavy work without a successful reservation.
    pub fn reserve(&self, request: &ReservationRequest) -> Result<Reservation, ResourceError> {
        let budget = self.budget();
        let state = self.pressure();

        if state == PressureState::Critical && budget.pause_on_critical {
            return Err(ResourceError::Refused(
                "system is under critical resource pressure".to_owned(),
            ));
        }
        if state == PressureState::HighPressure && request.priority < Priority::High {
            return Err(ResourceError::Refused(
                "system is under high pressure; only high-priority tasks are admitted".to_owned(),
            ));
        }
        let active = self.inner.active_tasks.load(MemOrder::Acquire);
        if active >= budget.max_concurrent_tasks {
            return Err(ResourceError::Refused(format!(
                "task limit reached ({active}/{})",
                budget.max_concurrent_tasks
            )));
        }
        let reserved = self.inner.reserved_ram.load(MemOrder::Acquire);
        if reserved.saturating_add(request.estimated_ram_bytes) > budget.max_process_ram_bytes {
            return Err(ResourceError::Refused(format!(
                "memory budget exceeded ({} bytes reserved, {} requested, {} allowed)",
                reserved, request.estimated_ram_bytes, budget.max_process_ram_bytes
            )));
        }
        self.inner.active_tasks.fetch_add(1, MemOrder::AcqRel);
        self.inner
            .reserved_ram
            .fetch_add(request.estimated_ram_bytes, MemOrder::AcqRel);
        self.inner.created.fetch_add(1, MemOrder::Relaxed);
        let token = if request.cancellable {
            CancellationToken::new()
        } else {
            CancellationToken::default()
        };
        Ok(Reservation {
            inner: Arc::clone(&self.inner),
            estimated_ram: request.estimated_ram_bytes,
            token,
        })
    }

    /// Feed real measurements and recompute the pressure state.
    pub fn update(&self, metrics: &Metrics) -> PressureState {
        let budget = self.budget();
        let previous = self.pressure();

        let process_ratio = metrics.process_ram_bytes as f64 / budget.max_process_ram_bytes as f64;
        let available_floor = 256 * 1024 * 1024;
        // sysinfo's global CPU reading is a percentage of total capacity.
        let cpu = metrics.system_cpu_percent as f64 / 100.0;
        let ceiling = budget.cpu_ceiling as f64;

        let mut next = if process_ratio >= 0.9
            || metrics.available_ram_bytes < available_floor
            || (budget.auto_throttle && cpu >= 0.95)
        {
            PressureState::Critical
        } else if process_ratio >= 0.75
            || metrics.available_ram_bytes < 768 * 1024 * 1024
            || (budget.auto_throttle && cpu >= ceiling)
        {
            PressureState::HighPressure
        } else if process_ratio >= 0.6
            || metrics.available_ram_bytes < 1536 * 1024 * 1024
            || (budget.auto_throttle && cpu >= ceiling * 0.85)
        {
            PressureState::Warning
        } else {
            PressureState::Normal
        };

        if previous == PressureState::Critical && next < PressureState::Critical {
            // One recovery step before going back to normal work.
            next = PressureState::Recovery;
        } else if previous == PressureState::Recovery && next < PressureState::Normal {
            next = PressureState::Normal;
        }
        self.inner.state.store(next.to_u8(), MemOrder::Release);
        next
    }

    /// Whether long loops should slow down (yield) right now.
    pub fn should_throttle(&self) -> bool {
        matches!(
            self.pressure(),
            PressureState::HighPressure | PressureState::Critical
        )
    }

    /// Whether cooperative tasks should stop at their next safe boundary.
    pub fn must_stop(&self) -> bool {
        self.pressure() == PressureState::Critical && self.budget().pause_on_critical
    }

    /// A cancellation token for a task that must stop at critical pressure.
    pub fn critical_stop_token(&self) -> CancellationToken {
        let token = CancellationToken::new();
        let inner = Arc::clone(&self.inner);
        let flag = token.flag.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let budget = *inner
                    .budget
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if PressureState::from_u8(inner.state.load(MemOrder::Acquire))
                    == PressureState::Critical
                    && budget.pause_on_critical
                {
                    flag.store(true, MemOrder::Release);
                    break;
                }
            }
        });
        token
    }
}

/// Real measurements fed to the [`ResourceManager`]. Produced by
/// [`crate::telemetry`]; constructible in tests for deterministic checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct Metrics {
    /// Total system CPU usage, 0..=100.
    pub system_cpu_percent: f32,
    /// Physical memory available to the system, in bytes.
    pub available_ram_bytes: u64,
    /// RAM committed by the GHIRUST process, in bytes.
    pub process_ram_bytes: u64,
}

/// A bounded, priority-aware CPU pool with pause, resume and cooperative
/// cancellation of queued jobs. Workers are joined on drop; no task outlives
/// the pool.
pub struct CpuPool {
    inner: Arc<PoolInner>,
    workers: Vec<JoinHandle<()>>,
}

struct PoolInner {
    queue: Mutex<BinaryHeap<PoolJob>>,
    ready: Condvar,
    paused: AtomicBool,
    stopping: AtomicBool,
    queued: AtomicUsize,
    sequence: AtomicU64,
    capacity: usize,
}

struct PoolJob {
    priority: u8,
    sequence: u64,
    cancelled: Arc<AtomicBool>,
    run: Box<dyn FnOnce() + Send>,
}

impl PartialEq for PoolJob {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for PoolJob {}

impl PartialOrd for PoolJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PoolJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap: higher priority first, then earlier submission.
        self.priority
            .cmp(&other.priority)
            .then(other.sequence.cmp(&self.sequence))
    }
}

/// Handle to a submitted job; dropping it does not cancel the job.
#[derive(Debug)]
pub struct PoolTask {
    cancelled: Arc<AtomicBool>,
}

impl PoolTask {
    /// Cancel the job if it has not started yet. A running job must observe
    /// its own token; the pool cannot interrupt it safely.
    pub fn cancel(&self) {
        self.cancelled.store(true, MemOrder::Release);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// The queue is full; apply backpressure instead of growing unbounded.
    Saturated,
    /// The pool is shutting down.
    Stopped,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Saturated => write!(formatter, "CPU queue is full (backpressure)"),
            PoolError::Stopped => write!(formatter, "CPU pool is stopping"),
        }
    }
}

impl CpuPool {
    /// Create a pool with `workers` threads and a queue bounded at
    /// `workers * 4` jobs. Never zero workers.
    pub fn new(workers: usize) -> Self {
        let workers = workers.max(1);
        let inner = Arc::new(PoolInner {
            queue: Mutex::new(BinaryHeap::new()),
            ready: Condvar::new(),
            paused: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            queued: AtomicUsize::new(0),
            sequence: AtomicU64::new(0),
            capacity: workers * 4,
        });
        let mut handles = Vec::with_capacity(workers);
        for index in 0..workers {
            let inner = Arc::clone(&inner);
            handles.push(
                std::thread::Builder::new()
                    .name(format!("ghirust-cpu-{index}"))
                    .spawn(move || worker_loop(inner))
                    .expect("cpu pool worker spawn"),
            );
        }
        Self {
            inner,
            workers: handles,
        }
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn queued(&self) -> usize {
        self.inner.queued.load(MemOrder::Acquire)
    }

    /// Submit a job. Refused with [`PoolError::Saturated`] when the bounded
    /// queue is full, so a burst of work applies backpressure instead of
    /// allocating without limits.
    pub fn submit(
        &self,
        priority: Priority,
        _cancellable: bool,
        run: impl FnOnce() + Send + 'static,
    ) -> Result<PoolTask, PoolError> {
        if self.inner.stopping.load(MemOrder::Acquire) {
            return Err(PoolError::Stopped);
        }
        let queued = self.inner.queued.load(MemOrder::Acquire);
        if queued >= self.inner.capacity {
            return Err(PoolError::Saturated);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let sequence = self.inner.sequence.fetch_add(1, MemOrder::Relaxed);
        {
            let mut queue = self
                .inner
                .queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            queue.push(PoolJob {
                priority: priority.rank(),
                sequence,
                cancelled: Arc::clone(&cancelled),
                run: Box::new(run),
            });
            self.inner.queued.fetch_add(1, MemOrder::AcqRel);
        }
        self.inner.ready.notify_one();
        Ok(PoolTask { cancelled })
    }

    pub fn pause(&self) {
        self.inner.paused.store(true, MemOrder::Release);
    }

    pub fn resume(&self) {
        self.inner.paused.store(false, MemOrder::Release);
        self.inner.ready.notify_all();
    }

    pub fn is_paused(&self) -> bool {
        self.inner.paused.load(MemOrder::Acquire)
    }

    /// Stop accepting jobs and cancel queued work. Workers drain and exit;
    /// drop joins them.
    pub fn stop(&self) {
        self.inner.stopping.store(true, MemOrder::Release);
        {
            let mut queue = self
                .inner
                .queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            queue.clear();
            self.inner.queued.store(0, MemOrder::Release);
        }
        self.inner.paused.store(false, MemOrder::Release);
        self.inner.ready.notify_all();
    }
}

impl Drop for CpuPool {
    fn drop(&mut self) {
        self.stop();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn worker_loop(inner: Arc<PoolInner>) {
    loop {
        let job = {
            let mut queue = inner
                .queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            loop {
                if inner.stopping.load(MemOrder::Acquire) {
                    return;
                }
                while inner.paused.load(MemOrder::Acquire) {
                    queue = inner
                        .ready
                        .wait(queue)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                if let Some(job) = queue.pop() {
                    inner.queued.fetch_sub(1, MemOrder::AcqRel);
                    break job;
                }
                queue = inner
                    .ready
                    .wait(queue)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        if job.cancelled.load(MemOrder::Acquire) {
            continue;
        }
        (job.run)();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn metrics(cpu: f32, available: u64, process: u64) -> Metrics {
        Metrics {
            system_cpu_percent: cpu,
            available_ram_bytes: available,
            process_ram_bytes: process,
        }
    }

    #[test]
    fn reservations_release_budget_on_drop() {
        let manager = ResourceManager::new(ResourceProfile::Conservative);
        let request = ReservationRequest::new("test", Priority::Normal).with_ram(64 * 1024 * 1024);
        {
            let _reservation = manager.reserve(&request).unwrap();
            assert_eq!(manager.active_tasks(), 1);
            assert_eq!(manager.reserved_ram_bytes(), 64 * 1024 * 1024);
        }
        assert_eq!(manager.active_tasks(), 0);
        assert_eq!(manager.reserved_ram_bytes(), 0);
        assert_eq!(manager.reservations_released(), 1);
    }

    #[test]
    fn memory_budget_refuses_oversized_reservations() {
        let manager = ResourceManager::new(ResourceProfile::Conservative);
        let request =
            ReservationRequest::new("huge", Priority::Normal).with_ram(4 * 1024 * 1024 * 1024);
        assert!(matches!(
            manager.reserve(&request),
            Err(ResourceError::Refused(_))
        ));
    }

    #[test]
    fn task_limit_is_enforced() {
        let manager = ResourceManager::new(ResourceProfile::Conservative);
        let first = manager
            .reserve(&ReservationRequest::new("a", Priority::Normal))
            .unwrap();
        let second = manager
            .reserve(&ReservationRequest::new("b", Priority::Normal))
            .unwrap();
        assert!(matches!(
            manager.reserve(&ReservationRequest::new("c", Priority::Normal)),
            Err(ResourceError::Refused(_))
        ));
        drop(first);
        assert!(
            manager
                .reserve(&ReservationRequest::new("d", Priority::Normal))
                .is_ok()
        );
        drop(second);
    }

    #[test]
    fn critical_pressure_refuses_everything() {
        let manager = ResourceManager::new(ResourceProfile::Conservative);
        let state = manager.update(&metrics(90.0, 64 * 1024 * 1024, 600 * 1024 * 1024));
        assert_eq!(state, PressureState::Critical);
        assert!(manager.must_stop());
        assert!(matches!(
            manager.reserve(&ReservationRequest::new("any", Priority::CriticalUi)),
            Err(ResourceError::Refused(_))
        ));
    }

    #[test]
    fn high_pressure_admits_only_high_priority() {
        let manager = ResourceManager::new(ResourceProfile::Conservative);
        let state = manager.update(&metrics(55.0, 512 * 1024 * 1024, 420 * 1024 * 1024));
        assert_eq!(state, PressureState::HighPressure);
        assert!(
            manager
                .reserve(&ReservationRequest::new("hi", Priority::High))
                .is_ok()
        );
        assert!(matches!(
            manager.reserve(&ReservationRequest::new("lo", Priority::Low)),
            Err(ResourceError::Refused(_))
        ));
    }

    #[test]
    fn recovery_takes_one_step_before_normal() {
        let manager = ResourceManager::new(ResourceProfile::Conservative);
        manager.update(&metrics(90.0, 64 * 1024 * 1024, 600 * 1024 * 1024));
        assert_eq!(manager.pressure(), PressureState::Critical);
        let state = manager.update(&metrics(10.0, 4 * 1024 * 1024 * 1024, 40 * 1024 * 1024));
        assert_eq!(state, PressureState::Recovery);
        let state = manager.update(&metrics(10.0, 4 * 1024 * 1024 * 1024, 40 * 1024 * 1024));
        assert_eq!(state, PressureState::Normal);
    }

    #[test]
    fn cpu_pool_runs_jobs_in_priority_order() {
        let pool = CpuPool::new(2);
        let order = Arc::new(Mutex::new(Vec::new()));
        for (priority, tag) in [
            (Priority::Low, 1),
            (Priority::High, 2),
            (Priority::Normal, 3),
            (Priority::CriticalUi, 4),
        ] {
            let order = Arc::clone(&order);
            pool.submit(priority, false, move || {
                order.lock().unwrap().push(tag);
            })
            .unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if order.lock().unwrap().len() == 4 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "pool deadlocked");
            std::thread::sleep(Duration::from_millis(5));
        }
        let observed = order.lock().unwrap().clone();
        assert_eq!(observed, vec![4, 2, 3, 1]);
    }

    #[test]
    fn cpu_pool_cancels_queued_jobs() {
        let pool = CpuPool::new(1);
        let ran = Arc::new(AtomicUsize::new(0));
        // Occupy the single worker.
        let release = Arc::new(AtomicBool::new(false));
        {
            let release = Arc::clone(&release);
            pool.submit(Priority::Normal, false, move || {
                while !release.load(MemOrder::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
            .unwrap();
        }
        std::thread::sleep(Duration::from_millis(30));
        let queued_task = {
            let ran = Arc::clone(&ran);
            pool.submit(Priority::Normal, true, move || {
                ran.fetch_add(1, MemOrder::Relaxed);
            })
            .unwrap()
        };
        queued_task.cancel();
        release.store(true, MemOrder::Release);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(ran.load(MemOrder::Relaxed), 0);
    }

    #[test]
    fn cpu_pool_does_not_start_jobs_while_paused() {
        let pool = CpuPool::new(1);
        pool.pause();
        let ran = Arc::new(AtomicUsize::new(0));
        {
            let ran = Arc::clone(&ran);
            pool.submit(Priority::Normal, false, move || {
                ran.fetch_add(1, MemOrder::Relaxed);
            })
            .unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(ran.load(MemOrder::Relaxed), 0);
        pool.resume();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while ran.load(MemOrder::Relaxed) == 0 {
            assert!(std::time::Instant::now() < deadline, "pool did not resume");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn budgets_always_keep_safety_floors() {
        let mut budget = ResourceBudget {
            max_worker_threads: 0,
            max_concurrent_tasks: 0,
            max_process_ram_bytes: 1,
            cpu_ceiling: 1.0,
            cache_limit_bytes: 0,
            auto_throttle: true,
            pause_on_critical: true,
        };
        budget = budget.normalized();
        assert!(budget.max_worker_threads >= 1);
        assert!(budget.max_concurrent_tasks >= 1);
        assert!(budget.max_process_ram_bytes >= 64 * 1024 * 1024);
        assert!(budget.cpu_ceiling <= 0.95);
        assert!(budget.cache_limit_bytes >= 8 * 1024 * 1024);
    }
}
