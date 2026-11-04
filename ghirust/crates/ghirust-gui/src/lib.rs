//! The GUI's internal API and background task runner.
//!
//! Every heavy operation passes through a [`ghirust_core::resources::ResourceManager`]:
//! tasks declare a priority and an estimated RAM cost, and the manager refuses
//! work when the budget or the system pressure does not allow it. Cancellation
//! stays cooperative (only at safe stage boundaries) and is never presented as
//! instantaneous. Real CPU/RAM telemetry comes from
//! [`ghirust_core::telemetry`]; GPU metrics are always unavailable.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use ghirust_core::analysis::{AnalysisOptions, ProgramAnalysis, analyze_path_managed};
use ghirust_core::error::GhirustError;
use ghirust_core::resources::{
    Metrics, PressureState, Priority, ReservationRequest, ResourceBudget, ResourceManager,
};
use ghirust_core::telemetry::{GpuMetrics, SystemSnapshot, Telemetry};
use ghirust_core::{
    DetectionReport, ExportOptions, ExportReport, IndexOptions, IndexReport, SearchIndex,
    SearchOptions, SearchReport, StringOptions, StringRecord, build_index, detect_file,
    export_input, extract_strings, load_index, search,
};

pub type TaskId = u64;
pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
    pub suggestion: &'static str,
}

impl ApiError {
    fn from_core(error: GhirustError) -> Self {
        let (code, suggestion) = match &error {
            GhirustError::Io { .. } => (
                "io_error",
                "Check that the file exists and that you have permission to read or write it.",
            ),
            GhirustError::EmptyQuery => ("empty_query", "Enter a search query before searching."),
            GhirustError::Json { .. } => (
                "invalid_data",
                "The stored data is not valid JSON and cannot be read.",
            ),
            _ => (
                "operation_failed",
                "Review the error details and correct the input before retrying.",
            ),
        };
        Self {
            code,
            message: error.to_string(),
            suggestion,
        }
    }

    fn cancelled() -> Self {
        Self {
            code: "cancelled",
            message: "The operation was cancelled at a safe stage boundary.".to_owned(),
            suggestion: "Start the operation again when ready.",
        }
    }

    fn resource_refused(reason: String) -> Self {
        Self {
            code: "resource_limit_refused",
            message: format!("The task was not started: {reason}"),
            suggestion: "Lower the resource limits, close other work, or wait for running tasks to finish.",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinaryInspection {
    pub path: PathBuf,
    pub detection: DetectionReport,
    pub strings: Vec<StringRecord>,
}

#[derive(Debug)]
pub struct IndexedProject {
    pub root: PathBuf,
    pub report: IndexReport,
    pub index: SearchIndex,
}

#[derive(Debug)]
pub enum TaskResult {
    BinaryInspected(BinaryInspection),
    AnalysisCompleted(Box<ProgramAnalysis>),
    ProjectIndexed(IndexedProject),
    SearchCompleted(SearchReport),
    ExportCompleted(ExportReport),
}

#[derive(Debug)]
pub enum TaskEvent {
    Started {
        id: TaskId,
        label: String,
        priority: Priority,
    },
    Progress {
        id: TaskId,
        stage: String,
    },
    Completed {
        id: TaskId,
        result: Box<TaskResult>,
    },
    Failed {
        id: TaskId,
        error: ApiError,
    },
    Cancelled {
        id: TaskId,
    },
}

struct TaskContext {
    id: TaskId,
    sender: mpsc::Sender<TaskEvent>,
    cancelled: Arc<AtomicBool>,
}

struct TaskCancellation {
    token: Arc<AtomicBool>,
    can_cancel: bool,
}

impl TaskContext {
    fn progress(&self, stage: &str) {
        let _ = self.sender.send(TaskEvent::Progress {
            id: self.id,
            stage: stage.to_owned(),
        });
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Real-time resource state shown by the Resource Monitor.
#[derive(Debug, Clone)]
pub struct ResourceState {
    pub pressure: PressureState,
    pub snapshot: SystemSnapshot,
    pub gpu: GpuMetrics,
    pub budget: ResourceBudget,
    pub active_tasks: usize,
    pub reserved_ram_bytes: usize,
    pub reservations_created: u64,
    pub reservations_released: u64,
}

/// Runs core operations away from the GUI thread, under resource budgets.
pub struct TaskManager {
    sender: mpsc::Sender<TaskEvent>,
    receiver: mpsc::Receiver<TaskEvent>,
    cancellation: Arc<Mutex<HashMap<TaskId, TaskCancellation>>>,
    next_id: TaskId,
    manager: ResourceManager,
    telemetry: Telemetry,
}

impl Default for TaskManager {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender,
            receiver,
            cancellation: Arc::new(Mutex::new(HashMap::new())),
            next_id: 1,
            manager: ResourceManager::default(),
            telemetry: Telemetry::new(),
        }
    }
}

impl TaskManager {
    pub fn start_inspection(&mut self, path: PathBuf) -> ApiResult<TaskId> {
        let label = format!("Inspect {}", path.display());
        self.spawn(label, Priority::Interactive, true, move |context| {
            let detection = detect_file(&path).map_err(ApiError::from_core)?;
            context.progress("Extracting strings");
            let strings = extract_strings(
                &path,
                &StringOptions {
                    min_length: 5,
                    ..StringOptions::default()
                },
            )
            .map_err(ApiError::from_core)?;
            Ok(TaskResult::BinaryInspected(BinaryInspection {
                path,
                detection,
                strings,
            }))
        })
    }

    /// Analyze with default options under the resource manager.
    pub fn start_analysis(&mut self, path: PathBuf) -> ApiResult<TaskId> {
        self.start_analysis_with_options(path, AnalysisOptions::default())
    }

    /// Load a binary, decode its instructions, recover functions and CFGs and
    /// reconstruct pseudocode — with explicit options and a resource budget.
    /// The analysis reserves its own budget through the shared manager.
    pub fn start_analysis_with_options(
        &mut self,
        path: PathBuf,
        options: AnalysisOptions,
    ) -> ApiResult<TaskId> {
        let label = format!("Analyze {}", path.display());
        let manager = self.manager.clone();
        self.spawn_with(label, Priority::High, true, false, move |context| {
            context.progress("Waiting for resource budget");
            let analysis =
                analyze_path_managed(&path, &options, &manager).map_err(ApiError::from_core)?;
            context.progress("Analysis complete");
            if context.is_cancelled() {
                return Err(ApiError::cancelled());
            }
            Ok(TaskResult::AnalysisCompleted(Box::new(analysis)))
        })
    }

    pub fn start_indexing(&mut self, root: PathBuf) -> ApiResult<TaskId> {
        let label = format!("Index {}", root.display());
        self.spawn(label, Priority::Low, false, move |context| {
            context.progress("Building persistent function and text index");
            let report = build_index(&IndexOptions::new(&root)).map_err(ApiError::from_core)?;
            if context.is_cancelled() {
                return Err(ApiError::cancelled());
            }

            context.progress("Loading indexed functions");
            let index_path = report.index_path.clone();
            let index = load_index(&index_path).map_err(ApiError::from_core)?;
            Ok(TaskResult::ProjectIndexed(IndexedProject {
                root,
                report,
                index,
            }))
        })
    }

    pub fn start_search(
        &mut self,
        root: PathBuf,
        query: String,
        limit: usize,
    ) -> ApiResult<TaskId> {
        let label = format!("Search {}", root.display());
        self.spawn(label, Priority::Interactive, true, move |context| {
            context.progress("Loading the persistent search index");
            let index_path = root.join(".ghirust").join("index.json");
            let index = load_index(&index_path).map_err(ApiError::from_core)?;
            if context.is_cancelled() {
                return Err(ApiError::cancelled());
            }

            context.progress("Searching indexed text and function markers");
            let report = search(
                &index,
                &SearchOptions {
                    query,
                    limit,
                    ..SearchOptions::default()
                },
            )
            .map_err(ApiError::from_core)?;
            if context.is_cancelled() {
                return Err(ApiError::cancelled());
            }
            Ok(TaskResult::SearchCompleted(report))
        })
    }

    pub fn start_export(&mut self, input: PathBuf, output: PathBuf) -> ApiResult<TaskId> {
        let label = format!("Export {}", input.display());
        self.spawn(label, Priority::Normal, false, move |context| {
            context.progress("Streaming source functions to the output file");
            let report = export_input(
                &input,
                &ExportOptions {
                    output,
                    ..ExportOptions::default()
                },
            )
            .map_err(ApiError::from_core)?;
            Ok(TaskResult::ExportCompleted(report))
        })
    }

    pub fn cancel(&self, id: TaskId) -> bool {
        let Ok(tasks) = self.cancellation.lock() else {
            return false;
        };
        let Some(token) = tasks.get(&id) else {
            return false;
        };
        if !token.can_cancel {
            return false;
        }
        token.token.store(true, Ordering::Release);
        true
    }

    pub fn active_count(&self) -> usize {
        self.manager.active_tasks()
    }

    pub fn drain_events(&mut self) -> Vec<TaskEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            if let TaskEvent::Completed { id, .. }
            | TaskEvent::Failed { id, .. }
            | TaskEvent::Cancelled { id } = &event
                && let Ok(mut tasks) = self.cancellation.lock()
            {
                tasks.remove(id);
            }
            events.push(event);
        }
        events
    }

    /// Resource manager used by all tasks.
    pub fn manager(&self) -> &ResourceManager {
        &self.manager
    }

    /// Apply new budget limits (normalized to safety floors by the manager).
    pub fn set_budget(&self, budget: ResourceBudget) {
        self.manager.set_budget(budget);
    }

    /// Refresh telemetry and feed the pressure state.
    pub fn refresh_telemetry(&mut self) -> ResourceState {
        let snapshot = self.telemetry.snapshot();
        let metrics = Metrics {
            system_cpu_percent: snapshot.cpu_percent,
            available_ram_bytes: snapshot.available_ram_bytes,
            process_ram_bytes: snapshot.process_ram_bytes,
        };
        let pressure = self.manager.update(&metrics);
        ResourceState {
            pressure,
            snapshot,
            gpu: self.telemetry.gpu(),
            budget: self.manager.budget(),
            active_tasks: self.manager.active_tasks(),
            reserved_ram_bytes: self.manager.reserved_ram_bytes(),
            reservations_created: self.manager.reservations_created(),
            reservations_released: self.manager.reservations_released(),
        }
    }

    fn spawn(
        &mut self,
        label: String,
        priority: Priority,
        can_cancel: bool,
        operation: impl FnOnce(TaskContext) -> ApiResult<TaskResult> + Send + 'static,
    ) -> ApiResult<TaskId> {
        self.spawn_with(label, priority, can_cancel, true, operation)
    }

    fn spawn_with(
        &mut self,
        label: String,
        priority: Priority,
        can_cancel: bool,
        reserve: bool,
        operation: impl FnOnce(TaskContext) -> ApiResult<TaskResult> + Send + 'static,
    ) -> ApiResult<TaskId> {
        let estimated_ram = match priority {
            Priority::Background | Priority::Low => 64 * 1024 * 1024,
            Priority::High => 256 * 1024 * 1024,
            _ => 128 * 1024 * 1024,
        };
        let reservation = if reserve {
            let reservation = self
                .manager
                .reserve(
                    &ReservationRequest::new(label.clone(), priority)
                        .with_ram(estimated_ram)
                        .cancellable(can_cancel),
                )
                .map_err(|error| ApiError::resource_refused(error.to_string()))?;
            Some(reservation)
        } else {
            None
        };
        let cancelled = match &reservation {
            Some(reservation) if can_cancel => reservation.token.arc(),
            _ => Arc::new(AtomicBool::new(false)),
        };

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.cancellation
            .lock()
            .map_err(|_| ApiError {
                code: "task_state_unavailable",
                message: "Task state is unavailable because its lock was poisoned.".to_owned(),
                suggestion: "Restart the application before launching another operation.",
            })?
            .insert(
                id,
                TaskCancellation {
                    token: Arc::clone(&cancelled),
                    can_cancel,
                },
            );

        self.sender
            .send(TaskEvent::Started {
                id,
                label: label.clone(),
                priority,
            })
            .map_err(|error| ApiError {
                code: "task_channel_closed",
                message: format!("Could not start task: {error}"),
                suggestion: "Restart the application and retry.",
            })?;

        let context = TaskContext {
            id,
            sender: self.sender.clone(),
            cancelled: Arc::clone(&cancelled),
        };
        let sender = self.sender.clone();
        let spawn_result = thread::Builder::new()
            .name(format!("ghirust-task-{id}"))
            .spawn(move || {
                let _reservation = reservation; // held until the task ends
                if context.is_cancelled() {
                    let _ = sender.send(TaskEvent::Cancelled { id });
                    return;
                }
                match operation(context) {
                    Ok(result) => {
                        let _ = sender.send(TaskEvent::Completed {
                            id,
                            result: Box::new(result),
                        });
                    }
                    Err(error) if error.code == "cancelled" => {
                        let _ = sender.send(TaskEvent::Cancelled { id });
                    }
                    Err(error) => {
                        let _ = sender.send(TaskEvent::Failed { id, error });
                    }
                }
            });

        if let Err(error) = spawn_result {
            if let Ok(mut tasks) = self.cancellation.lock() {
                tasks.remove(&id);
            }
            let error = ApiError {
                code: "worker_start_failed",
                message: format!("Could not start background task: {error}"),
                suggestion: "Close other applications and retry the operation.",
            };
            let _ = self.sender.send(TaskEvent::Failed {
                id,
                error: error.clone(),
            });
            return Err(error);
        }
        Ok(id)
    }
}
