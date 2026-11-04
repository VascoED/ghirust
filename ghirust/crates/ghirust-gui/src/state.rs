//! Explicit UI state machine for the import/analysis flow.
//!
//! Screens never change implicitly: every transition goes through
//! [`ImportFlow`] decisions, and stale task results (from a previous
//! import) are ignored instead of being applied to the current screen.

use std::path::PathBuf;

/// Screens of the application. Each screen owns its own panels; content is
/// never mixed across screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Project,
    Analysis,
    CodeBrowser,
    Functions,
    ProgramSearch,
    Search,
    Strings,
    CommandCenter,
    Settings,
}

impl Screen {
    pub fn name(self) -> &'static str {
        match self {
            Screen::Project => "Project",
            Screen::Analysis => "Analysis",
            Screen::CodeBrowser => "CodeBrowser",
            Screen::Functions => "Functions",
            Screen::ProgramSearch => "Program Search",
            Screen::Search => "Search",
            Screen::Strings => "Strings",
            Screen::CommandCenter => "Command Center",
            Screen::Settings => "Settings",
        }
    }
}

/// Why a screen transition happened (kept for tests and diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionReason {
    /// User pressed a button or menu entry.
    UserAction,
    /// Import of a binary started (inspection running).
    ImportStarted,
    /// Import was cancelled before analysis.
    ImportCancelled,
    /// Analysis finished and the CodeBrowser opened.
    AnalysisFinished,
    /// The current program was closed.
    ProgramClosed,
    /// Navigation inside a tool.
    Navigation,
}

/// The import/analysis flow. Exactly one of these states is active.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ImportFlow {
    /// No import running.
    #[default]
    Idle,
    /// Inspection task running for `path`.
    Inspecting { path: PathBuf, task: u64 },
    /// Inspection finished; the Analysis Options modal is open.
    Options { path: PathBuf },
    /// Analysis task running for `path`.
    Analyzing { path: PathBuf, task: u64 },
}

/// What the UI must do after an event reaches the flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAction {
    /// Apply the event: open Analysis Options.
    OpenOptions(PathBuf),
    /// Apply the event: analysis finished, open the CodeBrowser.
    AnalysisReady(PathBuf),
    /// The event belongs to an older import; ignore it.
    IgnoreStale,
    /// Nothing to do.
    None,
}

impl ImportFlow {
    /// Begin importing a binary. Refused when the same binary is already in
    /// the flow (no duplicate tasks).
    pub fn begin_inspection(&mut self, path: &PathBuf, task: u64) -> Result<(), DuplicateImport> {
        match self {
            ImportFlow::Inspecting { path: current, .. }
            | ImportFlow::Options { path: current }
            | ImportFlow::Analyzing { path: current, .. }
                if current == path =>
            {
                Err(DuplicateImport)
            }
            _ => {
                *self = ImportFlow::Inspecting {
                    path: path.clone(),
                    task,
                };
                Ok(())
            }
        }
    }

    /// An inspection task completed. Only the task that belongs to the
    /// current flow opens the options dialog.
    pub fn on_inspected(&mut self, task: u64, path: &PathBuf) -> FlowAction {
        match self {
            ImportFlow::Inspecting {
                path: current,
                task: current_task,
            } if *current_task == task && current == path => {
                *self = ImportFlow::Options { path: path.clone() };
                FlowAction::OpenOptions(path.clone())
            }
            _ => FlowAction::IgnoreStale,
        }
    }

    /// The user cancelled the options dialog.
    pub fn cancel(&mut self) -> FlowAction {
        match self {
            ImportFlow::Options { .. } | ImportFlow::Inspecting { .. } => {
                *self = ImportFlow::Idle;
                FlowAction::None
            }
            ImportFlow::Analyzing { path, .. } => {
                // Analysis already started; it keeps running but no longer
                // drives screen transitions.
                let _ = path;
                *self = ImportFlow::Idle;
                FlowAction::None
            }
            ImportFlow::Idle => FlowAction::None,
        }
    }

    /// The user confirmed the options; record the analysis task.
    pub fn begin_analysis(&mut self, path: &PathBuf, task: u64) -> FlowAction {
        match self {
            ImportFlow::Options { path: current } if current == path => {
                *self = ImportFlow::Analyzing {
                    path: path.clone(),
                    task,
                };
                FlowAction::None
            }
            _ => FlowAction::IgnoreStale,
        }
    }

    /// An analysis task completed. Only the current flow's task switches to
    /// the CodeBrowser.
    pub fn on_analyzed(&mut self, task: u64, path: &PathBuf) -> FlowAction {
        match self {
            ImportFlow::Analyzing {
                path: current,
                task: current_task,
            } if *current_task == task && current == path => {
                *self = ImportFlow::Idle;
                FlowAction::AnalysisReady(path.clone())
            }
            _ => FlowAction::IgnoreStale,
        }
    }

    /// The current program was closed.
    pub fn close(&mut self) {
        *self = ImportFlow::Idle;
    }

    /// Path currently being imported, if any.
    pub fn active_path(&self) -> Option<&PathBuf> {
        match self {
            ImportFlow::Idle => None,
            ImportFlow::Inspecting { path, .. }
            | ImportFlow::Options { path }
            | ImportFlow::Analyzing { path, .. } => Some(path),
        }
    }
}

/// A duplicate import for the same binary was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateImport;

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        PathBuf::from(format!("C:/fixtures/{name}.dll"))
    }

    #[test]
    fn import_flow_runs_inspection_options_analysis_then_ready() {
        let mut flow = ImportFlow::Idle;
        let binary = path("demo");

        flow.begin_inspection(&binary, 1).unwrap();
        assert_eq!(
            flow,
            ImportFlow::Inspecting {
                path: binary.clone(),
                task: 1
            }
        );

        assert_eq!(
            flow.on_inspected(1, &binary),
            FlowAction::OpenOptions(binary.clone())
        );
        assert_eq!(
            flow,
            ImportFlow::Options {
                path: binary.clone()
            }
        );

        assert_eq!(flow.begin_analysis(&binary, 2), FlowAction::None);
        assert_eq!(
            flow,
            ImportFlow::Analyzing {
                path: binary.clone(),
                task: 2
            }
        );

        assert_eq!(
            flow.on_analyzed(2, &binary),
            FlowAction::AnalysisReady(binary.clone())
        );
        assert_eq!(flow, ImportFlow::Idle);
    }

    #[test]
    fn cancel_from_options_returns_to_idle_without_analysis() {
        let mut flow = ImportFlow::Idle;
        let binary = path("demo");
        flow.begin_inspection(&binary, 1).unwrap();
        flow.on_inspected(1, &binary);
        assert_eq!(flow.cancel(), FlowAction::None);
        assert_eq!(flow, ImportFlow::Idle);
    }

    #[test]
    fn stale_inspection_event_is_ignored() {
        let mut flow = ImportFlow::Idle;
        flow.begin_inspection(&path("first"), 1).unwrap();
        // A late result from an older import must not open options.
        assert_eq!(
            flow.on_inspected(99, &path("first")),
            FlowAction::IgnoreStale
        );
        assert_eq!(
            flow,
            ImportFlow::Inspecting {
                path: path("first"),
                task: 1
            }
        );
    }

    #[test]
    fn stale_analysis_event_is_ignored() {
        let mut flow = ImportFlow::Idle;
        let binary = path("demo");
        flow.begin_inspection(&binary, 1).unwrap();
        flow.on_inspected(1, &binary);
        flow.begin_analysis(&binary, 2);
        assert_eq!(flow.on_analyzed(3, &binary), FlowAction::IgnoreStale);
        assert_eq!(
            flow,
            ImportFlow::Analyzing {
                path: binary,
                task: 2
            }
        );
    }

    #[test]
    fn duplicate_import_is_refused() {
        let mut flow = ImportFlow::Idle;
        let binary = path("demo");
        flow.begin_inspection(&binary, 1).unwrap();
        assert!(flow.begin_inspection(&binary, 2).is_err());
        // A different binary is still allowed.
        assert!(flow.begin_inspection(&path("other"), 3).is_ok());
    }

    #[test]
    fn close_program_resets_the_flow() {
        let mut flow = ImportFlow::Idle;
        let binary = path("demo");
        flow.begin_inspection(&binary, 1).unwrap();
        flow.close();
        assert_eq!(flow, ImportFlow::Idle);
    }
}
