use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use ghirust_core::analysis::{AnalysisOptions, FunctionAnalysis, ProgramAnalysis};
use ghirust_core::program_search::{
    ProgramSearchHit, ProgramSearchMode, ProgramSearchOptions, search_program,
};
use ghirust_core::project::{ProgramEntry, Project};
use ghirust_core::resources::{PressureState, Priority, ResourceBudget};
use ghirust_core::{SearchHit, SearchIndex, SearchReport};
use ghirust_gui::{
    ApiError, BinaryInspection, IndexedProject, ResourceState, TaskEvent, TaskId, TaskManager,
    TaskResult,
};
use serde::{Deserialize, Serialize};

mod state;
mod theme;

use state::{FlowAction, ImportFlow, Screen, TransitionReason};
use theme::Palette;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
enum Language {
    #[default]
    PtPt,
    PtBr,
    EnUs,
    RuRu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
enum Theme {
    #[default]
    Dark,
    Light,
}

/// Persisted resource limits (normalized to safety floors on apply).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
struct PersistedBudget {
    profile: ProfileSel,
    worker_threads: usize,
    max_concurrent_tasks: usize,
    ram_mb: usize,
    cpu_ceiling: u8,
    cache_mb: usize,
}

impl Default for PersistedBudget {
    fn default() -> Self {
        let budget = ResourceBudget::balanced();
        Self {
            profile: ProfileSel::Balanced,
            worker_threads: budget.max_worker_threads,
            max_concurrent_tasks: budget.max_concurrent_tasks,
            ram_mb: budget.max_process_ram_bytes / (1024 * 1024),
            cpu_ceiling: (budget.cpu_ceiling * 100.0) as u8,
            cache_mb: budget.cache_limit_bytes / (1024 * 1024),
        }
    }
}

impl PersistedBudget {
    fn into_budget(self) -> ResourceBudget {
        let (worker_threads, max_concurrent_tasks, ram_mb, cpu_ceiling, cache_mb) =
            match self.profile {
                ProfileSel::Conservative => {
                    let budget = ResourceBudget::conservative();
                    (
                        budget.max_worker_threads,
                        budget.max_concurrent_tasks,
                        budget.max_process_ram_bytes / (1024 * 1024),
                        (budget.cpu_ceiling * 100.0) as u8,
                        budget.cache_limit_bytes / (1024 * 1024),
                    )
                }
                ProfileSel::Balanced => {
                    let budget = ResourceBudget::balanced();
                    (
                        budget.max_worker_threads,
                        budget.max_concurrent_tasks,
                        budget.max_process_ram_bytes / (1024 * 1024),
                        (budget.cpu_ceiling * 100.0) as u8,
                        budget.cache_limit_bytes / (1024 * 1024),
                    )
                }
                ProfileSel::Performance => {
                    let budget = ResourceBudget::performance();
                    (
                        budget.max_worker_threads,
                        budget.max_concurrent_tasks,
                        budget.max_process_ram_bytes / (1024 * 1024),
                        (budget.cpu_ceiling * 100.0) as u8,
                        budget.cache_limit_bytes / (1024 * 1024),
                    )
                }
                ProfileSel::Custom => (
                    self.worker_threads.max(1),
                    self.max_concurrent_tasks.max(1),
                    self.ram_mb.max(64),
                    self.cpu_ceiling.clamp(10, 95),
                    self.cache_mb.max(8),
                ),
            };
        ResourceBudget {
            max_worker_threads: worker_threads,
            max_concurrent_tasks,
            max_process_ram_bytes: ram_mb * 1024 * 1024,
            cpu_ceiling: cpu_ceiling as f32 / 100.0,
            cache_limit_bytes: cache_mb * 1024 * 1024,
            auto_throttle: true,
            pause_on_critical: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
enum ProfileSel {
    Conservative,
    #[default]
    Balanced,
    Performance,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Preferences {
    language: Language,
    theme: Theme,
    budget: PersistedBudget,
}

/// Analysis preset: maps to concrete analyzer options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalysisPreset {
    Quick,
    Standard,
    Deep,
}

/// One analyzer row in the Analysis Options dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnalyzerEntry {
    id: &'static str,
    key: &'static str,
    quick: bool,
    standard: bool,
    deep: bool,
    description: &'static str,
}

const ANALYZERS: &[AnalyzerEntry] = &[
    AnalyzerEntry {
        id: "disassemble",
        key: "analyzer_disassemble",
        quick: true,
        standard: true,
        deep: true,
        description: "Decodes x86/x86-64 instructions with iced-x86 (always on).",
    },
    AnalyzerEntry {
        id: "function_discovery",
        key: "analyzer_functions",
        quick: true,
        standard: true,
        deep: true,
        description: "Finds function entries from exports, symbols, calls, branches and prologues.",
    },
    AnalyzerEntry {
        id: "strings",
        key: "analyzer_strings",
        quick: true,
        standard: true,
        deep: true,
        description: "Extracts printable ASCII/UTF-16 strings.",
    },
    AnalyzerEntry {
        id: "imports_exports",
        key: "analyzer_imports",
        quick: true,
        standard: true,
        deep: true,
        description: "Loads imports and exports from the container.",
    },
    AnalyzerEntry {
        id: "references",
        key: "analyzer_references",
        quick: false,
        standard: true,
        deep: true,
        description: "Records call/jump/data cross-references.",
    },
    AnalyzerEntry {
        id: "control_flow",
        key: "analyzer_control_flow",
        quick: true,
        standard: true,
        deep: true,
        description: "Builds basic blocks and CFG edges for every function.",
    },
    AnalyzerEntry {
        id: "decompile",
        key: "analyzer_decompile",
        quick: false,
        standard: true,
        deep: true,
        description: "Reconstructs C-like pseudocode (heuristic).",
    },
    AnalyzerEntry {
        id: "deep_prologues",
        key: "analyzer_deep",
        quick: false,
        standard: false,
        deep: true,
        description: "Deep mode: raises limits, enables prologue discovery and larger sweeps.",
    },
];

#[derive(Debug, Clone, Default)]
struct AnalysisForm {
    preset: Option<AnalysisPreset>,
    enabled: std::collections::BTreeSet<&'static str>,
    max_functions: usize,
    profile: ProfileSel,
}

impl AnalysisForm {
    fn apply_preset(&mut self, preset: AnalysisPreset) {
        self.preset = Some(preset);
        self.enabled.clear();
        for analyzer in ANALYZERS {
            let active = match preset {
                AnalysisPreset::Quick => analyzer.quick,
                AnalysisPreset::Standard => analyzer.standard,
                AnalysisPreset::Deep => analyzer.deep,
            };
            if active {
                self.enabled.insert(analyzer.id);
            }
        }
        self.max_functions = match preset {
            AnalysisPreset::Quick => 2_000,
            AnalysisPreset::Standard => 100_000,
            AnalysisPreset::Deep => 1_000_000,
        };
    }

    fn to_options(&self) -> AnalysisOptions {
        let decompile = self.enabled.contains("decompile");
        let discover_prologues = self.enabled.contains("deep_prologues") || decompile;
        AnalysisOptions {
            max_functions: self.max_functions,
            discover_prologues,
            decompile,
            max_linear_scan_instructions: if self.enabled.contains("deep_prologues") {
                80_000_000
            } else {
                20_000_000
            },
            ..AnalysisOptions::default()
        }
    }

    fn budget(&self) -> ResourceBudget {
        match self.profile {
            ProfileSel::Conservative => ResourceBudget::conservative(),
            ProfileSel::Balanced => ResourceBudget::balanced(),
            ProfileSel::Performance => ResourceBudget::performance(),
            ProfileSel::Custom => ResourceBudget::balanced(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct StringSearchForm {
    open: bool,
    min_length: usize,
    include_utf16: bool,
    deduplicate: bool,
    filter: String,
}

/// State of the advanced program search screen.
#[derive(Debug, Clone)]
struct ProgramSearchState {
    mode: ghirust_core::ProgramSearchMode,
    query: String,
    max_results: usize,
    report: Option<ghirust_core::ProgramSearchReport>,
    scope: SearchScope,
}

impl Default for ProgramSearchState {
    fn default() -> Self {
        Self {
            mode: ghirust_core::ProgramSearchMode::ProgramText,
            query: String::new(),
            max_results: 500,
            report: None,
            scope: SearchScope::Program,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchScope {
    /// Search the current analyzed program.
    Program,
    /// Search the persistent index of the open exported-source project.
    Index,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

struct TaskView {
    id: TaskId,
    label: String,
    stage: String,
    status: TaskStatus,
    started: Instant,
    elapsed: Duration,
    can_cancel: bool,
    priority: Option<Priority>,
}

struct GhirustApp {
    preferences: Preferences,
    screen: Screen,
    task_manager: TaskManager,
    tasks: Vec<TaskView>,
    binary: Option<BinaryInspection>,
    analysis: Option<ProgramAnalysis>,
    project_root: Option<PathBuf>,
    project_programs: Vec<ProgramEntry>,
    project_filter: String,
    project_view_tree: bool,
    project_index: Option<SearchIndex>,
    search_query: String,
    search_report: Option<SearchReport>,
    string_filter: String,
    selected_function: Option<usize>,
    selected_code_function: Option<usize>,
    code_function_filter: String,
    left_tab: LeftTab,
    bottom_tab: BottomTab,
    detail_filter: String,
    string_results: Vec<ghirust_core::StringRecord>,
    error: Option<ApiError>,
    notice: Option<String>,
    /// Import/analysis flow machine (see `state.rs`).
    import_flow: ImportFlow,
    /// Bounded log of screen transitions, for diagnostics and tests.
    transition_log: Vec<(Screen, TransitionReason)>,
    /// Folder awaiting user confirmation before indexing.
    pending_index_folder: Option<PathBuf>,
    /// Advanced program search state.
    program_search: ProgramSearchState,
    /// Binary waiting for the Analysis Options dialog.
    analysis_form: Option<(PathBuf, AnalysisForm)>,
    show_resource_settings: bool,
    show_resource_monitor_window: bool,
    resource_settings: PersistedBudget,
    resource_state: Option<ResourceState>,
    last_telemetry: Instant,
    cpu_history: VecDeque<f32>,
    ram_history: VecDeque<f32>,
    string_search: StringSearchForm,
    /// CodeBrowser navigation history.
    navigation: Vec<usize>,
    navigation_pos: Option<usize>,
    go_to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeftTab {
    Functions,
    Symbols,
    Trees,
    Types,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BottomTab {
    Tasks,
    Console,
    Summary,
    Graph,
    Xrefs,
    ResourceMonitor,
    Problems,
}

impl GhirustApp {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        let preferences: Preferences = context
            .storage
            .and_then(|storage| {
                storage
                    .get_string("preferences")
                    .and_then(|value| serde_json::from_str(&value).ok())
            })
            .unwrap_or_default();
        let task_manager = TaskManager::default();
        task_manager.set_budget(preferences.budget.into_budget());
        let resource_settings = preferences.budget;
        Self {
            preferences,
            screen: Screen::Project,
            task_manager,
            tasks: Vec::new(),
            binary: None,
            analysis: None,
            project_root: None,
            project_programs: Vec::new(),
            project_filter: String::new(),
            project_view_tree: false,
            project_index: None,
            search_query: String::new(),
            search_report: None,
            string_filter: String::new(),
            selected_function: None,
            selected_code_function: None,
            code_function_filter: String::new(),
            left_tab: LeftTab::Functions,
            bottom_tab: BottomTab::Tasks,
            detail_filter: String::new(),
            string_results: Vec::new(),
            error: None,
            notice: None,
            analysis_form: None,
            show_resource_settings: false,
            show_resource_monitor_window: false,
            resource_settings,
            resource_state: None,
            last_telemetry: Instant::now(),
            cpu_history: VecDeque::new(),
            ram_history: VecDeque::new(),
            string_search: StringSearchForm {
                open: false,
                min_length: 5,
                include_utf16: true,
                deduplicate: true,
                filter: String::new(),
            },
            navigation: Vec::new(),
            navigation_pos: None,
            go_to: String::new(),
            import_flow: ImportFlow::Idle,
            transition_log: Vec::new(),
            pending_index_folder: None,
            program_search: ProgramSearchState::default(),
        }
    }

    fn palette(&self) -> Palette {
        if self.preferences.theme == Theme::Light {
            Palette::light()
        } else {
            Palette::dark()
        }
    }

    /// The only way screens change. Every transition is recorded so stale
    /// flows and accidental mixed content are visible in diagnostics.
    fn transition_to(&mut self, screen: Screen, reason: TransitionReason) {
        if self.screen != screen || matches!(reason, TransitionReason::AnalysisFinished) {
            self.transition_log.push((screen, reason));
            if self.transition_log.len() > 40 {
                self.transition_log.remove(0);
            }
        }
        self.screen = screen;
    }

    /// Close the current program and clear every program-bound state.
    fn close_program(&mut self) {
        self.binary = None;
        self.analysis = None;
        self.selected_code_function = None;
        self.navigation.clear();
        self.navigation_pos = None;
        self.go_to.clear();
        self.search_report = None;
        self.program_search.report = None;
        self.string_results.clear();
        self.import_flow.close();
        self.analysis_form = None;
        self.transition_to(Screen::Project, TransitionReason::ProgramClosed);
    }

    fn tr(&self, key: &str) -> &'static str {
        match (self.preferences.language, key) {
            (_, "app_title") => "GHIRUST",
            (Language::PtPt, "home") => "Início",
            (Language::PtBr, "home") => "Início",
            (Language::EnUs, "home") => "Home",
            (Language::RuRu, "home") => "Главная",
            (Language::PtPt, "analysis") => "Análise",
            (Language::PtBr, "analysis") => "Análise",
            (Language::EnUs, "analysis") => "Analysis",
            (Language::RuRu, "analysis") => "Анализ",
            (Language::PtPt, "functions") => "Funções",
            (Language::PtBr, "functions") => "Funções",
            (Language::EnUs, "functions") => "Functions",
            (Language::RuRu, "functions") => "Функции",
            (Language::PtPt, "search") => "Pesquisa",
            (Language::PtBr, "search") => "Pesquisa",
            (Language::EnUs, "search") => "Search",
            (Language::RuRu, "search") => "Поиск",
            (Language::PtPt, "strings") => "Strings",
            (Language::PtBr, "strings") => "Strings",
            (Language::EnUs, "strings") => "Strings",
            (Language::RuRu, "strings") => "Строки",
            (Language::PtPt, "command_center") => "Centro de controlo",
            (Language::PtBr, "command_center") => "Central de controle",
            (Language::EnUs, "command_center") => "Command Center",
            (Language::RuRu, "command_center") => "Центр управления",
            (Language::PtPt, "code_browser") => "Navegador de código",
            (Language::PtBr, "code_browser") => "Navegador de código",
            (Language::EnUs, "code_browser") => "Code browser",
            (Language::RuRu, "code_browser") => "Обозреватель кода",
            (Language::PtPt, "listing") => "Listagem",
            (Language::PtBr, "listing") => "Listagem",
            (Language::EnUs, "listing") => "Listing",
            (Language::RuRu, "listing") => "Дизассемблер",
            (Language::PtPt, "decompile") => "Pseudocódigo",
            (Language::PtBr, "decompile") => "Pseudocódigo",
            (Language::EnUs, "decompile") => "Pseudocode",
            (Language::RuRu, "decompile") => "Псевдокод",
            (Language::PtPt, "summary") => "Resumo",
            (Language::PtBr, "summary") => "Resumo",
            (Language::EnUs, "summary") => "Summary",
            (Language::RuRu, "summary") => "Сводка",
            (Language::PtPt, "graph") => "Grafo CFG",
            (Language::PtBr, "graph") => "Grafo CFG",
            (Language::EnUs, "graph") => "CFG graph",
            (Language::RuRu, "graph") => "Граф CFG",
            (Language::PtPt, "symbols") => "Símbolos",
            (Language::PtBr, "symbols") => "Símbolos",
            (Language::EnUs, "symbols") => "Symbols",
            (Language::RuRu, "symbols") => "Символы",
            (Language::PtPt, "xrefs") => "Referências",
            (Language::PtBr, "xrefs") => "Referências",
            (Language::EnUs, "xrefs") => "Cross-references",
            (Language::RuRu, "xrefs") => "Ссылки",
            (Language::PtPt, "warnings") => "Avisos",
            (Language::PtBr, "warnings") => "Avisos",
            (Language::EnUs, "warnings") => "Warnings",
            (Language::RuRu, "warnings") => "Предупреждения",
            (Language::PtPt, "settings") => "Definições",
            (Language::PtBr, "settings") => "Configurações",
            (Language::EnUs, "settings") => "Settings",
            (Language::RuRu, "settings") => "Настройки",
            (Language::PtPt, "tasks") => "Tarefas",
            (Language::PtBr, "tasks") => "Tarefas",
            (Language::EnUs, "tasks") => "Tasks",
            (Language::RuRu, "tasks") => "Задачи",
            (Language::PtPt, "console") => "Consola",
            (Language::PtBr, "console") => "Console",
            (Language::EnUs, "console") => "Console",
            (Language::RuRu, "console") => "Консоль",
            (Language::PtPt, "resource_monitor") => "Monitor de recursos",
            (Language::PtBr, "resource_monitor") => "Monitor de recursos",
            (Language::EnUs, "resource_monitor") => "Resource Monitor",
            (Language::RuRu, "resource_monitor") => "Монитор ресурсов",
            (Language::PtPt, "problems") => "Problemas",
            (Language::PtBr, "problems") => "Problemas",
            (Language::EnUs, "problems") => "Problems",
            (Language::RuRu, "problems") => "Проблемы",
            (Language::PtPt, "program_trees") => "Árvore do programa",
            (Language::PtBr, "program_trees") => "Árvore do programa",
            (Language::EnUs, "program_trees") => "Program Trees",
            (Language::RuRu, "program_trees") => "Дерево программы",
            (Language::PtPt, "data_types") => "Tipos de dados",
            (Language::PtBr, "data_types") => "Tipos de dados",
            (Language::EnUs, "data_types") => "Data Types",
            (Language::RuRu, "data_types") => "Типы данных",
            (Language::PtPt, "open_file") => "Abrir ficheiro",
            (Language::PtBr, "open_file") => "Abrir arquivo",
            (Language::EnUs, "open_file") => "Open file",
            (Language::RuRu, "open_file") => "Открыть файл",
            (Language::PtPt, "open_project") => "Abrir projeto de código",
            (Language::PtBr, "open_project") => "Abrir projeto de código",
            (Language::EnUs, "open_project") => "Open source project",
            (Language::RuRu, "open_project") => "Открыть проект исходного кода",
            (Language::PtPt, "welcome") => "Bem-vindo ao GHIRUST",
            (Language::PtBr, "welcome") => "Bem-vindo ao GHIRUST",
            (Language::EnUs, "welcome") => "Welcome to GHIRUST",
            (Language::RuRu, "welcome") => "Добро пожаловать в GHIRUST",
            (Language::PtPt, "drop_hint") => {
                "Abra um binário para inspecionar o formato e extrair strings, ou um projeto exportado para pesquisar funções e texto."
            }
            (Language::PtBr, "drop_hint") => {
                "Abra um binário para inspecionar o formato e extrair strings, ou um projeto exportado para pesquisar funções e texto."
            }
            (Language::EnUs, "drop_hint") => {
                "Open a binary to inspect its format and extract strings, or an exported source project to search functions and text."
            }
            (Language::RuRu, "drop_hint") => {
                "Откройте двоичный файл для анализа формата и извлечения строк или экспортированный проект для поиска."
            }
            _ => "?",
        }
    }

    fn open_path(&mut self, path: PathBuf) {
        self.error = None;
        self.notice = None;
        if path.is_dir() {
            self.open_project(path);
        } else {
            self.open_binary(path);
        }
    }

    fn open_binary(&mut self, path: PathBuf) {
        // Never start two imports for the same binary.
        if self.import_flow.active_path() == Some(&path) {
            self.notice = Some(format!("{} is already being imported.", path.display()));
            return;
        }
        self.binary = None;
        self.analysis = None;
        self.selected_code_function = None;
        self.code_function_filter.clear();
        self.detail_filter.clear();
        self.search_report = None;
        match self.task_manager.start_inspection(path.clone()) {
            Ok(task) => {
                if self.import_flow.begin_inspection(&path, task).is_err() {
                    self.notice = Some(format!("{} is already being imported.", path.display()));
                    return;
                }
                self.transition_to(Screen::Project, TransitionReason::ImportStarted);
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn open_project(&mut self, path: PathBuf) {
        // A GHIRUST project store opens as an active project (Ghidra-style
        // Project Window). Anything else asks before indexing: a folder is
        // never indexed silently.
        if let Ok(project) = Project::open(&path) {
            self.project_root = Some(path.clone());
            self.project_programs = project.programs().to_vec();
            self.project_filter.clear();
            self.project_index = None;
            self.search_report = None;
            self.binary = None;
            self.analysis = None;
            self.selected_code_function = None;
            self.transition_to(Screen::Project, TransitionReason::UserAction);
            return;
        }
        self.pending_index_folder = Some(path);
    }

    /// User confirmed indexing a non-project folder as an exported-source
    /// project.
    fn confirm_index_folder(&mut self) {
        let Some(path) = self.pending_index_folder.take() else {
            return;
        };
        self.project_root = Some(path.clone());
        self.project_index = None;
        self.search_report = None;
        self.binary = None;
        self.analysis = None;
        self.selected_code_function = None;
        match self.task_manager.start_indexing(path) {
            Ok(_) => self.transition_to(Screen::Functions, TransitionReason::UserAction),
            Err(error) => self.error = Some(error),
        }
    }

    /// Open a program stored in the active project.
    fn open_project_program(&mut self, program: ProgramEntry) {
        let Some(root) = self.project_root.clone() else {
            return;
        };
        // Reuse a valid saved analysis when one exists.
        if let Ok(project) = Project::open(&root)
            && project.analysis_path(&program.id).is_file()
            && let Ok(analysis) = project.load_analysis(&program.id)
        {
            self.notice = Some(format!(
                "Loaded saved analysis for {}: {} function(s).",
                program.display_name, analysis.stats.functions
            ));
            self.binary = None;
            self.analysis = Some(analysis);
            self.selected_code_function = Some(0);
            self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
            return;
        }
        let Ok(path) =
            std::fs::canonicalize(root.join("programs").join(&program.id).join("binary"))
                .or_else(|_| std::fs::canonicalize(&program.source_path))
        else {
            self.error = Some(ApiError {
                code: "missing_binary",
                message: format!("The binary for {} is not available.", program.display_name),
                suggestion: "Re-import the file into the project.",
            });
            return;
        };
        self.open_binary(path);
    }

    fn search_project(&mut self) {
        let Some(root) = self.project_root.clone() else {
            return;
        };
        self.error = None;
        self.search_report = None;
        match self
            .task_manager
            .start_search(root, self.search_query.clone(), 200)
        {
            Ok(_) => self.transition_to(Screen::Search, TransitionReason::UserAction),
            Err(error) => self.error = Some(error),
        }
    }

    fn export_project(&mut self) {
        let Some(root) = self.project_root.clone() else {
            return;
        };
        let Some(output) = rfd::FileDialog::new()
            .set_file_name("ghirust-export.c")
            .save_file()
        else {
            return;
        };
        self.error = None;
        match self.task_manager.start_export(root, output) {
            Ok(_) => self.transition_to(Screen::CommandCenter, TransitionReason::UserAction),
            Err(error) => self.error = Some(error),
        }
    }

    fn pick_binary(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.open_binary(path);
        }
    }

    fn pick_project(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            self.open_project(path);
        }
    }

    fn process_events(&mut self) {
        for event in self.task_manager.drain_events() {
            match event {
                TaskEvent::Started {
                    id,
                    label,
                    priority,
                } => {
                    let can_cancel = label.starts_with("Inspect ")
                        || label.starts_with("Analyze ")
                        || label.starts_with("Search ");
                    self.tasks.push(TaskView {
                        id,
                        label,
                        stage: "Starting".to_owned(),
                        status: TaskStatus::Running,
                        started: Instant::now(),
                        elapsed: Duration::ZERO,
                        can_cancel,
                        priority: Some(priority),
                    });
                    if self.tasks.len() > 100 {
                        self.tasks.remove(0);
                    }
                }
                TaskEvent::Progress { id, stage } => {
                    if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                        task.stage = stage;
                    }
                }
                TaskEvent::Completed { id, result } => {
                    if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                        task.status = TaskStatus::Completed;
                        task.elapsed = task.started.elapsed();
                        task.stage = "Completed".to_owned();
                    }
                    match *result {
                        TaskResult::BinaryInspected(inspection) => {
                            let path = inspection.path.clone();
                            let action = self.import_flow.on_inspected(id, &path);
                            self.binary = Some(inspection);
                            if matches!(action, FlowAction::OpenOptions(_)) {
                                // Inspection finished for the current import:
                                // open the Analysis Options dialog.
                                let mut form = AnalysisForm::default();
                                form.apply_preset(AnalysisPreset::Standard);
                                form.profile = self.resource_settings.profile;
                                self.analysis_form = Some((path, form));
                            }
                        }
                        TaskResult::AnalysisCompleted(analysis) => {
                            self.notice = Some(format!(
                                "Analyzed {} function(s): {} instructions, {} blocks, {} xref(s) in {} ms.",
                                analysis.stats.functions,
                                analysis.stats.instructions,
                                analysis.stats.blocks,
                                analysis.stats.xrefs,
                                analysis.stats.elapsed_ms
                            ));
                            let path = analysis.path.clone();
                            let path_buf = std::path::PathBuf::from(&path);
                            let ready = matches!(
                                self.import_flow.on_analyzed(id, &path_buf),
                                FlowAction::AnalysisReady(_)
                            );
                            self.selected_code_function =
                                (!analysis.functions.is_empty()).then_some(0);
                            self.analysis = Some(*analysis);
                            if ready {
                                self.transition_to(
                                    Screen::CodeBrowser,
                                    TransitionReason::AnalysisFinished,
                                );
                            }
                        }
                        TaskResult::ProjectIndexed(IndexedProject {
                            root,
                            report,
                            index,
                        }) => {
                            self.project_root = Some(root);
                            self.project_index = Some(index);
                            self.notice = Some(format!(
                                "Indexed {} file(s) and {} function(s); cache: {} hit(s), {} miss(es).",
                                report.files,
                                report.functions,
                                report.cache_hits,
                                report.cache_misses
                            ));
                            if !report.cache_warnings.is_empty() {
                                self.notice = Some(format!(
                                    "{} Cache warnings: {}",
                                    self.notice.as_deref().unwrap_or_default(),
                                    report.cache_warnings.join("; ")
                                ));
                            }
                            self.transition_to(Screen::Functions, TransitionReason::UserAction);
                        }
                        TaskResult::SearchCompleted(report) => {
                            self.search_report = Some(report);
                            self.transition_to(Screen::Search, TransitionReason::UserAction);
                        }
                        TaskResult::ExportCompleted(report) => {
                            self.notice = Some(format!(
                                "Exported {} function(s), {} bytes written to {} in {} ms.",
                                report.records,
                                report.written_bytes,
                                report.output.display(),
                                report.elapsed_ms
                            ));
                            self.transition_to(Screen::CommandCenter, TransitionReason::UserAction);
                        }
                    }
                }
                TaskEvent::Failed { id, error } => {
                    if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                        task.status = TaskStatus::Failed;
                        task.elapsed = task.started.elapsed();
                        task.stage = "Failed".to_owned();
                    }
                    self.error = Some(error);
                }
                TaskEvent::Cancelled { id } => {
                    if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                        task.status = TaskStatus::Cancelled;
                        task.elapsed = task.started.elapsed();
                        task.stage = "Cancelled".to_owned();
                    }
                }
            }
        }
    }

    fn render_project(&mut self, ui: &mut egui::Ui) {
        // Toolbar (Ghidra Project Window style).
        ui.horizontal_wrapped(|ui| {
            if ui.button("New Project").clicked() {
                self.create_project();
            }
            if ui.button("Open Project").clicked() {
                self.pick_project();
            }
            if ui.button("Import File").clicked() {
                self.pick_binary();
            }
            if ui
                .add_enabled(
                    self.analysis.is_some(),
                    egui::Button::new("Open CodeBrowser"),
                )
                .clicked()
            {
                self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
            }
            if ui.button("Settings").clicked() {
                self.transition_to(Screen::Settings, TransitionReason::UserAction);
            }
        });
        ui.separator();

        egui::SidePanel::left("tool_chest")
            .resizable(true)
            .default_width(190.0)
            .show_inside(ui, |ui| {
                ui.heading("Tool Chest");
                ui.separator();
                if ui
                    .add_enabled(
                        self.analysis.is_some(),
                        egui::Button::new("CodeBrowser").min_size(egui::vec2(150.0, 0.0)),
                    )
                    .clicked()
                {
                    self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
                }
                if ui
                    .add_sized(
                        egui::vec2(150.0, 24.0),
                        egui::Button::new("Program Analysis"),
                    )
                    .clicked()
                {
                    self.transition_to(Screen::Analysis, TransitionReason::UserAction);
                }
                if ui
                    .add_enabled(
                        self.project_index.is_some(),
                        egui::Button::new("Search").min_size(egui::vec2(150.0, 0.0)),
                    )
                    .clicked()
                {
                    self.transition_to(Screen::Search, TransitionReason::UserAction);
                }
                if ui
                    .add_enabled(
                        self.analysis.is_some(),
                        egui::Button::new("Strings").min_size(egui::vec2(150.0, 0.0)),
                    )
                    .clicked()
                {
                    self.string_search.open = true;
                }
                if ui
                    .add_sized(
                        egui::vec2(150.0, 24.0),
                        egui::Button::new("Resource Monitor"),
                    )
                    .clicked()
                {
                    self.show_resource_monitor_window = true;
                }
                ui.add_enabled(
                    false,
                    egui::Button::new("Function Graph (not implemented)")
                        .min_size(egui::vec2(150.0, 0.0)),
                );
                ui.add_enabled(
                    false,
                    egui::Button::new("Call Graph (not implemented)")
                        .min_size(egui::vec2(150.0, 0.0)),
                );
                ui.add_enabled(
                    false,
                    egui::Button::new("Memory Map (not implemented)")
                        .min_size(egui::vec2(150.0, 0.0)),
                );
                ui.add_enabled(
                    false,
                    egui::Button::new("Script Manager (not implemented)")
                        .min_size(egui::vec2(150.0, 0.0)),
                );
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Active Project");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.selectable_value(&mut self.project_view_tree, true, "Tree");
                    ui.selectable_value(&mut self.project_view_tree, false, "Table");
                });
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.project_filter)
                    .hint_text("Filter files in the active project"),
            );
            ui.separator();
            let root_path = self.project_root.clone();
            let programs_empty = self.project_programs.is_empty();
            match (root_path.as_ref(), programs_empty) {
                (Some(root), false) => {
                    let programs = self.project_programs.clone();
                    let mut to_open = None;
                    egui::ScrollArea::vertical()
                        .id_salt("project-program-list")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for program in &programs {
                                if !self.project_filter.is_empty()
                                    && !program
                                        .display_name
                                        .to_lowercase()
                                        .contains(&self.project_filter.to_lowercase())
                                {
                                    continue;
                                }
                                let analyzed = program
                                    .analyzed_unix
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "never".to_owned());
                                let row = format!(
                                    "{:<24} {:<8} {:<10} {:<6} funcs  analyzed {}  {}",
                                    truncate_text(&program.display_name, 24),
                                    program.format,
                                    program.architecture,
                                    format!("{}-bit", program.bits),
                                    program.function_count,
                                    analyzed,
                                );
                                let double_clicked = if self.project_view_tree {
                                    ui.collapsing(
                                        format!(
                                            "{} (0x{})",
                                            program.display_name,
                                            &program.id[..8]
                                        ),
                                        |ui| {
                                            ui.monospace(row.clone());
                                            ui.label(format!("SHA-256: {}", program.sha256));
                                            if ui.button("Open in CodeBrowser").clicked() {
                                                to_open = Some(program.clone());
                                            }
                                        },
                                    )
                                    .header_response
                                    .double_clicked()
                                } else {
                                    let response = ui.selectable_label(false, &row);
                                    if response.clicked() {
                                        to_open = Some(program.clone());
                                    }
                                    false
                                };
                                if double_clicked {
                                    to_open = Some(program.clone());
                                }
                            }
                        });
                    if let Some(program) = to_open {
                        self.open_project_program(program);
                    }
                    ui.label(format!("Project root: {}", root.display()));
                }
                (Some(root), true) => {
                    ui.label(format!("Project opened: {}", root.display()));
                    ui.label("No programs imported yet. Use Import File.");
                }
                (None, _) => {
                    ui.label("No project is open.");
                    ui.label("Open a GHIRUST project folder or import a binary.");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("New Project").clicked() {
                            self.create_project();
                        }
                        if ui.button("Open Project").clicked() {
                            self.pick_project();
                        }
                        if ui.button("Import File").clicked() {
                            self.pick_binary();
                        }
                    });
                }
            }
        });

        egui::SidePanel::right("running_tools")
            .resizable(true)
            .default_width(210.0)
            .show_inside(ui, |ui| {
                ui.heading("Running Tools");
                ui.separator();
                if self.analysis.is_some() {
                    ui.label("· CodeBrowser");
                }
                if self.project_index.is_some() {
                    ui.label("· Search");
                }
                if self.string_search.open {
                    ui.label("· Search For Strings");
                }
                if self.show_resource_monitor_window {
                    ui.label("· Resource Monitor");
                }
                if self.screen == Screen::CommandCenter {
                    ui.label("· Command Center");
                }
            });
    }

    fn create_project(&mut self) {
        let Some(path) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "GhirustProject".to_owned());
        match Project::create(&path, &name) {
            Ok(_) => {
                self.project_root = Some(path);
                self.project_programs.clear();
                self.notice = Some(format!("Created project '{name}'."));
            }
            Err(error) => {
                self.error = Some(ApiError {
                    code: "project_create_failed",
                    message: format!("Could not create the project: {error}"),
                    suggestion: "Pick an empty or writable folder.",
                });
            }
        }
    }

    fn verify_project(&mut self) {
        let Some(root) = self.project_root.clone() else {
            return;
        };
        match Project::open(&root) {
            Ok(project) => match project.verify() {
                report if report.ok => self.notice = Some("Project verification: OK".to_owned()),
                report => {
                    self.error = Some(ApiError {
                        code: "project_verify_failed",
                        message: format!(
                            "Project verification failed for {} program(s).",
                            report
                                .programs
                                .iter()
                                .filter(|entry| !entry.binary_ok || !entry.analysis_ok)
                                .count()
                        ),
                        suggestion: "Re-import or re-analyze the affected programs.",
                    });
                }
            },
            Err(error) => {
                self.error = Some(ApiError {
                    code: "project_open_failed",
                    message: error.to_string(),
                    suggestion: "Open a folder that contains project.json.",
                });
            }
        }
    }

    fn render_analysis(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        if self.binary.is_none() {
            if let Some(analysis) = &self.analysis {
                let loader = &analysis.loader;
                ui.heading("Binary analysis");
                ui.label(&analysis.path);
                ui.add_space(8.0);
                egui::Grid::new("analysis-properties")
                    .num_columns(2)
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        property(ui, "Format", &loader.format);
                        property(ui, "Architecture", &loader.architecture);
                        property(ui, "Bitness", &format!("{}-bit", loader.bits));
                        property(ui, "Endianness", &loader.endian);
                        property(ui, "Kind", &loader.object_kind);
                        property(
                            ui,
                            "Operating system",
                            loader.os.as_deref().unwrap_or("unknown"),
                        );
                        property(ui, "Image base", &format!("0x{:x}", loader.image_base));
                        property(ui, "Entry point", &format!("0x{:x}", loader.entry));
                        property(ui, "Functions", &analysis.stats.functions.to_string());
                        property(ui, "Instructions", &analysis.stats.instructions.to_string());
                        property(ui, "Blocks", &analysis.stats.blocks.to_string());
                        property(ui, "Cross-references", &analysis.stats.xrefs.to_string());
                    });
                ui.add_space(12.0);
                if ui.button(self.tr("code_browser")).clicked() {
                    self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
                }
                return;
            }
            ui.heading("Binary inspection");
            ui.label("Waiting for the binary inspection task...");
            return;
        }
        let binary = self.binary.as_ref().expect("checked above");
        ui.heading(
            binary
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
        );
        ui.label(binary.path.display().to_string());
        ui.add_space(8.0);
        egui::Grid::new("binary-properties")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                property(ui, "Size", &format_bytes(binary.detection.file_size));
                property(ui, "Format", binary.detection.format.as_str());
                property(
                    ui,
                    "Architecture",
                    binary
                        .detection
                        .architecture
                        .as_deref()
                        .unwrap_or("Unavailable"),
                );
                property(
                    ui,
                    "Bitness",
                    &binary
                        .detection
                        .bits
                        .map(|bits| format!("{bits}-bit"))
                        .unwrap_or_else(|| "Unavailable".to_owned()),
                );
                property(
                    ui,
                    "Type",
                    binary.detection.kind.as_deref().unwrap_or("Unavailable"),
                );
                property(
                    ui,
                    "Operating system",
                    binary.detection.os.as_deref().unwrap_or("Unavailable"),
                );
                property(
                    ui,
                    "Detection confidence",
                    &format!("{:.0}%", binary.detection.confidence * 100.0),
                );
                property(ui, "Extracted strings", &binary.strings.len().to_string());
            });
        if !binary.detection.evidence.is_empty() {
            ui.collapsing("Detection evidence", |ui| {
                for evidence in &binary.detection.evidence {
                    ui.label(evidence);
                }
            });
        }
        if !binary.detection.warnings.is_empty() {
            ui.colored_label(palette.warning, "Warnings");
            for warning in &binary.detection.warnings {
                ui.label(warning);
            }
        }
        if !binary.detection.sections.is_empty() {
            ui.collapsing(
                format!("Sections ({})", binary.detection.sections.len()),
                |ui| {
                    for section in &binary.detection.sections {
                        ui.horizontal(|ui| {
                            ui.monospace(&section.name);
                            ui.label(format!(
                                "{} at 0x{:x}, file bytes: {}",
                                section.kind,
                                section.address,
                                section
                                    .file_size
                                    .map(|size| size.to_string())
                                    .unwrap_or_else(|| "unavailable".to_owned())
                            ));
                        });
                    }
                },
            );
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if self.analysis.is_some() && ui.button(self.tr("code_browser")).clicked() {
                self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
            }
            if ui.button(self.tr("strings")).clicked() {
                self.transition_to(Screen::Strings, TransitionReason::UserAction);
            }
        });
    }

    fn select_code_function(&mut self, index: Option<usize>) {
        if let Some(previous) = self.selected_code_function {
            if Some(previous) != index {
                // Record the previous selection for Back/Forward.
                let position = self.navigation_pos.unwrap_or(self.navigation.len());
                self.navigation.truncate(position);
                self.navigation.push(previous);
                self.navigation_pos = Some(self.navigation.len());
            }
        }
        self.selected_code_function = index;
    }

    fn navigate_back(&mut self) {
        let position = self.navigation_pos.unwrap_or(self.navigation.len());
        if position > 0 {
            let previous = self.navigation[position - 1];
            self.navigation_pos = Some(position - 1);
            self.selected_code_function = Some(previous);
            self.transition_to(Screen::CodeBrowser, TransitionReason::Navigation);
        }
    }

    fn navigate_forward(&mut self) {
        let position = self.navigation_pos.unwrap_or(self.navigation.len());
        if position < self.navigation.len() {
            let next = self.navigation[position];
            self.navigation_pos = Some(position + 1);
            self.selected_code_function = Some(next);
            self.transition_to(Screen::CodeBrowser, TransitionReason::Navigation);
        }
    }

    fn go_to_address(&mut self) {
        let address = if let Some(hex) = self.go_to.trim().strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            self.go_to.trim().parse::<u64>().ok()
        };
        let Some(address) = address else {
            return;
        };
        let Some(analysis) = self.analysis.as_ref() else {
            return;
        };
        let index = analysis
            .functions
            .iter()
            .position(|function| address >= function.address && address < function.end)
            .or_else(|| {
                analysis
                    .functions
                    .iter()
                    .position(|function| function.address >= address)
            });
        if let Some(index) = index {
            self.select_code_function(Some(index));
            self.transition_to(Screen::CodeBrowser, TransitionReason::Navigation);
        }
    }

    fn render_code_browser(&mut self, ui: &mut egui::Ui) {
        if self.analysis.is_none() {
            ui.heading(self.tr("code_browser"));
            ui.label("Open a binary to disassemble it and reconstruct pseudocode.");
            return;
        }
        let palette = self.palette();
        let functions_meta: Vec<(u64, String, u64)> = self
            .analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .functions
                    .iter()
                    .map(|function| {
                        (
                            function.address,
                            function.name.clone(),
                            function.instruction_count,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let total = functions_meta.len();
        let selected = self
            .selected_code_function
            .unwrap_or(0)
            .min(total.saturating_sub(1));
        let mut left_tab = self.left_tab;
        let mut bottom_tab = self.bottom_tab;
        let mut function_filter = self.code_function_filter.clone();
        let mut detail_filter = self.detail_filter.clone();

        egui::SidePanel::left("code_left")
            .resizable(true)
            .default_width(330.0)
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut left_tab, LeftTab::Functions, self.tr("functions"));
                    ui.selectable_value(&mut left_tab, LeftTab::Symbols, self.tr("symbols"));
                    ui.selectable_value(&mut left_tab, LeftTab::Trees, self.tr("program_trees"));
                    ui.selectable_value(&mut left_tab, LeftTab::Types, self.tr("data_types"));
                });
                ui.separator();
                match left_tab {
                    LeftTab::Functions => {
                        ui.add(
                            egui::TextEdit::singleline(&mut function_filter)
                                .hint_text("Filter by name or address"),
                        );
                        ui.label(format!("{total} recovered function(s)"));
                        ui.separator();
                        let needle = function_filter.to_lowercase();
                        let visible: Vec<usize> = functions_meta
                            .iter()
                            .enumerate()
                            .filter(|(_, (address, name, _))| {
                                needle.is_empty()
                                    || name.to_lowercase().contains(&needle)
                                    || format!("0x{address:x}").contains(&needle)
                            })
                            .map(|(index, _)| index)
                            .collect();
                        egui::ScrollArea::vertical()
                            .id_salt("code-function-list")
                            .auto_shrink([false, false])
                            .show_rows(ui, 22.0, visible.len(), |ui, rows| {
                                for row in rows {
                                    let index = visible[row];
                                    let (address, name, count) = &functions_meta[index];
                                    let label = format!(
                                        "0x{address:08x}  {:<26} {:>4} insn",
                                        truncate_text(name, 26),
                                        count
                                    );
                                    if ui
                                        .selectable_label(selected == index, label)
                                        .clicked()
                                    {
                                        self.select_code_function(Some(index));
                                    }
                                }
                            });
                    }
                    LeftTab::Symbols => {
                        egui::ScrollArea::vertical()
                            .id_salt("code-symbols")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if let Some(analysis) = self.analysis.as_ref() {
                                    render_symbols_panel(ui, analysis, "");
                                }
                            });
                    }
                    LeftTab::Trees => {
                        egui::ScrollArea::vertical()
                            .id_salt("code-trees")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.strong("Program Trees");
                                if let Some(analysis) = self.analysis.as_ref() {
                                    for section in &analysis.sections {
                                        ui.monospace(format!(
                                            "{}  0x{:08x}  +0x{:x}  {}",
                                            section.name,
                                            section.address,
                                            section.virtual_size,
                                            section.kind
                                        ));
                                    }
                                }
                                ui.separator();
                                ui.strong("Memory blocks (Ghidra-style view)");
                                ui.label("Sections are reported by the loader; see the Summary tab for imports, exports and statistics.");
                            });
                    }
                    LeftTab::Types => {
                        egui::ScrollArea::vertical()
                            .id_salt("code-types")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.strong("Data Type Manager");
                                for ty in [
                                    "void", "bool", "char", "int8", "uint8", "int16", "uint16",
                                    "int32", "uint32", "int64", "uint64", "float", "double",
                                    "pointer", "string",
                                ] {
                                    ui.monospace(ty);
                                }
                                ui.separator();
                                ui.label("Builtin scalar types used by the decompiler.");
                                ui.label(
                                    "Aggregate types (structs, unions, classes) are not recovered yet.",
                                );
                            });
                    }
                }
            });

        // Decompile panel on the right, listing in the middle.
        egui::SidePanel::right("code_decompile")
            .resizable(true)
            .default_width(520.0)
            .show_inside(ui, |ui| {
                ui.strong(self.tr("decompile"));
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("code-decompile-scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let function = self
                            .analysis
                            .as_ref()
                            .and_then(|analysis| analysis.functions.get(selected));
                        match function {
                            Some(function) => render_decompile_panel(ui, function, &palette),
                            None => {
                                ui.label("No pseudocode is available for this program.");
                            }
                        }
                    });
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.navigation_pos.unwrap_or(self.navigation.len()) > 0,
                        egui::Button::new("Back"),
                    )
                    .clicked()
                {
                    self.navigate_back();
                }
                if ui
                    .add_enabled(
                        self.navigation_pos.is_some()
                            && self.navigation_pos.unwrap() < self.navigation.len(),
                        egui::Button::new("Forward"),
                    )
                    .clicked()
                {
                    self.navigate_forward();
                }
                ui.label("Go to:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.go_to)
                        .hint_text("0x401000")
                        .desired_width(120.0),
                );
                if ui.button("Go").clicked()
                    || ui.input(|input| input.key_pressed(egui::Key::Enter))
                {
                    self.go_to_address();
                }
                ui.separator();
                if let Some(analysis) = self.analysis.as_ref() {
                    if let Some(function) = analysis.functions.get(selected) {
                        ui.monospace(format!("0x{:x}", function.address));
                        ui.strong(&function.name);
                        ui.label(format!(
                            "{} · {:.0}% confidence · {} block(s)",
                            function.discovery,
                            function.confidence * 100.0,
                            function.blocks.len()
                        ));
                    } else {
                        ui.label("No functions were recovered.");
                    }
                }
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("code-listing-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let function = self
                        .analysis
                        .as_ref()
                        .and_then(|analysis| analysis.functions.get(selected));
                    match function {
                        Some(function) => render_listing_panel(ui, function, &palette),
                        None => {
                            ui.label("No disassembly is available for this program.");
                        }
                    }
                });
        });

        egui::TopBottomPanel::bottom("code_bottom")
            .resizable(true)
            .default_height(240.0)
            .show_inside(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.selectable_value(&mut bottom_tab, BottomTab::Tasks, self.tr("tasks"));
                    ui.selectable_value(&mut bottom_tab, BottomTab::Console, self.tr("console"));
                    ui.selectable_value(&mut bottom_tab, BottomTab::Summary, self.tr("summary"));
                    ui.selectable_value(&mut bottom_tab, BottomTab::Graph, self.tr("graph"));
                    ui.selectable_value(&mut bottom_tab, BottomTab::Xrefs, self.tr("xrefs"));
                    ui.selectable_value(
                        &mut bottom_tab,
                        BottomTab::ResourceMonitor,
                        self.tr("resource_monitor"),
                    );
                    ui.selectable_value(&mut bottom_tab, BottomTab::Problems, self.tr("problems"));
                });
                egui::ScrollArea::vertical()
                    .id_salt("code-bottom-content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| match bottom_tab {
                        BottomTab::Tasks => self.render_tasks_panel(ui),
                        BottomTab::Console => {
                            ui.monospace("GHIRUST console");
                            ui.label("Scripting integration is not implemented yet.");
                            ui.separator();
                            if let Some(analysis) = self.analysis.as_ref() {
                                for warning in analysis.warnings.iter().take(40) {
                                    ui.label(warning);
                                }
                            }
                        }
                        BottomTab::Summary => {
                            if let Some(analysis) = self.analysis.as_ref() {
                                render_summary_panel(ui, analysis);
                            }
                        }
                        BottomTab::Graph => {
                            let function = self
                                .analysis
                                .as_ref()
                                .and_then(|analysis| analysis.functions.get(selected));
                            match function {
                                Some(function) => render_cfg_graph(ui, function, &palette),
                                None => {
                                    ui.label("Select a function to draw its control-flow graph.");
                                }
                            }
                        }
                        BottomTab::Xrefs => {
                            ui.add(
                                egui::TextEdit::singleline(&mut detail_filter)
                                    .hint_text("Filter cross-references"),
                            );
                            if let Some(analysis) = self.analysis.as_ref() {
                                render_xrefs_panel(ui, analysis, &detail_filter);
                            }
                        }
                        BottomTab::ResourceMonitor => self.render_resource_monitor(ui),
                        BottomTab::Problems => {
                            let function = self
                                .analysis
                                .as_ref()
                                .and_then(|analysis| analysis.functions.get(selected));
                            if let Some(analysis) = self.analysis.as_ref() {
                                render_warnings_panel(ui, analysis, function);
                            }
                        }
                    });
            });

        self.left_tab = left_tab;
        self.bottom_tab = bottom_tab;
        self.code_function_filter = function_filter;
        self.detail_filter = detail_filter;
    }

    fn render_functions(&mut self, ui: &mut egui::Ui) {
        if self.project_index.is_none() {
            ui.heading(self.tr("functions"));
            ui.label("Building the persistent project index...");
            return;
        }
        let search_label = self.tr("search");
        let (selected, search_clicked, export_clicked) = {
            let index = self.project_index.as_ref().expect("checked above");
            ui.horizontal(|ui| {
                ui.heading(self.tr("functions"));
                ui.label(format!(
                    "{} function marker(s) in {} text file(s)",
                    index.functions.len(),
                    index.files.len()
                ));
            });
            let mut search_clicked = false;
            let mut export_clicked = false;
            ui.horizontal(|ui| {
                search_clicked = ui.button(search_label).clicked();
                export_clicked = ui.button("Export source").clicked();
            });
            ui.separator();
            let mut selected = self.selected_function;
            egui::ScrollArea::vertical().show_rows(ui, 24.0, index.functions.len(), |ui, rows| {
                for row in rows {
                    let function = &index.functions[row];
                    let label = match &function.address {
                        Some(address) => format!("{}  @  {}", function.name, address),
                        None => function.name.clone(),
                    };
                    if ui.selectable_label(selected == Some(row), label).clicked() {
                        selected = Some(row);
                    }
                }
            });
            if let Some(function) = selected.and_then(|selected| index.functions.get(selected)) {
                ui.separator();
                ui.label(format!("Function: {}", function.name));
                ui.label(format!(
                    "File: {} | marker line: {}",
                    index
                        .files
                        .get(function.file_id as usize)
                        .map(|file| file.path.as_str())
                        .unwrap_or("unavailable"),
                    function.line
                ));
                ui.label("This is an imported function marker, not a decompilation result.");
            }
            (selected, search_clicked, export_clicked)
        };
        self.selected_function = selected;
        if search_clicked {
            self.transition_to(Screen::Search, TransitionReason::UserAction);
        }
        if export_clicked {
            self.export_project();
        }
    }

    fn render_program_search(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.tr("program_search"));
        ui.label(
            "Bounded search over the current ProgramAnalysis: functions, symbols, strings, listing patterns, xrefs and scalar immediates.",
        );
        ui.horizontal(|ui| {
            ui.label("Mode:");
            egui::ComboBox::from_id_salt("program-search-mode")
                .selected_text(self.program_search.mode.name())
                .show_ui(ui, |ui| {
                    for mode in ProgramSearchMode::ALL {
                        ui.selectable_value(&mut self.program_search.mode, mode, mode.name());
                    }
                });
            ui.label("Scope:");
            egui::ComboBox::from_id_salt("program-search-scope")
                .selected_text(match self.program_search.scope {
                    SearchScope::Program => "Program",
                    SearchScope::Index => "Index",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.program_search.scope,
                        SearchScope::Program,
                        "Program",
                    );
                    ui.selectable_value(
                        &mut self.program_search.scope,
                        SearchScope::Index,
                        "Index (not implemented)",
                    );
                });
            ui.label("Max results:");
            ui.add(egui::DragValue::new(&mut self.program_search.max_results).range(1..=10_000));
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.program_search.query)
                .hint_text("Text, address (0x...) or bytes (bytes:..)"),
        );
        let run = ui.button("Search").clicked();
        let clear = ui.button("Clear").clicked();
        if clear {
            self.program_search.report = None;
            self.program_search.query.clear();
        }
        if run {
            let options = ProgramSearchOptions {
                mode: self.program_search.mode,
                query: self.program_search.query.clone(),
                max_results: self.program_search.max_results,
            };
            if self.program_search.scope == SearchScope::Index {
                self.notice = Some(
                    "Index scope is not implemented for program search; searching the current program."
                        .to_owned(),
                );
                self.program_search.report = None;
            } else if let Some(analysis) = self.analysis.clone() {
                let report = search_program(&analysis, &options);
                self.program_search.report = Some(report);
            } else {
                self.error = Some(ApiError {
                    code: "no_analysis",
                    message: "Open and analyze a binary before running a program search."
                        .to_owned(),
                    suggestion: "Import a binary and complete the analysis first.",
                });
            }
        }

        let result_count = self
            .program_search
            .report
            .as_ref()
            .map_or(0, |report| report.hits.len());
        let report = self.program_search.report.clone();
        egui::ScrollArea::vertical()
            .id_salt("program-search-results")
            .max_height(420.0)
            .show_rows(ui, 8.0, result_count, |ui, rows| {
                if let Some(report) = report.as_ref() {
                    for row in rows {
                        let hit: ProgramSearchHit = match report.hits.get(row).cloned() {
                            Some(hit) => hit,
                            None => continue,
                        };
                        let response = ui.selectable_label(
                            false,
                            format!(
                                "{} @ {}",
                                hit.kind,
                                hit.address.map_or_else(
                                    || "any".to_owned(),
                                    |address| format!("0x{address:x}")
                                )
                            ),
                        );
                        if response.clicked() {
                            if let Some(address) = hit.address {
                                self.go_to = format!("0x{address:x}");
                                self.go_to_address();
                            }
                        }
                        ui.label(format!(
                            "function: {}",
                            hit.function.as_deref().unwrap_or("-")
                        ));
                        ui.label(truncate_text(&hit.preview, 120));
                    }
                }
            });
        if let Some(report) = &self.program_search.report {
            ui.label(format!(
                "{} hit(s) for {} query {:?}",
                report.hits.len(),
                report.mode.name(),
                report.query
            ));
            if report.truncated {
                ui.colored_label(
                    self.palette().warning,
                    "Results truncated at the configured limit.",
                );
            }
        }
    }

    fn render_search(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.tr("search"));
        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Function, address, path, or source text"),
            );
            let submitted =
                response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if ui.button("Search").clicked() || submitted {
                self.search_project();
            }
            if ui.button("Index project").clicked() {
                self.pick_project();
            }
        });
        if let Some(report) = &self.search_report {
            ui.label(format!(
                "{} result(s), {} bytes scanned in {} ms{}",
                report.hits.len(),
                report.scanned_bytes,
                report.elapsed_ms,
                if report.truncated {
                    " (results limited)"
                } else {
                    ""
                }
            ));
            egui::ScrollArea::vertical().show_rows(ui, 68.0, report.hits.len(), |ui, rows| {
                for row in rows {
                    render_search_hit(ui, &report.hits[row]);
                }
            });
        } else if self.project_index.is_none() {
            ui.label("Open a source project and wait for indexing before searching.");
        }
    }

    fn render_strings(&mut self, ui: &mut egui::Ui) {
        let records: &[ghirust_core::StringRecord] = if let Some(binary) = &self.binary {
            &binary.strings
        } else if let Some(analysis) = &self.analysis {
            &analysis.strings
        } else {
            ui.heading(self.tr("strings"));
            ui.label("Open a binary to extract strings.");
            return;
        };
        ui.heading(format!("{} ({})", self.tr("strings"), records.len()));
        ui.text_edit_singleline(&mut self.string_filter);
        let strings: Vec<_> = records
            .iter()
            .filter(|record| {
                self.string_filter.is_empty()
                    || record
                        .value
                        .to_lowercase()
                        .contains(&self.string_filter.to_lowercase())
            })
            .collect();
        egui::ScrollArea::vertical().show_rows(ui, 24.0, strings.len(), |ui, rows| {
            for row in rows {
                let record = strings[row];
                ui.horizontal(|ui| {
                    ui.monospace(format!("0x{:08x}", record.offset));
                    ui.monospace(record.encoding.as_str());
                    ui.label(&record.value);
                });
            }
        });
    }

    fn render_command_center(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.tr("command_center"));
        ui.label(format!(
            "Active background tasks: {}",
            self.task_manager.active_count()
        ));
        ui.label("CPU utilization: unavailable (no system monitor is connected).");
        ui.label("GPU and VRAM: unavailable (no GPU backend or monitor is connected).");
        ui.label("RAM usage: unavailable (no process-memory monitor is connected).");
        ui.label("No queue, priority scheduler, pause/resume, or ETA is implemented.");
        ui.separator();
        for task in self.tasks.iter_mut().rev() {
            if task.status == TaskStatus::Running {
                task.elapsed = task.started.elapsed();
            }
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(&task.label);
                    ui.label(format!("{:?}", task.status));
                    ui.label(format!("{:.1}s", task.elapsed.as_secs_f32()));
                    if task.status == TaskStatus::Running
                        && task.can_cancel
                        && ui.button("Cancel at safe boundary").clicked()
                        && !self.task_manager.cancel(task.id)
                    {
                        self.error = Some(ApiError {
                            code: "cancel_unavailable",
                            message: "This operation cannot be cancelled by the current core backend."
                                .to_owned(),
                            suggestion: "Let the operation finish; its progress remains visible.",
                        });
                    }
                });
                ui.label(&task.stage);
                if !task.can_cancel && task.status == TaskStatus::Running {
                    ui.label(
                        "This operation runs to completion; cancellation is only available at safe stage boundaries.",
                    );
                }
            });
        }
    }

    fn render_tasks_panel(&mut self, ui: &mut egui::Ui) {
        ui.strong(format!(
            "Tasks ({} active)",
            self.task_manager.active_count()
        ));
        ui.separator();
        if self.tasks.is_empty() {
            ui.label("No tasks yet.");
            return;
        }
        for task in self.tasks.iter_mut().rev() {
            if task.status == TaskStatus::Running {
                task.elapsed = task.started.elapsed();
            }
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(&task.label);
                    ui.label(format!("{:?}", task.status));
                    if let Some(priority) = task.priority {
                        ui.label(priority_name(priority));
                    }
                    ui.label(format!("{:.1}s", task.elapsed.as_secs_f32()));
                });
                ui.label(&task.stage);
                if task.status == TaskStatus::Running && !task.can_cancel {
                    ui.label(
                        "This operation runs to completion; cancellation is only available at safe stage boundaries.",
                    );
                }
            });
        }
    }

    fn render_resource_monitor(&mut self, ui: &mut egui::Ui) {
        let Some(state) = self.resource_state.clone() else {
            ui.label("Telemetry is warming up...");
            return;
        };
        let palette = self.palette();
        let snapshot = state.snapshot;
        let budget = state.budget;
        let pressure_color = match state.pressure {
            PressureState::Normal => palette.success,
            PressureState::Warning => palette.warning,
            PressureState::HighPressure => palette.pressure_high,
            PressureState::Critical => palette.error,
            PressureState::Recovery => palette.info,
        };
        ui.horizontal(|ui| {
            ui.strong("Resource Monitor");
            ui.separator();
            ui.colored_label(pressure_color, pressure_name(state.pressure));
        });
        ui.separator();
        egui::Grid::new("resource-grid")
            .num_columns(3)
            .spacing([18.0, 6.0])
            .show(ui, |ui| {
                property(ui, "CPU (system)", &format!("{:.0}%", snapshot.cpu_percent));
                property(
                    ui,
                    "CPU ceiling",
                    &format!("{:.0}%", budget.cpu_ceiling * 100.0),
                );
                property(
                    ui,
                    "Worker threads",
                    &format!(
                        "{} (limit {})",
                        self.task_manager
                            .active_count()
                            .min(budget.max_worker_threads),
                        budget.max_worker_threads
                    ),
                );
                property(
                    ui,
                    "RAM (process)",
                    &format_bytes(snapshot.process_ram_bytes),
                );
                property(
                    ui,
                    "RAM available",
                    &format_bytes(snapshot.available_ram_bytes),
                );
                property(
                    ui,
                    "RAM budget",
                    &format_bytes(budget.max_process_ram_bytes as u64),
                );
                property(
                    ui,
                    "RAM reserved",
                    &format_bytes(state.reserved_ram_bytes as u64),
                );
                property(
                    ui,
                    "Active tasks",
                    &format!("{} / {}", state.active_tasks, budget.max_concurrent_tasks),
                );
                property(
                    ui,
                    "Reservations",
                    &format!(
                        "{} created · {} released",
                        state.reservations_created, state.reservations_released
                    ),
                );
                if state.gpu.available {
                    property(ui, "GPU", "available");
                } else {
                    property(ui, "GPU", "Unavailable");
                    property(ui, "VRAM", "Unavailable");
                }
            });
        if !state.gpu.available {
            ui.label(format!("GPU: {}", state.gpu.reason));
        }
        ui.separator();
        ui.strong("History (last 3 minutes)");
        sparkline(ui, &self.cpu_history, &palette, palette.success, "CPU %");
        sparkline(
            ui,
            &self.ram_history,
            &palette,
            palette.info,
            "Process RAM (MB)",
        );
        if state.pressure >= PressureState::HighPressure {
            ui.colored_label(
                palette.pressure_high,
                "Throttling is active: heavy tasks are refused or slowed down.",
            );
        }
    }

    fn render_analysis_options(&mut self, context: &egui::Context) {
        let Some((path, mut form)) = self.analysis_form.take() else {
            return;
        };
        let mut open = true;
        let mut start = false;
        let mut close = false;
        egui::Window::new("Analysis Options")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .show(context, |ui| {
                ui.label(format!("File: {}", path.display()));
                ui.separator();
                ui.horizontal(|ui| {
                    for (preset, label) in [
                        (AnalysisPreset::Quick, "Quick Analysis"),
                        (AnalysisPreset::Standard, "Standard Analysis"),
                        (AnalysisPreset::Deep, "Deep Analysis"),
                    ] {
                        if ui.selectable_label(form.preset == Some(preset), label).clicked() {
                            form.apply_preset(preset);
                        }
                    }
                });
                ui.separator();
                ui.strong("Analyzers");
                ui.label("Every analyzer runs under the ResourceManager budget; none may exceed the configured limits.");
                egui::ScrollArea::vertical()
                    .id_salt("analysis-options-list")
                    .max_height(320.0)
                    .show(ui, |ui| {
                        for analyzer in ANALYZERS {
                            let mut enabled = form.enabled.contains(analyzer.id);
                            ui.horizontal(|ui| {
                                if ui.checkbox(&mut enabled, "").changed() {
                                    if enabled {
                                        form.enabled.insert(analyzer.id);
                                    } else {
                                        form.enabled.remove(analyzer.id);
                                    }
                                    form.preset = None;
                                }
                                ui.vertical(|ui| {
                                    ui.strong(analyzer_name(analyzer.id));
                                    ui.small(analyzer.description);
                                });
                            });
                        }
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Function limit:");
                    ui.add(
                        egui::DragValue::new(&mut form.max_functions)
                            .range(1..=10_000_000),
                    );
                    ui.label("Resource profile:");
                    egui::ComboBox::from_id_salt("analysis-profile")
                        .selected_text(profile_name(form.profile))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut form.profile, ProfileSel::Conservative, "Conservative");
                            ui.selectable_value(&mut form.profile, ProfileSel::Balanced, "Balanced");
                            ui.selectable_value(&mut form.profile, ProfileSel::Performance, "Performance");
                        });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Select All").clicked() {
                        form.enabled = ANALYZERS.iter().map(|entry| entry.id).collect();
                        form.preset = None;
                    }
                    if ui.button("Deselect All").clicked() {
                        form.enabled.clear();
                        form.preset = None;
                    }
                    if ui.button("Reset").clicked() {
                        form.apply_preset(AnalysisPreset::Standard);
                    }
                    ui.separator();
                    if ui.button("Cancel").clicked() {
                        close = true;
                        self.import_flow.cancel();
                        self.transition_to(Screen::Project, TransitionReason::ImportCancelled);
                    }
                    if ui.button("Analyze").clicked() {
                        start = true;
                        close = true;
                    }
                });
            });
        if close {
            open = false;
        }
        if close && !start {
            self.import_flow.cancel();
        }
        if start {
            let budget = form.budget();
            self.task_manager.set_budget(budget);
            self.resource_settings.profile = form.profile;
            match self
                .task_manager
                .start_analysis_with_options(path.clone(), form.to_options())
            {
                Ok(task) => {
                    self.import_flow.begin_analysis(&path, task);
                }
                Err(error) => {
                    self.import_flow.cancel();
                    self.error = Some(error);
                }
            }
        } else if open {
            self.analysis_form = Some((path, form));
        }
    }

    fn render_resource_settings(&mut self, context: &egui::Context) {
        let mut open = self.show_resource_settings;
        let mut close = false;
        egui::Window::new("Resource Settings")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .show(context, |ui| {
                ui.label(
                    "Limits are enforced by the ResourceManager. Safety floors cannot be disabled.",
                );
                ui.separator();
                egui::ComboBox::from_id_salt("resource-profile")
                    .selected_text(profile_name(self.resource_settings.profile))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.resource_settings.profile,
                            ProfileSel::Conservative,
                            "Conservative",
                        );
                        ui.selectable_value(
                            &mut self.resource_settings.profile,
                            ProfileSel::Balanced,
                            "Balanced",
                        );
                        ui.selectable_value(
                            &mut self.resource_settings.profile,
                            ProfileSel::Performance,
                            "Performance",
                        );
                        ui.selectable_value(
                            &mut self.resource_settings.profile,
                            ProfileSel::Custom,
                            "Custom",
                        );
                    });
                egui::Grid::new("resource-settings-grid")
                    .num_columns(2)
                    .spacing([16.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Maximum Worker Threads");
                        ui.add(
                            egui::DragValue::new(&mut self.resource_settings.worker_threads)
                                .range(1..=64),
                        );
                        ui.end_row();
                        ui.label("Maximum Concurrent Tasks");
                        ui.add(
                            egui::DragValue::new(&mut self.resource_settings.max_concurrent_tasks)
                                .range(1..=32),
                        );
                        ui.end_row();
                        ui.label("Maximum RAM Usage (MB)");
                        ui.add(
                            egui::DragValue::new(&mut self.resource_settings.ram_mb)
                                .range(64..=32_768),
                        );
                        ui.end_row();
                        ui.label("Maximum CPU Usage (%)");
                        ui.add(
                            egui::DragValue::new(&mut self.resource_settings.cpu_ceiling)
                                .range(10..=95),
                        );
                        ui.end_row();
                        ui.label("Cache Limit (MB)");
                        ui.add(
                            egui::DragValue::new(&mut self.resource_settings.cache_mb)
                                .range(8..=16_384),
                        );
                        ui.end_row();
                    });
                ui.separator();
                let mut auto_throttle = true;
                let mut pause_on_critical = true;
                ui.add_enabled(
                    false,
                    egui::Checkbox::new(&mut auto_throttle, "Automatic Resource Throttling"),
                );
                ui.add_enabled(
                    false,
                    egui::Checkbox::new(&mut pause_on_critical, "Pause on Critical Pressure"),
                );
                ui.label("These protections are always enabled for system safety.");
                ui.label(
                    "GPU Fallback to CPU: the CPU backend is the only backend; GPU is unavailable.",
                );
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Apply").clicked() {
                        let budget = self.resource_settings.into_budget();
                        self.task_manager.set_budget(budget);
                        self.preferences.budget = self.resource_settings;
                        close = true;
                    }
                    if ui.button("Cancel").clicked() {
                        self.resource_settings = self.preferences.budget;
                        close = true;
                    }
                });
            });
        if close {
            open = false;
        }
        self.show_resource_settings = open;
    }

    fn render_string_search(&mut self, context: &egui::Context) {
        let mut open = self.string_search.open;
        egui::Window::new("Search For Strings")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Minimum Length:");
                    ui.add(egui::DragValue::new(&mut self.string_search.min_length).range(1..=64));
                });
                ui.checkbox(&mut self.string_search.include_utf16, "UTF-16 (LE)");
                ui.checkbox(&mut self.string_search.deduplicate, "Deduplicate");
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Search").clicked() {
                        if let Some(binary) = &self.binary {
                            let options = ghirust_core::StringOptions {
                                min_length: self.string_search.min_length,
                                utf16: self.string_search.include_utf16,
                                deduplicate: self.string_search.deduplicate,
                                ..ghirust_core::StringOptions::default()
                            };
                            match ghirust_core::extract_strings(&binary.path, &options) {
                                Ok(records) => self.string_results = records,
                                Err(error) => {
                                    self.error = Some(ApiError {
                                        code: "string_search_failed",
                                        message: error.to_string(),
                                        suggestion: "Verify the binary is readable.",
                                    });
                                }
                            }
                        }
                    }
                    if ui.button("Export CSV").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_file_name("strings.csv")
                            .save_file()
                        {
                            let mut csv = String::from("offset,encoding,value\n");
                            for record in &self.string_results {
                                csv.push_str(&format!(
                                    "{},{},{}\n",
                                    record.offset,
                                    record.encoding.as_str(),
                                    record.value.replace('"', "'")
                                ));
                            }
                            if let Err(error) = std::fs::write(&path, csv) {
                                self.error = Some(ApiError {
                                    code: "csv_write_failed",
                                    message: format!("Could not write {}: {error}", path.display()),
                                    suggestion: "Pick another output path.",
                                });
                            } else {
                                self.notice =
                                    Some(format!("Exported strings to {}", path.display()));
                            }
                        }
                    }
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::singleline(&mut self.string_search.filter)
                        .hint_text("Filter results"),
                );
                let needle = self.string_search.filter.to_lowercase();
                egui::ScrollArea::vertical()
                    .id_salt("string-search-results")
                    .max_height(420.0)
                    .show_rows(ui, 20.0, self.string_results.len(), |ui, rows| {
                        for row in rows {
                            let record = &self.string_results[row];
                            if !needle.is_empty() && !record.value.to_lowercase().contains(&needle)
                            {
                                continue;
                            }
                            ui.horizontal(|ui| {
                                ui.monospace(format!("0x{:08x}", record.offset));
                                ui.monospace(record.encoding.as_str());
                                ui.label(&record.value);
                            });
                        }
                    });
            });
        self.string_search.open = open;
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.tr("settings"));
        ui.horizontal(|ui| {
            ui.label("Language");
            egui::ComboBox::from_id_salt("language")
                .selected_text(language_name(self.preferences.language))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.preferences.language, Language::PtPt, "pt-PT");
                    ui.selectable_value(&mut self.preferences.language, Language::PtBr, "pt-BR");
                    ui.selectable_value(&mut self.preferences.language, Language::EnUs, "en-US");
                    ui.selectable_value(&mut self.preferences.language, Language::RuRu, "ru-RU");
                });
        });
        ui.horizontal(|ui| {
            ui.label("Theme");
            ui.selectable_value(&mut self.preferences.theme, Theme::Dark, "Dark");
            ui.selectable_value(&mut self.preferences.theme, Theme::Light, "Light");
        });
        ui.label("Preferences are saved by the native eframe application.");
        ui.label("The selected language currently covers navigation and the first-run actions; other views are being localized.");
    }
}

impl eframe::App for GhirustApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_events();
        let dark = self.preferences.theme == Theme::Dark;
        self.palette().apply(context, dark);

        // Real telemetry, about once per second.
        if self.last_telemetry.elapsed() >= Duration::from_secs(1) {
            self.resource_state = Some(self.task_manager.refresh_telemetry());
            if let Some(state) = &self.resource_state {
                self.cpu_history.push_back(state.snapshot.cpu_percent);
                self.ram_history
                    .push_back(state.snapshot.process_ram_bytes as f32 / (1024.0 * 1024.0));
                while self.cpu_history.len() > 180 {
                    self.cpu_history.pop_front();
                }
                while self.ram_history.len() > 180 {
                    self.ram_history.pop_front();
                }
            }
            self.last_telemetry = Instant::now();
        }

        if let Some(path) = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        }) {
            self.open_path(path);
        }

        egui::TopBottomPanel::top("topbar").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading(self.tr("app_title"));
                ui.separator();
                ui.label(self.screen.name());
                ui.menu_button("File", |ui| {
                    if ui.button("Open...").clicked() {
                        self.pick_binary();
                        ui.close_menu();
                    }
                    if ui.button("Open Project...").clicked() {
                        self.pick_project();
                        ui.close_menu();
                    }
                    if ui.button("Import File...").clicked() {
                        self.pick_binary();
                        ui.close_menu();
                    }
                    if ui.button("Close Program").clicked() {
                        self.close_program();
                        ui.close_menu();
                    }
                    ui.add_enabled(false, egui::Button::new("Parse C Source (not implemented)"));
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        context.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |ui| {
                    ui.add_enabled(false, egui::Button::new("Undo (not implemented)"));
                    ui.add_enabled(false, egui::Button::new("Redo (not implemented)"));
                    if ui.button("Tool Options").clicked() {
                        self.transition_to(Screen::Settings, TransitionReason::UserAction);
                        ui.close_menu();
                    }
                    if ui.button("Options for Program...").clicked() {
                        self.show_resource_settings = true;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Project", |ui| {
                    if ui.button("New Project...").clicked() {
                        self.create_project();
                        ui.close_menu();
                    }
                    if ui.button("Open Project...").clicked() {
                        self.pick_project();
                        ui.close_menu();
                    }
                    if ui.button("Verify Project").clicked() {
                        self.verify_project();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui
                        .add_enabled(self.analysis.is_some(), egui::Button::new("CodeBrowser"))
                        .clicked()
                    {
                        self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
                        ui.close_menu();
                    }
                    if ui.button("Command Center").clicked() {
                        self.transition_to(Screen::CommandCenter, TransitionReason::UserAction);
                        ui.close_menu();
                    }
                    if ui.button("Program Search...").clicked() {
                        self.transition_to(Screen::ProgramSearch, TransitionReason::UserAction);
                        ui.close_menu();
                    }
                    if ui.button("Resource Monitor").clicked() {
                        self.show_resource_monitor_window = true;
                        ui.close_menu();
                    }
                    ui.add_enabled(false, egui::Button::new("Function Graph (not implemented)"));
                    ui.add_enabled(false, egui::Button::new("Call Graph (not implemented)"));
                    ui.add_enabled(false, egui::Button::new("Memory Map (not implemented)"));
                    ui.add_enabled(false, egui::Button::new("Script Manager (not implemented)"));
                });
                ui.menu_button("Window", |ui| {
                    if ui.button("Search For Strings...").clicked() {
                        self.string_search.open = true;
                        ui.close_menu();
                    }
                    if ui.button("Listing").clicked() {
                        if self.analysis.is_some() {
                            self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
                        }
                        ui.close_menu();
                    }
                    if ui.button("Decompile").clicked() {
                        if self.analysis.is_some() {
                            self.transition_to(Screen::CodeBrowser, TransitionReason::UserAction);
                        }
                        ui.close_menu();
                    }
                    if ui.button("Resource Monitor").clicked() {
                        self.show_resource_monitor_window = true;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Help", |ui| {
                    ui.label("GHIRUST 0.1.0 — Rust-first reverse engineering");
                    ui.label("Decompiler: heuristic, not a Ghidra clone.");
                    ui.label("GPU metrics are unavailable: no GPU backend is linked.");
                    ui.label("Docs: docs/ and README.md in the repository.");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(state) = &self.resource_state {
                        let palette = self.palette();
                        let pressure_color = palette.pressure(state.pressure);
                        ui.colored_label(pressure_color, pressure_name(state.pressure));
                        ui.label(format!(
                            "CPU {:.0}% · {} RAM",
                            state.snapshot.cpu_percent,
                            format_bytes(state.snapshot.process_ram_bytes)
                        ));
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status").show(context, |ui| {
            if let Some(error) = &self.error {
                ui.colored_label(self.palette().error, &error.message);
                ui.label(error.suggestion);
                ui.label(format!("Error code: {}", error.code));
                if ui.small_button("Dismiss").clicked() {
                    self.error = None;
                }
            } else if let Some(notice) = &self.notice {
                ui.label(notice);
            } else if let Some(task) = self
                .tasks
                .iter()
                .rev()
                .find(|task| task.status == TaskStatus::Running)
            {
                ui.label(format!("{} - {}", task.label, task.stage));
            } else if let Some(root) = &self.project_root {
                ui.label(format!("Project: {}", root.display()));
            } else {
                ui.label(
                    "Ready - open a project, import a binary, or drop files anywhere in this window.",
                );
            }
        });

        egui::CentralPanel::default().show(context, |ui| match self.screen {
            Screen::Project => self.render_project(ui),
            Screen::Analysis => self.render_analysis(ui),
            Screen::CodeBrowser => self.render_code_browser(ui),
            Screen::Functions => self.render_functions(ui),
            Screen::ProgramSearch => self.render_program_search(ui),
            Screen::Search => self.render_search(ui),
            Screen::Strings => self.render_strings(ui),
            Screen::CommandCenter => self.render_command_center(ui),
            Screen::Settings => self.render_settings(ui),
        });

        // Folder confirmation before indexing a non-project folder.
        if let Some(folder) = self.pending_index_folder.take() {
            let mut open = true;
            let mut confirm = false;
            egui::Window::new("Index Folder?")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(context, |ui| {
                    ui.label(format!(
                        "The folder {} is not a GHIRUST project store. Index it as an exported-source project?",
                        folder.display()
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            confirm = true;
                        }
                        if ui.button("Cancel").clicked() {
                            confirm = false;
                        }
                    });
                });
            if confirm {
                self.confirm_index_folder();
            }
        }

        // Floating windows.
        self.render_analysis_options(context);
        self.render_resource_settings(context);
        self.render_string_search(context);
        if self.show_resource_monitor_window {
            let mut open = self.show_resource_monitor_window;
            egui::Window::new("Resource Monitor")
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .show(context, |ui| self.render_resource_monitor(ui));
            self.show_resource_monitor_window = open;
        }

        context.request_repaint_after(Duration::from_millis(250));
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        match serde_json::to_string(&self.preferences) {
            Ok(value) => storage.set_string("preferences", value),
            Err(error) => {
                self.error = Some(ApiError {
                    code: "preferences_serialize",
                    message: format!("Could not save preferences: {error}"),
                    suggestion: "Reset the language and theme settings before exiting.",
                });
            }
        }
    }
}

fn property(ui: &mut egui::Ui, name: &str, value: &str) {
    ui.label(name);
    ui.monospace(value);
    ui.end_row();
}

fn render_listing_panel(ui: &mut egui::Ui, function: &FunctionAnalysis, palette: &Palette) {
    for block in &function.blocks {
        ui.add_space(4.0);
        ui.colored_label(
            palette.info,
            format!(
                "; block {} @ 0x{:x} · {} · successors: {}",
                block.id,
                block.start,
                block.terminator,
                if block.successors.is_empty() {
                    "(none)".to_owned()
                } else {
                    block
                        .successors
                        .iter()
                        .map(|target| format!("0x{target:x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        );
        for instruction in &block.instructions {
            let mut text = format!(
                "0x{:08x}  {:<24} {}",
                instruction.address, instruction.bytes, instruction.text
            );
            if let Some(target) = instruction.call_target {
                text.push_str(&format!("  ; call 0x{target:x}"));
            } else if let Some(target) = instruction.branch_target {
                text.push_str(&format!("  ; branch 0x{target:x}"));
            } else if let Some(target) = instruction.memory_reference {
                text.push_str(&format!("  ; data 0x{target:x}"));
            }
            if instruction.unsupported {
                ui.colored_label(palette.warning, format!("! {text}"));
            } else {
                ui.monospace(text);
            }
        }
    }
    if function.instruction_count == 0 {
        ui.label("This function contains no decoded instructions.");
    }
}

fn render_decompile_panel(ui: &mut egui::Ui, function: &FunctionAnalysis, palette: &Palette) {
    let decompiled = &function.decompiled;
    if decompiled.text.trim().is_empty() {
        ui.label("No pseudocode was produced for this function.");
        return;
    }
    if !decompiled.unsupported_instructions.is_empty() {
        ui.colored_label(
            palette.warning,
            format!(
                "Limitation: this function uses instructions without a semantic model: {}",
                decompiled.unsupported_instructions.join(", ")
            ),
        );
    }
    ui.add_space(4.0);
    ui.monospace(&decompiled.text);
    if !decompiled.warnings.is_empty() {
        ui.add_space(8.0);
        ui.colored_label(
            palette.warning,
            format!("Warnings ({})", decompiled.warnings.len()),
        );
        for warning in &decompiled.warnings {
            ui.label(warning);
        }
    }
}

/// Draw a deterministic layered control-flow graph. Blocks are grouped by
/// breadth-first depth from the entry block, so loops are visible as backward
/// edges and branches fan out to the right.
fn render_cfg_graph(ui: &mut egui::Ui, function: &FunctionAnalysis, palette: &Palette) {
    let blocks = &function.blocks;
    if blocks.is_empty() {
        ui.label("This function has no recovered basic blocks.");
        return;
    }
    if blocks.len() > 200 {
        ui.label(format!(
            "Graph rendering is limited to 200 blocks; this function has {}.",
            blocks.len()
        ));
        return;
    }
    let index_by_start: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let mut depth: Vec<Option<usize>> = vec![None; blocks.len()];
    depth[0] = Some(0);
    let mut queue = VecDeque::from([0usize]);
    while let Some(index) = queue.pop_front() {
        let current = depth[index].unwrap_or(0);
        for successor in &blocks[index].successors {
            if let Some(&next) = index_by_start.get(successor)
                && depth[next].is_none()
            {
                depth[next] = Some(current + 1);
                queue.push_back(next);
            }
        }
    }
    let max_depth = depth.iter().flatten().copied().max().unwrap_or(0);
    for slot in depth.iter_mut() {
        if slot.is_none() {
            *slot = Some(max_depth + 1);
        }
    }
    let columns = max_depth + 2;
    let mut column_blocks: Vec<Vec<usize>> = vec![Vec::new(); columns];
    let mut row_of = vec![0usize; blocks.len()];
    for (index, slot) in depth.iter().enumerate() {
        let column = slot.unwrap_or(columns - 1);
        row_of[index] = column_blocks[column].len();
        column_blocks[column].push(index);
    }
    let rows = column_blocks.iter().map(Vec::len).max().unwrap_or(1);

    let node_width = 230.0;
    let node_height = 66.0;
    let horizontal_gap = 70.0;
    let vertical_gap = 22.0;
    let margin = 24.0;
    let width = columns as f32 * node_width
        + (columns.saturating_sub(1)) as f32 * horizontal_gap
        + margin * 2.0;
    let height =
        rows as f32 * node_height + (rows.saturating_sub(1)) as f32 * vertical_gap + margin * 2.0;
    let (canvas, _response) =
        ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(canvas, 6.0, palette.code_bg);

    let node_rect = |index: usize| -> egui::Rect {
        let column = depth[index].unwrap_or(0);
        let row = row_of[index];
        let min = canvas.min
            + egui::vec2(
                margin + column as f32 * (node_width + horizontal_gap),
                margin + row as f32 * (node_height + vertical_gap),
            );
        egui::Rect::from_min_size(min, egui::vec2(node_width, node_height))
    };

    let edge_color = palette.info;
    for (index, block) in blocks.iter().enumerate() {
        let from = node_rect(index);
        for successor in &block.successors {
            let Some(&target) = index_by_start.get(successor) else {
                continue;
            };
            let to = node_rect(target);
            let start = egui::pos2(from.center().x, from.bottom());
            let end = egui::pos2(to.center().x, to.top());
            painter.line_segment([start, end], egui::Stroke::new(1.4_f32, edge_color));
            let direction = (end - start).normalized();
            let normal = egui::vec2(-direction.y, direction.x);
            painter.line_segment(
                [end, end - direction * 9.0 + normal * 4.5],
                egui::Stroke::new(1.4_f32, edge_color),
            );
            painter.line_segment(
                [end, end - direction * 9.0 - normal * 4.5],
                egui::Stroke::new(1.4_f32, edge_color),
            );
        }
    }

    for (index, block) in blocks.iter().enumerate() {
        let rect = node_rect(index);
        let is_entry = index == 0;
        painter.rect_filled(
            rect,
            5.0,
            if is_entry {
                palette.surface_alt
            } else {
                palette.surface
            },
        );
        painter.rect_stroke(
            rect,
            5.0,
            egui::Stroke::new(
                1.4_f32,
                if is_entry {
                    palette.accent
                } else {
                    palette.border
                },
            ),
            egui::StrokeKind::Inside,
        );
        painter.text(
            rect.min + egui::vec2(10.0, 7.0),
            egui::Align2::LEFT_TOP,
            format!("block {} @ 0x{:x}", block.id, block.start),
            egui::FontId::monospace(12.0),
            palette.text_primary,
        );
        painter.text(
            rect.min + egui::vec2(10.0, 26.0),
            egui::Align2::LEFT_TOP,
            format!("{} instruction(s)", block.instructions.len()),
            egui::FontId::proportional(11.0),
            palette.text_secondary,
        );
        painter.text(
            rect.min + egui::vec2(10.0, 44.0),
            egui::Align2::LEFT_TOP,
            truncate_text(
                &format!(
                    "{} -> {}",
                    block.terminator,
                    if block.successors.is_empty() {
                        "exit".to_owned()
                    } else {
                        block
                            .successors
                            .iter()
                            .map(|target| format!("0x{target:x}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
                34,
            ),
            egui::FontId::proportional(10.0),
            palette.text_disabled,
        );
    }
}

fn render_summary_panel(ui: &mut egui::Ui, analysis: &ProgramAnalysis) {
    let loader = &analysis.loader;
    egui::Grid::new("code-summary-grid")
        .num_columns(2)
        .spacing([18.0, 4.0])
        .show(ui, |ui| {
            property(ui, "File", &analysis.path);
            property(ui, "SHA-256", &analysis.sha256);
            property(ui, "Format", &loader.format);
            property(ui, "Architecture", &loader.architecture);
            property(ui, "Bitness", &format!("{}-bit", loader.bits));
            property(ui, "Endianness", &loader.endian);
            property(ui, "Kind", &loader.object_kind);
            property(
                ui,
                "Operating system",
                loader.os.as_deref().unwrap_or("unknown"),
            );
            property(ui, "Image base", &format!("0x{:x}", loader.image_base));
            property(ui, "Entry point", &format!("0x{:x}", loader.entry));
            property(ui, "Sections", &analysis.sections.len().to_string());
            property(ui, "Imports", &analysis.imports.len().to_string());
            property(ui, "Exports", &analysis.exports.len().to_string());
            property(ui, "Symbols", &analysis.symbols.len().to_string());
            property(ui, "Strings", &analysis.strings.len().to_string());
            property(ui, "Functions", &analysis.stats.functions.to_string());
            property(ui, "Instructions", &analysis.stats.instructions.to_string());
            property(ui, "Blocks", &analysis.stats.blocks.to_string());
            property(ui, "Cross-references", &analysis.stats.xrefs.to_string());
            property(ui, "Seeds", &analysis.stats.seeds.to_string());
            property(
                ui,
                "Overlapping functions skipped",
                &analysis.stats.overlapping_functions_skipped.to_string(),
            );
            property(ui, "Elapsed", &format!("{} ms", analysis.stats.elapsed_ms));
            property(
                ui,
                "Truncated",
                if analysis.stats.truncated {
                    "yes"
                } else {
                    "no"
                },
            );
        });
    if !analysis.sections.is_empty() {
        ui.add_space(6.0);
        ui.strong("Sections");
        for section in &analysis.sections {
            ui.monospace(format!(
                "{:<12} 0x{:08x}  virtual {:>8}  file {:>8}  {}",
                section.name,
                section.address,
                section.virtual_size,
                section.file_size,
                section.kind
            ));
        }
    }
}

fn render_symbols_panel(ui: &mut egui::Ui, analysis: &ProgramAnalysis, filter: &str) {
    let needle = filter.to_lowercase();
    let mut shown = 0usize;
    for symbol in &analysis.symbols {
        if !needle.is_empty()
            && !symbol.name.to_lowercase().contains(&needle)
            && !format!("0x{:x}", symbol.address).contains(&needle)
        {
            continue;
        }
        if shown >= 5_000 {
            ui.label("Symbol list limited to 5000 entries; refine the filter.");
            break;
        }
        ui.monospace(format!(
            "0x{:08x}  {:<10} {:<8} {:<10} {}",
            symbol.address,
            symbol.kind,
            symbol.source,
            symbol.name,
            if symbol.global { "global" } else { "" }
        ));
        shown += 1;
    }
    if shown == 0 {
        ui.label("No matching symbols.");
    }
    if !analysis.imports.is_empty() {
        ui.add_space(6.0);
        ui.strong(format!("Imports ({})", analysis.imports.len()));
        for import in &analysis.imports {
            ui.monospace(format!("{}!{}", import.library, import.name));
        }
    }
    if !analysis.exports.is_empty() {
        ui.add_space(6.0);
        ui.strong(format!("Exports ({})", analysis.exports.len()));
        for export in &analysis.exports {
            match export.address {
                Some(address) => ui.monospace(format!("0x{address:08x}  {}", export.name)),
                None => ui.monospace(format!(
                    "{} -> {}",
                    export.name,
                    export.forwarder.as_deref().unwrap_or("(forwarded)")
                )),
            };
        }
    }
}

fn render_xrefs_panel(ui: &mut egui::Ui, analysis: &ProgramAnalysis, filter: &str) {
    let needle = filter.to_lowercase();
    let mut shown = 0usize;
    for xref in &analysis.xrefs {
        let target_name = symbol_name(analysis, xref.to);
        let source_name = xref
            .function
            .and_then(|function| {
                analysis
                    .functions
                    .iter()
                    .find(|item| item.address == function)
            })
            .map(|function| function.name.as_str())
            .unwrap_or("");
        let line = format!(
            "0x{:08x} -> 0x{:08x}  {:<5} {:<28} {}",
            xref.from, xref.to, xref.kind, target_name, source_name
        );
        if !needle.is_empty() && !line.to_lowercase().contains(&needle) {
            continue;
        }
        if shown >= 5_000 {
            ui.label("Cross-reference list limited to 5000 entries; refine the filter.");
            break;
        }
        ui.monospace(line);
        shown += 1;
    }
    if shown == 0 {
        ui.label("No matching cross-references.");
    }
}

fn render_warnings_panel(
    ui: &mut egui::Ui,
    analysis: &ProgramAnalysis,
    function: Option<&FunctionAnalysis>,
) {
    ui.strong(format!("Program warnings ({})", analysis.warnings.len()));
    for warning in &analysis.warnings {
        ui.label(warning);
    }
    if let Some(function) = function {
        ui.add_space(6.0);
        ui.strong(format!(
            "{} warnings ({})",
            function.name,
            function.decompiled.warnings.len()
        ));
        for warning in &function.decompiled.warnings {
            ui.label(warning);
        }
    }
}

fn symbol_name(analysis: &ProgramAnalysis, address: u64) -> String {
    if let Some(function) = analysis
        .functions
        .iter()
        .find(|function| function.address == address)
    {
        return function.name.clone();
    }
    if let Some(symbol) = analysis
        .symbols
        .iter()
        .find(|symbol| symbol.address == address && !symbol.name.is_empty())
    {
        return symbol.name.clone();
    }
    String::new()
}

fn truncate_text(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    let mut output: String = value.chars().take(width.saturating_sub(1)).collect();
    output.push('…');
    output
}

fn render_search_hit(ui: &mut egui::Ui, hit: &SearchHit) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.strong(&hit.file);
            ui.label(format!("{}:{}", hit.line, hit.column));
        });
        if let Some(function) = &hit.function {
            ui.label(format!(
                "{}{}",
                function,
                hit.address
                    .as_deref()
                    .map(|address| format!(" @ {address}"))
                    .unwrap_or_default()
            ));
        }
        ui.monospace(&hit.text);
    });
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::PtPt => "Português (Portugal)",
        Language::PtBr => "Português (Brasil)",
        Language::EnUs => "English (US)",
        Language::RuRu => "Русский",
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

fn priority_name(priority: Priority) -> &'static str {
    match priority {
        Priority::CriticalUi => "CRITICAL_UI",
        Priority::Interactive => "INTERACTIVE",
        Priority::High => "HIGH",
        Priority::Normal => "NORMAL",
        Priority::Low => "LOW",
        Priority::Background => "BACKGROUND",
    }
}

fn pressure_name(pressure: PressureState) -> &'static str {
    match pressure {
        PressureState::Normal => "NORMAL",
        PressureState::Warning => "WARNING",
        PressureState::HighPressure => "HIGH_PRESSURE",
        PressureState::Critical => "CRITICAL",
        PressureState::Recovery => "RECOVERY",
    }
}

fn profile_name(profile: ProfileSel) -> &'static str {
    match profile {
        ProfileSel::Conservative => "Conservative",
        ProfileSel::Balanced => "Balanced",
        ProfileSel::Performance => "Performance",
        ProfileSel::Custom => "Custom",
    }
}

fn analyzer_name(id: &str) -> &str {
    match id {
        "disassemble" => "Disassemble",
        "function_discovery" => "Function Discovery",
        "strings" => "String Analysis",
        "imports_exports" => "Import / Export Analysis",
        "references" => "Reference Analysis",
        "control_flow" => "Control Flow Analysis",
        "decompile" => "Decompiler Analysis",
        "deep_prologues" => "Deep Discovery (prologues, larger sweep)",
        _ => id,
    }
}

/// Minimal painter-based sparkline; real data only.
fn sparkline(
    ui: &mut egui::Ui,
    history: &VecDeque<f32>,
    palette: &Palette,
    color: egui::Color32,
    label: &str,
) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(260.0, 44.0), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 3.0, palette.code_bg);
    painter.text(
        rect.min + egui::vec2(4.0, 2.0),
        egui::Align2::LEFT_TOP,
        label,
        egui::FontId::proportional(10.0),
        palette.text_secondary,
    );
    if history.len() < 2 {
        return;
    }
    let maximum = history.iter().cloned().fold(f32::MIN, f32::max).max(1.0);
    let step_x = rect.width() / (history.len().saturating_sub(1)).max(1) as f32;
    let points: Vec<egui::Pos2> = history
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let x = rect.min.x + index as f32 * step_x;
            let y = rect.max.y - 4.0 - (value / maximum) * (rect.height() - 8.0);
            egui::pos2(x, y)
        })
        .collect();
    for pair in points.windows(2) {
        painter.line_segment([pair[0], pair[1]], egui::Stroke::new(1.2_f32, color));
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("GHIRUST")
            .with_inner_size([1100.0, 760.0])
            .with_min_inner_size([800.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "GHIRUST",
        options,
        Box::new(|context| Ok(Box::new(GhirustApp::new(context)))),
    )
}
