use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use ghirust_core::{BinaryFormat, SearchMode, SearchOptions, search};
use ghirust_gui::{TaskEvent, TaskManager, TaskResult};
use tempfile::tempdir;

fn objective_binary() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("tests")
        .join("objectives")
        .join("binaries")
        .join("demo.dll");
    path.is_file().then_some(path)
}

#[test]
fn background_inspection_uses_core_detection_and_string_extraction() {
    let temp = tempdir().unwrap();
    let binary = temp.path().join("sample.bin");
    fs::write(&binary, b"not a known binary\0GHIRUST_VISIBLE_STRING\0").unwrap();

    let mut tasks = TaskManager::default();
    let id = tasks.start_inspection(binary.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for event in tasks.drain_events() {
            if let TaskEvent::Completed {
                id: event_id,
                result,
            } = event
            {
                if event_id == id {
                    let TaskResult::BinaryInspected(report) = *result else {
                        panic!("inspection returned the wrong task result");
                    };
                    assert_eq!(report.path, binary);
                    assert_eq!(report.detection.format, BinaryFormat::Unknown);
                    assert!(
                        report
                            .strings
                            .iter()
                            .any(|string| string.value == "GHIRUST_VISIBLE_STRING")
                    );
                    assert_eq!(tasks.active_count(), 0);
                    return;
                }
            }
        }
        assert!(Instant::now() < deadline, "inspection task timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn background_analysis_disassembles_a_real_dll() {
    let Some(binary) = objective_binary() else {
        eprintln!("skipping GUI analysis test: objective fixture is missing");
        return;
    };
    let mut tasks = TaskManager::default();
    let id = tasks.start_analysis(binary).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        for event in tasks.drain_events() {
            if let TaskEvent::Completed {
                id: event_id,
                result,
            } = event
            {
                if event_id == id {
                    let TaskResult::AnalysisCompleted(analysis) = *result else {
                        panic!("analysis returned the wrong task result");
                    };
                    assert_eq!(analysis.loader.format, "PE");
                    assert_eq!(analysis.loader.architecture, "X86_64");
                    assert!(analysis.stats.functions >= 6);
                    assert!(analysis.stats.instructions > 0);
                    for name in ["demo_add", "demo_classify", "demo_fact", "demo_max"] {
                        assert!(
                            analysis
                                .functions
                                .iter()
                                .any(|function| function.name == name),
                            "GUI analysis did not recover {name}"
                        );
                    }
                    let add = analysis
                        .functions
                        .iter()
                        .find(|function| function.name == "demo_add")
                        .unwrap();
                    assert!(add.decompiled.text.contains("a0 + a1"));
                    assert_eq!(tasks.active_count(), 0);
                    return;
                }
            }
        }
        assert!(Instant::now() < deadline, "analysis task timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn resource_budget_is_applied_by_the_task_manager() {
    let tasks = TaskManager::default();
    let budget = ghirust_core::ResourceBudget {
        max_worker_threads: 2,
        max_concurrent_tasks: 1,
        max_process_ram_bytes: 256 * 1024 * 1024,
        cpu_ceiling: 0.5,
        cache_limit_bytes: 32 * 1024 * 1024,
        auto_throttle: true,
        pause_on_critical: true,
    };
    tasks.set_budget(budget);
    let applied = tasks.manager().budget();
    assert_eq!(applied.max_worker_threads, 2);
    assert_eq!(applied.max_concurrent_tasks, 1);
    // Safety floors must survive impossible configurations.
    tasks.set_budget(ghirust_core::ResourceBudget {
        max_worker_threads: 0,
        max_concurrent_tasks: 0,
        max_process_ram_bytes: 1,
        cpu_ceiling: 1.0,
        cache_limit_bytes: 0,
        auto_throttle: true,
        pause_on_critical: true,
    });
    let normalized = tasks.manager().budget();
    assert!(normalized.max_worker_threads >= 1);
    assert!(normalized.max_concurrent_tasks >= 1);
    assert!(normalized.max_process_ram_bytes >= 64 * 1024 * 1024);
    assert!(normalized.cpu_ceiling <= 0.95);
}

#[test]
fn indexed_project_searches_imported_functions() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("main.c"),
        "// Function: main @ 0x401000\nint main(void) { return SEARCH_ME; }\n",
    )
    .unwrap();

    let mut tasks = TaskManager::default();
    let id = tasks.start_indexing(temp.path().to_path_buf()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut indexed = false;
    loop {
        for event in tasks.drain_events() {
            if let TaskEvent::Completed {
                id: event_id,
                result,
            } = event
            {
                if event_id == id {
                    assert!(matches!(*result, TaskResult::ProjectIndexed(_)));
                    indexed = true;
                }
            }
        }
        if indexed {
            break;
        }
        assert!(Instant::now() < deadline, "index task timed out");
        thread::sleep(Duration::from_millis(5));
    }

    let index_path = temp.path().join(".ghirust").join("index.json");
    let index = ghirust_core::load_index(&index_path).unwrap();
    let report = search(
        &index,
        &SearchOptions {
            query: "name:main".to_owned(),
            mode: SearchMode::Auto,
            ..SearchOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].address.as_deref(), Some("0x401000"));
}

#[test]
fn background_export_streams_an_existing_function_manifest() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("ghidra-export");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("000001.c"), "int first(void) { return 1; }\n").unwrap();
    fs::write(
        input.join("manifest.ndjson"),
        "{\"name\":\"first\",\"address\":\"0x1000\",\"file\":\"000001.c\"}\n",
    )
    .unwrap();
    let output = temp.path().join("combined.c");

    let mut tasks = TaskManager::default();
    let id = tasks.start_export(input, output).unwrap();
    assert!(!tasks.cancel(id));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for event in tasks.drain_events() {
            if let TaskEvent::Completed {
                id: event_id,
                result,
            } = event
            {
                if event_id == id {
                    let TaskResult::ExportCompleted(report) = *result else {
                        panic!("export returned the wrong task result");
                    };
                    assert_eq!(report.records, 1);
                    let contents = fs::read_to_string(report.output).unwrap();
                    assert!(contents.contains("// Function: first @ 0x1000"));
                    assert!(contents.contains("return 1"));
                    return;
                }
            }
        }
        assert!(Instant::now() < deadline, "export task timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn invalid_search_query_returns_a_structured_error() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    fs::create_dir_all(project.join(".ghirust")).unwrap();
    fs::write(
        project.join(".ghirust").join("index.json"),
        r#"{"version":1,"root":".","built_unix":0,"files":[],"functions":[]}"#,
    )
    .unwrap();

    let mut tasks = TaskManager::default();
    let id = tasks.start_search(project, "  ".to_owned(), 20).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for event in tasks.drain_events() {
            if let TaskEvent::Failed {
                id: event_id,
                error,
            } = event
            {
                if event_id == id {
                    assert_eq!(error.code, "empty_query");
                    assert!(!error.suggestion.is_empty());
                    return;
                }
            }
        }
        assert!(Instant::now() < deadline, "search task timed out");
        thread::sleep(Duration::from_millis(5));
    }
}
