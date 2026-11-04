use std::fs;

use ghirust_core::index::{IndexOptions, build_index};
use ghirust_core::search::{SearchMode, SearchOptions, search};
use tempfile::tempdir;

fn fixture() -> (tempfile::TempDir, ghirust_core::SearchIndex) {
    let temp = tempdir().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("alpha.c"),
        concat!(
            "// GHIRUST streaming export (format 1)\n",
            "\n// Function: alpha @ 0x401000\n",
            "int alpha(void) {\n",
            "    return 42; // MAGIC_TOKEN\n",
            "}\n",
            "\n// Function: helper @ 0x401020\n",
            "int helper(void) { return 0; }\n",
        ),
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("beta.c"),
        concat!(
            "\n// Function: beta @ 0x402000\n",
            "void beta(void) {\n",
            "    // magic_token in a second file\n",
            "}\n",
        ),
    )
    .unwrap();

    let index_path = temp.path().join(".ghirust").join("index.json");
    build_index(&IndexOptions {
        root: temp.path().to_path_buf(),
        index_path: index_path.clone(),
        include_hidden: false,
    })
    .unwrap();
    let index = ghirust_core::load_index(&index_path).unwrap();
    (temp, index)
}

#[test]
fn finds_text_and_attributes_the_enclosing_function() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "MAGIC_TOKEN".to_owned(),
            ..SearchOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.hits.len(), 1);
    let hit = &report.hits[0];
    assert_eq!(hit.file, "src/alpha.c");
    assert_eq!(hit.line, 5);
    assert_eq!(hit.function.as_deref(), Some("alpha"));
    assert_eq!(hit.address.as_deref(), Some("0x401000"));
    assert!(hit.text.contains("MAGIC_TOKEN"));
}

#[test]
fn exact_result_limit_is_not_reported_as_truncated() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "MAGIC_TOKEN".to_owned(),
            limit: 1,
            ..SearchOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.hits.len(), 1);
    assert!(!report.truncated);
}

#[test]
fn case_insensitive_text_search_spans_files() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "magic_token".to_owned(),
            ignore_case: true,
            ..SearchOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.hits.len(), 2);
    assert_eq!(report.hits[0].function.as_deref(), Some("alpha"));
    assert_eq!(report.hits[1].function.as_deref(), Some("beta"));
}

#[test]
fn searches_function_names() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "name:help".to_owned(),
            ..SearchOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.mode, SearchMode::Name);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].function.as_deref(), Some("helper"));
    assert_eq!(report.hits[0].address.as_deref(), Some("0x401020"));
}

#[test]
fn searches_file_paths() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "file:beta".to_owned(),
            ..SearchOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.mode, SearchMode::File);
    assert!(!report.hits.is_empty());
    assert!(report.hits.iter().all(|hit| hit.file.contains("beta")));
}

#[test]
fn indexes_and_searches_a_ghidra_directory_manifest() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("ghidra-export");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("000001.c"), "int first(void) { return 1; }\n").unwrap();
    fs::write(
        input.join("manifest.ndjson"),
        "{\"name\":\"first\",\"address\":\"0x1000\",\"file\":\"000001.c\"}\n",
    )
    .unwrap();

    let index_path = temp.path().join("index.json");
    let report = build_index(&IndexOptions {
        root: temp.path().to_path_buf(),
        index_path: index_path.clone(),
        include_hidden: false,
    })
    .unwrap();
    assert_eq!(report.functions, 1);

    let index = ghirust_core::load_index(&index_path).unwrap();
    let found = search(
        &index,
        &SearchOptions {
            query: "name:first".to_owned(),
            ..SearchOptions::default()
        },
    )
    .unwrap();
    assert_eq!(found.hits.len(), 1);
    assert_eq!(found.hits[0].file, "ghidra-export/000001.c");
}

#[test]
fn rejects_empty_queries() {
    let (_temp, index) = fixture();
    let error = search(
        &index,
        &SearchOptions {
            query: "   ".to_owned(),
            ..SearchOptions::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot be empty"));
}

#[test]
fn rebuild_reuses_the_content_addressed_scan_cache() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("sample.c"),
        "// Function: main @ 0x1000\nint main(void) { return 0; }\n",
    )
    .unwrap();

    let options = IndexOptions {
        root: temp.path().to_path_buf(),
        index_path: temp.path().join(".ghirust").join("index.json"),
        include_hidden: false,
    };
    let first = build_index(&options).unwrap();
    assert_eq!(first.cache_hits, 0);
    assert_eq!(first.cache_misses, 1);

    let second = build_index(&options).unwrap();
    assert_eq!(second.cache_hits, 1);
    assert_eq!(second.cache_misses, 0);
}

#[test]
fn rebuild_reports_cache_failures_and_continues_indexing() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("sample.c"),
        "// Function: main @ 0x1000\nint main(void) { return 0; }\n",
    )
    .unwrap();
    let cache_path = temp.path().join(".ghirust").join("cache");
    fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    fs::write(&cache_path, "cache path is not a directory").unwrap();

    let report = build_index(&IndexOptions {
        root: temp.path().to_path_buf(),
        index_path: temp.path().join(".ghirust").join("index.json"),
        include_hidden: false,
    })
    .unwrap();

    assert_eq!(report.functions, 1);
    assert_eq!(report.cache_misses, 1);
    assert_eq!(report.cache_warnings.len(), 1);
    assert!(report.cache_warnings[0].contains("scan cache unavailable"));
}

#[test]
fn rebuild_reports_corrupt_cache_manifest_and_recovers() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("sample.c"),
        "// Function: main @ 0x1000\nint main(void) { return 0; }\n",
    )
    .unwrap();
    let options = IndexOptions {
        root: temp.path().to_path_buf(),
        index_path: temp.path().join(".ghirust").join("index.json"),
        include_hidden: false,
    };

    build_index(&options).unwrap();
    fs::write(
        temp.path()
            .join(".ghirust")
            .join("cache")
            .join("index.json"),
        "{ invalid json",
    )
    .unwrap();

    let recovered = build_index(&options).unwrap();
    assert_eq!(recovered.functions, 1);
    assert_eq!(recovered.cache_misses, 1);
    assert!(
        recovered
            .cache_warnings
            .iter()
            .any(|warning| warning.contains("invalid cache manifest"))
    );

    let reused = build_index(&options).unwrap();
    assert_eq!(reused.cache_hits, 1);
    assert_eq!(reused.cache_misses, 0);
}

#[test]
fn limits_results_and_reports_truncation() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "e".to_owned(),
            ignore_case: true,
            limit: 2,
            ..SearchOptions::default()
        },
    )
    .unwrap();
    assert!(report.hits.len() <= 2);
    assert!(report.truncated);
}

#[test]
fn text_results_remain_path_ordered_when_truncated() {
    let (_temp, index) = fixture();
    let report = search(
        &index,
        &SearchOptions {
            query: "return".to_owned(),
            limit: 1,
            ..SearchOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].file, "src/alpha.c");
    assert!(report.truncated);
}
