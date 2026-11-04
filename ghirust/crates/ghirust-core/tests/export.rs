use std::fs;
use std::io::Read;

use flate2::read::GzDecoder;
use ghirust_core::export::{Compression, ExportOptions, export_input};
use ghirust_core::model::FunctionRecord;
use tempfile::tempdir;

fn record(name: &str, address: &str, code: &str) -> FunctionRecord {
    FunctionRecord {
        name: name.to_owned(),
        address: Some(address.to_owned()),
        kind: Some("function".to_owned()),
        source: None,
        code: code.to_owned(),
    }
}

fn write_ndjson(path: &std::path::Path, records: &[FunctionRecord]) {
    let mut text = String::new();
    for record in records {
        text.push_str(&serde_json::to_string(record).unwrap());
        text.push('\n');
    }
    fs::write(path, text).unwrap();
}

#[test]
fn exports_ndjson_with_markers_and_manifest() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    let output = temp.path().join("out.c");
    let records = vec![
        record("main", "0x401000", "int main(void) {\n    return 0;\n}\n"),
        record("helper", "0x401050", "void helper(void) {}\n"),
    ];
    write_ndjson(&input, &records);

    let report = export_input(
        &input,
        &ExportOptions {
            output: output.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.records, 2);
    assert!(report.uncompressed_bytes > 0);
    let text = fs::read_to_string(&output).unwrap();
    assert!(text.contains("// Function: main @ 0x401000"));
    assert!(text.contains("return 0;"));
    assert!(text.contains("// Function: helper @ 0x401050"));
    assert!(!temp.path().join("out.c.part").exists());
    assert!(!temp.path().join("out.c.checkpoint.json").exists());

    let manifest = fs::read_to_string(temp.path().join("out.c.manifest.ndjson")).unwrap();
    let lines: Vec<_> = manifest.lines().collect();
    assert_eq!(lines.len(), 2);
    let first: ghirust_core::ExportedFunction = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first.name, "main");
    assert!(first.length > 0);
}

#[test]
fn refuses_to_overwrite_without_force() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    let output = temp.path().join("out.c");
    fs::write(&output, b"keep me").unwrap();
    write_ndjson(&input, &[record("main", "0x1", "int main() {}\n")]);

    let error = export_input(
        &input,
        &ExportOptions {
            output: output.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("use --force"));
    assert_eq!(fs::read_to_string(&output).unwrap(), "keep me");
}

#[test]
fn gzip_output_is_valid() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    let output = temp.path().join("out.c.gz");
    write_ndjson(
        &input,
        &[record("main", "0x1", &"int x = 1;\n".repeat(500))],
    );

    export_input(
        &input,
        &ExportOptions {
            output: output.clone(),
            compression: Compression::Gzip,
            ..ExportOptions::default()
        },
    )
    .unwrap();

    let mut decoder = GzDecoder::new(fs::File::open(&output).unwrap());
    let mut text = String::new();
    decoder.read_to_string(&mut text).unwrap();
    assert!(text.contains("int x = 1;"));
    assert!(text.contains("// Function: main @ 0x1"));
}

#[test]
fn resumes_from_a_checkpoint() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    let full = temp.path().join("full.c");
    let resumed = temp.path().join("resumed.c");
    let records = vec![
        record("first", "0x1", "int first(void) { return 1; }\n"),
        record("second", "0x2", "int second(void) { return 2; }\n"),
        record("third", "0x3", "int third(void) { return 3; }\n"),
        record("fourth", "0x4", "int fourth(void) { return 4; }\n"),
    ];
    write_ndjson(&input, &records);

    export_input(
        &input,
        &ExportOptions {
            output: full.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    let full_text = fs::read_to_string(&full).unwrap();
    let full_manifest = fs::read_to_string(full.with_extension("c.manifest.ndjson")).unwrap();
    let manifest_lines: Vec<_> = full_manifest.lines().collect();

    // Recreate the state left by an interruption after the second function.
    // The newline that separates the second body from the third header is
    // written as part of the third function, so cut before it.
    let third_header = full_text
        .find("// Function: third")
        .expect("third function marker");
    let cut = if third_header > 0 && full_text.as_bytes()[third_header - 1] == b'\n' {
        third_header - 1
    } else {
        third_header
    };
    let prefix = &full_text[..cut];
    fs::write(temp.path().join("resumed.c.part"), prefix).unwrap();
    fs::write(
        temp.path().join("resumed.c.checkpoint.json"),
        serde_json::to_vec(&serde_json::json!({
            "records": 2,
            "output_bytes": prefix.len(),
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        temp.path().join("resumed.c.manifest.ndjson"),
        format!("{}\n{}\n", manifest_lines[0], manifest_lines[1]),
    )
    .unwrap();

    let report = export_input(
        &input,
        &ExportOptions {
            output: resumed.clone(),
            resume: true,
            ..ExportOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.resumed_from, 2);
    assert_eq!(report.records, 4);
    assert_eq!(fs::read_to_string(&resumed).unwrap(), full_text);
    let resumed_manifest = fs::read_to_string(temp.path().join("resumed.c.manifest.ndjson")).unwrap();
    assert_eq!(resumed_manifest.lines().count(), 4);
}

#[test]
fn exports_a_directory_using_its_manifest() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("ghidra-export");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("000002.c"), "int second(void) { return 2; }\n").unwrap();
    fs::write(input.join("000001.c"), "int first(void) { return 1; }\n").unwrap();
    fs::write(
        input.join("manifest.ndjson"),
        concat!(
            "{\"name\":\"first\",\"address\":\"0x1\",\"file\":\"000001.c\"}\n",
            "{\"name\":\"second\",\"address\":\"0x2\",\"file\":\"000002.c\"}\n"
        ),
    )
    .unwrap();

    let output = temp.path().join("out.c");
    let report = export_input(
        &input,
        &ExportOptions {
            output: output.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.records, 2);
    let text = fs::read_to_string(&output).unwrap();
    let first = text.find("// Function: first @ 0x1").unwrap();
    let second = text.find("// Function: second @ 0x2").unwrap();
    assert!(first < second);
    assert!(text.contains("int first(void)"));
}

#[test]
fn rejects_path_traversal_in_manifest() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("ghidra-export");
    fs::create_dir_all(&input).unwrap();
    fs::write(
        input.join("manifest.ndjson"),
        "{\"name\":\"escape\",\"file\":\"../secret.c\"}\n",
    )
    .unwrap();

    let error = export_input(
        &input,
        &ExportOptions {
            output: temp.path().join("out.c"),
            ..ExportOptions::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("escapes the export directory"));
}
