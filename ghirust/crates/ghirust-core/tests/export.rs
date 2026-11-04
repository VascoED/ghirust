use std::fs;
use std::io::{BufWriter, Read, Write};

use flate2::read::GzDecoder;
use ghirust_core::export::{Compression, ExportOptions, export_input, export_input_fingerprint};
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
    let fingerprint = export_input_fingerprint(
        &input,
        &ExportOptions {
            output: resumed.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    fs::write(temp.path().join("resumed.c.part"), prefix).unwrap();
    fs::write(
        temp.path().join("resumed.c.checkpoint.json"),
        serde_json::to_vec(&serde_json::json!({
            "records": 2,
            "output_bytes": prefix.len(),
            "input_fingerprint": fingerprint,
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
    let resumed_manifest =
        fs::read_to_string(temp.path().join("resumed.c.manifest.ndjson")).unwrap();
    assert_eq!(resumed_manifest.lines().count(), 4);
}

#[test]
fn refuses_to_resume_when_the_input_changes() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    let output = temp.path().join("resumed.c");
    write_ndjson(&input, &[record("first", "0x1", "int first() {}\n")]);

    let fingerprint = export_input_fingerprint(&input, &ExportOptions::default()).unwrap();
    let partial = temp.path().join("resumed.c.part");
    fs::write(&partial, b"preserve partial export").unwrap();
    fs::write(
        temp.path().join("resumed.c.checkpoint.json"),
        serde_json::to_vec(&serde_json::json!({
            "records": 1,
            "output_bytes": 23,
            "input_fingerprint": fingerprint,
        }))
        .unwrap(),
    )
    .unwrap();
    write_ndjson(&input, &[record("changed", "0x2", "int changed() {}\n")]);

    let error = export_input(
        &input,
        &ExportOptions {
            output,
            resume: true,
            ..ExportOptions::default()
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("input or export options changed")
    );
    assert_eq!(fs::read(partial).unwrap(), b"preserve partial export");
}

#[test]
fn export_fingerprint_includes_output_configuration() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    write_ndjson(&input, &[record("first", "0x1", "int first() {}\n")]);

    let default_fingerprint = export_input_fingerprint(&input, &ExportOptions::default()).unwrap();
    let no_manifest_fingerprint = export_input_fingerprint(
        &input,
        &ExportOptions {
            write_manifest: false,
            ..ExportOptions::default()
        },
    )
    .unwrap();

    assert_ne!(default_fingerprint, no_manifest_fingerprint);
}

#[test]
fn refuses_to_resume_past_the_end_of_the_input() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("functions.ndjson");
    let output = temp.path().join("resumed.c");
    write_ndjson(&input, &[record("first", "0x1", "int first() {}\n")]);

    let options = ExportOptions {
        output: output.clone(),
        write_manifest: false,
        ..ExportOptions::default()
    };
    let fingerprint = export_input_fingerprint(&input, &options).unwrap();
    let partial = temp.path().join("resumed.c.part");
    fs::write(&partial, b"part").unwrap();
    fs::write(
        temp.path().join("resumed.c.checkpoint.json"),
        serde_json::to_vec(&serde_json::json!({
            "records": 2,
            "output_bytes": 4,
            "input_fingerprint": fingerprint,
        }))
        .unwrap(),
    )
    .unwrap();

    let error = export_input(
        &input,
        &ExportOptions {
            resume: true,
            ..options
        },
    )
    .unwrap_err();

    assert!(error.to_string().contains("input has only 1"));
    assert_eq!(fs::read(partial).unwrap(), b"part");
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
fn exports_large_directory_manifest_incrementally() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("ghidra-export");
    fs::create_dir_all(&input).unwrap();
    let mut manifest = BufWriter::new(fs::File::create(input.join("manifest.ndjson")).unwrap());
    const FUNCTIONS: usize = 2_000;

    for index in 0..FUNCTIONS {
        let file_name = format!("{index:06}.c");
        fs::write(input.join(&file_name), format!("int f{index}() {{}}\n")).unwrap();
        writeln!(
            manifest,
            "{}",
            serde_json::json!({
                "name": format!("f{index}"),
                "address": format!("0x{index:x}"),
                "file": file_name,
            })
        )
        .unwrap();
    }
    manifest.flush().unwrap();

    let output = temp.path().join("out.c");
    let report = export_input(
        &input,
        &ExportOptions {
            output: output.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap();

    assert_eq!(report.records, FUNCTIONS as u64);
    assert_eq!(
        fs::read_to_string(temp.path().join("out.c.manifest.ndjson"))
            .unwrap()
            .lines()
            .count(),
        FUNCTIONS
    );
    assert!(
        fs::read_to_string(output)
            .unwrap()
            .contains("// Function: f1999 @ 0x7cf")
    );
}

#[test]
#[ignore = "writes and verifies more than 100 MiB; run explicitly for streaming validation"]
fn exports_more_than_one_hundred_megabytes_from_ndjson() {
    use std::io::{BufRead, BufReader};

    let temp = tempdir().unwrap();
    let input = temp.path().join("large-functions.ndjson");
    let output = temp.path().join("large-output.c");
    const FUNCTIONS: usize = 1_024;
    const BODY_BYTES: usize = 128 * 1024;
    let body = "x".repeat(BODY_BYTES);

    {
        let mut writer = BufWriter::new(fs::File::create(&input).unwrap());
        for index in 0..FUNCTIONS {
            let function = record(&format!("function_{index}"), &format!("0x{index:x}"), &body);
            serde_json::to_writer(&mut writer, &function).unwrap();
            writer.write_all(b"\n").unwrap();
        }
        writer.flush().unwrap();
    }

    let report = export_input(
        &input,
        &ExportOptions {
            output: output.clone(),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    let output_bytes = fs::metadata(&output).unwrap().len();
    assert_eq!(report.records, FUNCTIONS as u64);
    assert!(output_bytes > 100 * 1024 * 1024);
    assert_eq!(report.written_bytes, output_bytes);
    assert_eq!(ghirust_core::cache::hash_file(&output).unwrap().len(), 64);

    let manifest = fs::File::open(temp.path().join("large-output.c.manifest.ndjson")).unwrap();
    assert_eq!(BufReader::new(manifest).lines().count(), FUNCTIONS);
    eprintln!(
        "streamed {} functions into {} bytes in {} ms",
        report.records, output_bytes, report.elapsed_ms
    );
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
