#!/usr/bin/env python3
"""GHIRUST vs Ghidra objective comparison.

This tool coordinates a real, reproducible comparison:

1. Hashes the binary and captures the environment (OS, CPU, tool versions).
2. Runs Ghidra headless with ExportProgram.java and stores the NDJSON export.
3. Runs the GHIRUST CLI `benchmark` command (real analysis, N runs, samples)
   and stores the full analysis JSON plus the benchmark JSON.
4. Normalizes both outputs to relative virtual addresses (RVA).
5. Compares sections, entry, imports, strings, functions, instructions,
   basic blocks, CFG edges and decompiled text.
6. Writes comparison.json, comparison.md and functions.csv.

It never fabricates results: anything not measured is recorded as null with a
reason, and failures abort with a non-zero exit code.

Usage:
  python tools/compare.py --binary tests/objectives/binaries/demo.dll \
      --ghidra-home "C:/.../ghidra_12.2_PUBLIC" \
      [--java-home "C:/Program Files/Java/jdk-25"] \
      [--ghirust ghirust/target/release/ghirust.exe] \
      [--runs 3] [--output-dir tests/objectives/results]
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = Path(__file__).resolve().parents[1] / "ghidra"


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(2)


def run_command(command, timeout=1800, env=None, log_path=None, cwd=None):
    """Run a command, tee output to an optional log, return (returncode, stdout)."""
    print("+ " + " ".join(str(part) for part in command))
    log_file = open(log_path, "w", encoding="utf-8", errors="replace") if log_path else None
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines = []
    assert process.stdout is not None
    for raw in process.stdout:
        lines.append(raw)
        if log_file is not None:
            log_file.write(raw)
    returncode = process.wait(timeout=timeout)
    elapsed = time.monotonic() - started
    if log_file is not None:
        log_file.close()
    return returncode, "".join(lines), elapsed


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_java_home(requested):
    if requested:
        if Path(requested, "bin", "java.exe").exists():
            return str(Path(requested))
        fail(f"--java-home {requested} has no bin/java.exe")
    env_home = os.environ.get("JAVA_HOME")
    if env_home and Path(env_home, "bin", "java.exe").exists():
        return env_home
    located = shutil.which("java")
    if located:
        return str(Path(located).parent.parent)
    fail("no JDK found: pass --java-home or set JAVA_HOME")


def locate_ghirust(requested, repo_root):
    if requested:
        path = Path(requested)
        if path.is_file():
            return str(path)
        fail(f"--ghirust {requested} is not a file")
    release = repo_root / "ghirust" / "target" / "release" / "ghirust.exe"
    if release.is_file():
        return str(release)
    debug = repo_root / "ghirust" / "target" / "debug" / "ghirust.exe"
    if debug.is_file():
        return str(debug)
    print("GHIRUST binary not built; running cargo build --release -p ghirust-cli")
    returncode, _, _ = run_command(
        ["cargo", "build", "--release", "-p", "ghirust-cli"],
        timeout=2400,
        env=None,
        cwd=str(repo_root / "ghirust"),
    )
    if returncode != 0 or not release.is_file():
        fail("could not build the GHIRUST CLI")
    return str(release)


def capture_environment(ghidra_home, java_home, ghirust_path, binary, runs):
    ghidra_version = None
    properties = Path(ghidra_home) / "Ghidra" / "application.properties"
    if properties.is_file():
        for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                ghidra_version = line.split("=", 1)[1]
    java_version = None
    java_bin = Path(java_home) / "bin" / "java.exe"
    if java_bin.is_file():
        returncode, output, _ = run_command([str(java_bin), "-version"], timeout=120)
        java_version = (output or "").splitlines()[0].strip() if returncode == 0 else None
    ghirust_version = None
    returncode, output, _ = run_command([ghirust_path, "--version"], timeout=120)
    if returncode == 0:
        ghirust_version = (output or "").strip().splitlines()[0] if output else None
    return {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python": platform.python_version(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER"),
        "logical_processors": os.environ.get("NUMBER_OF_PROCESSORS"),
        "rustc": run_tool_version(["rustc", "--version"]),
        "cargo": run_tool_version(["cargo", "--version"]),
        "ghidra_home": str(ghidra_home),
        "ghidra_version": ghidra_version,
        "java_home": java_home,
        "java_version": java_version,
        "ghirust_binary": ghirust_path,
        "ghirust_version": ghirust_version,
        "runs": runs,
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "binary_bytes": binary.stat().st_size,
    }


def run_tool_version(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return (result.stdout or result.stderr or "").strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def run_ghidra(args, env):
    output = args.output_dir / "ghidra.ndjson"
    log = args.output_dir / "ghidra.log"
    if args.reuse_ghidra and output.is_file():
        print(f"Reusing existing Ghidra export: {output}")
        return output, None
    project_dir = Path(tempfile.mkdtemp(prefix="ghirust-ghidra-project-"))
    project_name = "GhirustObjective"
    command = [
        str(Path(args.ghidra_home) / "support" / "analyzeHeadless.bat"),
        str(project_dir),
        project_name,
        "-import",
        str(args.binary),
        "-scriptPath",
        str(SCRIPT_DIR),
        "-postScript",
        "ExportProgram.java",
        str(output),
        "-deleteProject",
        "-analysisTimeoutPerFile",
        "900",
    ]
    returncode, _, elapsed = run_command(command, timeout=1800, env=env, log_path=log)
    if returncode != 0 or not output.is_file():
        fail(f"Ghidra headless analysis failed; see {log}")
    return output, elapsed


def run_ghirust(args, env):
    analysis = args.output_dir / "ghirust.analysis.json"
    benchmark_out = args.output_dir / "ghirust.benchmark.json"
    command = [
        args.ghirust,
        "benchmark",
        str(args.binary),
        "--runs",
        str(args.runs),
        "--save-analysis",
        str(analysis),
        "--json",
    ]
    returncode, stdout, elapsed = run_command(
        command, timeout=1800, env=env, log_path=None
    )
    if returncode != 0:
        fail("GHIRUST benchmark failed:\n" + stdout[-4000:])
    benchmark_out.write_text(stdout, encoding="utf-8")
    benchmark = json.loads(stdout)
    if not analysis.is_file():
        fail("GHIRUST benchmark succeeded but did not write the analysis")
    return analysis, benchmark, elapsed


def parse_hex(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("0x") or text.startswith("0X"):
            return int(text, 16)
        return int(text, 10)
    return value


def load_ghidra(path):
    records = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    by_type = {}
    for record in records:
        by_type.setdefault(record["type"], []).append(record)
    return by_type


def rva(value, image_base):
    value = parse_hex(value)
    if value is None:
        return None
    return value - image_base


def normalize_ghidra(by_type):
    program = by_type["program"][0]
    image_base = parse_hex(program["image_base"]) or 0
    functions = []
    for function in by_type.get("function", []):
        entry = rva(function["address"], image_base)
        blocks = []
        for block in function.get("blocks", []):
            start = rva(block["start"], image_base)
            blocks.append(
                {
                    "start": start,
                    "end": rva(block["end"], image_base),
                    "edges": sorted(
                        {rva(edge, image_base) for edge in block.get("edges", [])}
                    ),
                    "instructions": [
                        {
                            "address": rva(ins["address"], image_base),
                            "mnemonic": ins["mnemonic"].strip().lower(),
                            "operands": ins.get("operands", ""),
                        }
                        for ins in block.get("instructions", [])
                    ],
                }
            )
        functions.append(
            {
                "address": entry,
                "name": function["name"],
                "size": function.get("size"),
                "external": function.get("external", False),
                "thunk": function.get("thunk", False),
                "external_entry": function.get("external_entry", False),
                "calling_convention": function.get("calling_convention"),
                "blocks": blocks,
                "decompiled": function.get("decompiled", ""),
            }
        )
    memory = [
        {
            "name": block["name"],
            "start": rva(block["start"], image_base),
            "end": rva(block["end"], image_base),
            "execute": block.get("execute", False),
        }
        for block in by_type.get("memory", [])
    ]
    imports = [
        {
            "name": item["name"],
            "namespace": item.get("namespace", ""),
        }
        for item in by_type.get("import", [])
    ]
    strings = [
        {
            "address": rva(item["address"], image_base),
            "value": item["value"],
            "data_type": item.get("data_type"),
        }
        for item in by_type.get("string", [])
    ]
    return {
        "program": {
            "name": program.get("name"),
            "format": program.get("format"),
            "language": program.get("language"),
            "compiler": program.get("compiler"),
            "image_base": image_base,
            "entry": rva(program.get("entry"), image_base),
            "entries": sorted(
                {rva(item, image_base) for item in program.get("entries", [])}
            ),
            "function_count": program.get("function_count"),
        },
        "memory": memory,
        "imports": imports,
        "strings": strings,
        "functions": functions,
    }


def normalize_ghirust(analysis):
    loader = analysis["loader"]
    image_base = parse_hex(loader.get("image_base", 0)) or 0
    functions = []
    for function in analysis.get("functions", []):
        blocks = []
        for block in function.get("blocks", []):
            blocks.append(
                {
                    "start": rva(block["start"], image_base),
                    "end": rva(block["end"], image_base),
                    "edges": sorted({rva(target, image_base) for target in block.get("successors", [])}),
                    "instructions": [
                        {
                            "address": rva(ins["address"], image_base),
                            "mnemonic": (ins.get("mnemonic") or "").strip().lower(),
                            "operands": ins.get("operands", ""),
                        }
                        for ins in block.get("instructions", [])
                    ],
                }
            )
        functions.append(
            {
                "address": rva(function["address"], image_base),
                "name": function["name"],
                "size": function.get("size"),
                "external": False,
                "thunk": False,
                "external_entry": function.get("discovery") == "export",
                "calling_convention": None,
                "blocks": blocks,
                "decompiled": function.get("decompiled", {}).get("text", ""),
            }
        )
    memory = [
        {
            "name": section.get("name", ""),
            "start": rva(section.get("address"), image_base),
            "end": rva(section.get("address"), image_base) + int(section.get("virtual_size", 0) or 0),
            "execute": (section.get("kind") or "") in ("code", "text", "exec"),
        }
        for section in analysis.get("sections", [])
    ]
    imports = [
        {
            "name": item.get("name", ""),
            "namespace": item.get("library", ""),
        }
        for item in analysis.get("imports", [])
    ]
    strings = [
        {
            "address": rva(item.get("offset"), image_base),
            "value": item.get("value", ""),
            "data_type": None,
        }
        for item in analysis.get("strings", [])
    ]
    return {
        "program": {
            "name": analysis.get("path", "").rsplit("\\", 1)[-1],
            "format": loader.get("format"),
            "language": f"{loader.get('architecture')}:{'LE' if loader.get('endian') == 'little' else 'BE'}:{loader.get('bits')}:default",
            "compiler": loader.get("os"),
            "image_base": image_base,
            "entry": rva(loader.get("entry"), image_base),
            "entries": sorted(
                {
                    rva(item.get("address"), image_base)
                    for item in analysis.get("exports", [])
                    if item.get("address") is not None
                }
            ),
            "function_count": len(functions),
        },
        "memory": memory,
        "imports": imports,
        "strings": strings,
        "functions": functions,
    }


def tokenize(text):
    """Very coarse lexical tokenization for similarity: identifiers, numbers, operators."""
    tokens = []
    current = []
    for character in text:
        if character.isalnum() or character == "_":
            current.append(character.lower())
        else:
            if current:
                tokens.append("".join(current))
                current = []
            if character in "+-*/%<>=!&|^~?:":
                tokens.append(character)
    if current:
        tokens.append("".join(current))
    return tokens


def lexical_similarity(first, second):
    a = tokenize(first)
    b = tokenize(second)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    set_a = set(a)
    set_b = set(b)
    inter = len(set_a & set_b)
    union = len(set_a | set_b)
    jaccard = inter / union if union else 0.0
    containment = inter / len(set_a) if set_a else 0.0
    return round((jaccard + containment) / 2.0, 4)


def compare_functions(ghidra, ghirust):
    ghira_by_addr = {function["address"]: function for function in ghidra["functions"]}
    ghiri_by_addr = {function["address"]: function for function in ghirust["functions"]}
    common = sorted(set(ghira_by_addr) & set(ghiri_by_addr))
    only_ghidra = sorted(set(ghira_by_addr) - set(ghiri_by_addr))
    only_ghirust = sorted(set(ghiri_by_addr) - set(ghira_by_addr))
    rows = []
    for address in common:
        ghira_fn = ghira_by_addr[address]
        ghiri_fn = ghiri_by_addr[address]
        ghira_insns = {
            ins["address"]: ins
            for block in ghira_fn["blocks"]
            for ins in block["instructions"]
        }
        ghiri_insns = {
            ins["address"]: ins
            for block in ghiri_fn["blocks"]
            for ins in block["instructions"]
        }
        ins_common = sorted(set(ghira_insns) & set(ghiri_insns))
        mnemonic_agree = sum(
            1
            for ins_address in ins_common
            if ghira_insns[ins_address]["mnemonic"] == ghiri_insns[ins_address]["mnemonic"]
        )
        ghira_only_insns = sorted(set(ghira_insns) - set(ghiri_insns))
        ghiri_only_insns = sorted(set(ghiri_insns) - set(ghira_insns))
        ghira_blocks = {block["start"] for block in ghira_fn["blocks"]}
        ghiri_blocks = {block["start"] for block in ghiri_fn["blocks"]}
        ghira_edges = {
            (block["start"], target)
            for block in ghira_fn["blocks"]
            for target in block["edges"]
        }
        ghiri_edges = {
            (block["start"], target)
            for block in ghiri_fn["blocks"]
            for target in block["edges"]
        }
        rows.append(
            {
                "address": address,
                "ghidra_name": ghira_fn["name"],
                "ghirust_name": ghiri_fn["name"],
                "name_match": ghira_fn["name"] == ghiri_fn["name"],
                "ghidra_size": ghira_fn["size"],
                "ghirust_size": ghiri_fn["size"],
                "ghidra_instructions": len(ghira_insns),
                "ghirust_instructions": len(ghiri_insns),
                "common_instructions": len(ins_common),
                "only_ghidra_instructions": len(ghira_only_insns),
                "only_ghirust_instructions": len(ghiri_only_insns),
                "mnemonics_matching": mnemonic_agree,
                "ghidra_blocks": len(ghira_fn["blocks"]),
                "ghirust_blocks": len(ghiri_fn["blocks"]),
                "common_blocks": len(ghira_blocks & ghiri_blocks),
                "ghidra_edges": len(ghira_edges),
                "ghirust_edges": len(ghiri_edges),
                "common_edges": len(ghira_edges & ghiri_edges),
                "decompiled_ghidra_lines": len([line for line in ghira_fn["decompiled"].splitlines() if line.strip()]),
                "decompiled_ghirust_lines": len([line for line in ghiri_fn["decompiled"].splitlines() if line.strip()]),
                "decompiled_lexical_similarity": lexical_similarity(
                    ghira_fn["decompiled"], ghiri_fn["decompiled"]
                ),
            }
        )
    return {
        "total_ghidra": len(ghidra["functions"]),
        "total_ghirust": len(ghirust["functions"]),
        "common": len(common),
        "only_ghidra": only_ghidra,
        "only_ghirust": only_ghirust,
        "function_rows": rows,
    }


def compare_sets(ghidra, ghirust):
    ghira_memory = {item["name"] for item in ghidra["memory"]}
    ghiri_memory = {item["name"] for item in ghirust["memory"]}
    ghira_imports = {item["name"] for item in ghidra["imports"]}
    ghiri_imports = {item["name"] for item in ghirust["imports"]}
    ghira_strings = {item["value"] for item in ghidra["strings"]}
    ghiri_strings = {item["value"] for item in ghirust["strings"]}
    ghira_entries = set(ghidra["program"].get("entries") or [])
    ghiri_entries = set(ghirust["program"].get("entries") or [])
    return {
        "sections": {
            "ghidra": sorted(ghira_memory),
            "ghirust": sorted(ghiri_memory),
            "common": sorted(ghira_memory & ghiri_memory),
            "only_ghidra": sorted(ghira_memory - ghiri_memory),
            "only_ghirust": sorted(ghiri_memory - ghira_memory),
        },
        "imports": {
            "ghidra_count": len(ghira_imports),
            "ghirust_count": len(ghiri_imports),
            "common": len(ghira_imports & ghiri_imports),
            "only_ghidra_count": len(ghira_imports - ghiri_imports),
            "only_ghirust_count": len(ghiri_imports - ghira_imports),
        },
        "strings": {
            "ghidra_count": len(ghira_strings),
            "ghirust_count": len(ghiri_strings),
            "common": len(ghira_strings & ghiri_strings),
            "only_ghidra_count": len(ghira_strings - ghiri_strings),
            "only_ghirust_count": len(ghiri_strings - ghira_strings),
        },
        "exports": {
            "ghidra_count": len(ghira_entries),
            "ghirust_count": len(ghiri_entries),
            "common": len(ghira_entries & ghiri_entries),
            "only_ghidra": sorted(ghira_entries - ghiri_entries),
            "only_ghirust": sorted(ghiri_entries - ghira_entries),
        },
    }


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)


def write_markdown(path, comparison, environment, timings):
    functions = comparison["functions"]
    sets = comparison["sets"]
    program_ghidra = comparison["normalized_ghidra"]["program"]
    program_ghirust = comparison["normalized_ghirust"]["program"]
    rows = functions["function_rows"]
    total_common_insns = sum(row["common_instructions"] for row in rows)
    total_ghidra_insns = sum(row["ghidra_instructions"] for row in rows)
    total_ghirust_insns = sum(row["ghirust_instructions"] for row in rows)
    only_ghidra_insns = sum(row["only_ghidra_instructions"] for row in rows)
    only_ghirust_insns = sum(row["only_ghirust_instructions"] for row in rows)
    mnemonic_agree = sum(row["mnemonics_matching"] for row in rows)
    mnemonic_common = sum(row["common_instructions"] for row in rows)
    common_edges = sum(row["common_edges"] for row in rows)
    ghidra_edges = sum(row["ghidra_edges"] for row in rows)
    ghirust_edges = sum(row["ghirust_edges"] for row in rows)

    lines = []
    add = lines.append
    add("# GHIRUST vs Ghidra comparison")
    add("")
    add(f"Generated: {environment['captured_at']}")
    add("")
    add("## Input")
    add("")
    add(f"- Binary: `{environment['binary']}`")
    add(f"- Size: {environment['binary_bytes']} bytes")
    add(f"- SHA-256: `{environment['binary_sha256']}`")
    add(f"- Ghidra: {environment['ghidra_version']} at `{environment['ghidra_home']}`")
    add(f"- Java: {environment['java_version']} ({environment['java_home']})")
    add(f"- GHIRUST: {environment['ghirust_version']} ({environment['ghirust_binary']})")
    add(f"- Rust: {environment['rustc']} · Python: {environment['python']}")
    add(f"- Hardware: {environment['processor_identifier']} · {environment['logical_processors']} logical processors")
    add("")
    add("## Program identification")
    add("")
    add(f"- Format: Ghidra `{program_ghidra['format']}` vs GHIRUST `{program_ghirust['format']}`")
    add(f"- Architecture: Ghidra `{program_ghidra['language']}` vs GHIRUST `{program_ghirust['language']}`")
    add(f"- PE entry point (GHIRUST loader, RVA): `0x{program_ghirust['entry']:x}`")
    exports = sets["exports"]
    add(
        f"- External entry points/exports: Ghidra {exports['ghidra_count']} · GHIRUST {exports['ghirust_count']} "
        f"· common {exports['common']}"
    )
    if exports["only_ghidra"]:
        add(f"  - Only Ghidra: {', '.join(f'0x{a:x}' for a in exports['only_ghidra'][:12])}")
    if exports["only_ghirust"]:
        add(f"  - Only GHIRUST: {', '.join(f'0x{a:x}' for a in exports['only_ghirust'][:12])}")
    add("")
    add("## Functions")
    add("")
    add(f"- Ghidra: {functions['total_ghidra']} functions")
    add(f"- GHIRUST: {functions['total_ghirust']} functions")
    add(f"- Common entry addresses: {functions['common']}")
    add(f"- Only Ghidra: {len(functions['only_ghidra'])}")
    add(f"- Only GHIRUST: {len(functions['only_ghirust'])}")
    add("")
    if functions["only_ghidra"]:
        add("Only Ghidra (first 60):")
        add("")
        for address in functions["only_ghidra"][:60]:
            name = next(
                (fn["name"] for fn in comparison["normalized_ghidra"]["functions"] if fn["address"] == address),
                "?",
            )
            add(f"- `0x{address:x}` {name}")
        add("")
    if functions["only_ghirust"]:
        add("Only GHIRUST:")
        add("")
        for address in functions["only_ghirust"]:
            name = next(
                (fn["name"] for fn in comparison["normalized_ghirust"]["functions"] if fn["address"] == address),
                "?",
            )
            add(f"- `0x{address:x}` {name}")
        add("")
    add("## Disassembly and CFG (matched functions only)")
    add("")
    add(f"- Instruction addresses (matched functions): GHIRUST {total_ghirust_insns} · common with Ghidra {total_common_insns} · Ghidra {total_ghidra_insns}")
    add(f"- Instructions only in GHIRUST: {only_ghirust_insns} · only in Ghidra: {only_ghidra_insns}")
    add(f"- Mnemonics agreeing on common addresses: {mnemonic_agree}/{mnemonic_common}")
    add(f"- CFG edges: GHIRUST {ghirust_edges} · common with Ghidra {common_edges} · Ghidra {ghidra_edges}")
    add("")
    add("| Function | Name match | GHIDRA insn | Common insn | Only GHIRUST | Mnemonic agree | GHIDRA blocks | Common blocks | GHIDRA edges | Common edges | Lexical sim |")
    add("|---|---|---|---|---|---|---|---|---|---|---|")
    for row in rows:
        add(
            f"| 0x{row['address']:x} {row['ghidra_name']} | {'yes' if row['name_match'] else 'no'} "
            f"| {row['ghidra_instructions']} | {row['common_instructions']} "
            f"| {row['only_ghirust_instructions']} "
            f"| {row['mnemonics_matching']}/{row['common_instructions']} "
            f"| {row['ghidra_blocks']} | {row['common_blocks']} "
            f"| {row['ghidra_edges']} | {row['common_edges']} "
            f"| {row['decompiled_lexical_similarity']} |"
        )
    add("")
    add("## Sets")
    add("")
    add(f"- Sections: {len(sets['sections']['common'])} common · {len(sets['sections']['only_ghidra'])} only Ghidra · {len(sets['sections']['only_ghirust'])} only GHIRUST")
    add(f"- Imports: {sets['imports']['common']} common · {sets['imports']['only_ghidra_count']} only Ghidra · {sets['imports']['only_ghirust_count']} only GHIRUST")
    add(f"- Strings (by value): {sets['strings']['common']} common · {sets['strings']['only_ghidra_count']} only Ghidra · {sets['strings']['only_ghirust_count']} only GHIRUST")
    add("")
    add("## Timing")
    add("")
    ghidra_line = (
        f"{timings.get('ghidra_wall_s'):.1f} s (1 run)"
        if timings.get("ghidra_wall_s") is not None
        else "not measured (reused export)"
    )
    add(f"- Ghidra headless (import + auto-analysis + export): {ghidra_line}")
    add(f"- GHIRUST ({environment['runs']} runs, release CLI): {timings.get('ghirust_wall_s'):.1f} s total")
    add("")
    add("## Interpretation rules")
    add("")
    add("- Addresses are normalized to relative virtual addresses (RVA) using each tool's image base.")
    add("- \"Lexical sim\" is a token Jaccard/containment average over decompiled text; it is NOT semantic equivalence.")
    add("- Ghidra exports more functions because GHIRUST function discovery is seed-based; see the only-Ghidra list.")
    add("- This comparison covers one small PE DLL. Results do not generalize to other formats or architectures.")
    add("")
    add("## Artifacts")
    add("")
    add("- `ghidra.ndjson` — raw Ghidra export (`ExportProgram.java`).")
    add("- `ghirust.analysis.json` — complete GHIRUST analysis.")
    add("- `ghirust.benchmark.json` — per-run GHIRUST samples.")
    add("- `comparison.json` — machine-readable comparison.")
    add("- `functions.csv` — per-function rows.")
    add("- `environment.json` — tool versions and hardware.")
    add("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--name", default=None)
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_HOME"))
    parser.add_argument("--java-home", default=None)
    parser.add_argument("--ghirust", default=None)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "tests" / "objectives" / "results")
    parser.add_argument("--reuse-ghidra", action="store_true")
    args = parser.parse_args()

    if not args.ghidra_home:
        fail("--ghidra-home is required (or set GHIDRA_HOME)")
    if not Path(args.ghidra_home, "support", "analyzeHeadless.bat").exists():
        fail(f"{args.ghidra_home} has no support/analyzeHeadless.bat")
    if not args.binary.is_file():
        fail(f"{args.binary} does not exist")

    name = args.name or args.binary.stem
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = args.output_dir / name
    output_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir = output_dir

    java_home = detect_java_home(args.java_home)
    ghirust_path = locate_ghirust(args.ghirust, REPO_ROOT)
    args.ghirust = ghirust_path
    environment = capture_environment(args.ghidra_home, java_home, ghirust_path, args.binary, args.runs)
    print(f"Environment: Ghidra {environment['ghidra_version']}, Java {environment['java_version']}")

    env = dict(os.environ)
    env["JAVA_HOME"] = java_home
    env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")

    ghidra_export, ghidra_wall = run_ghidra(args, env)
    ghirust_analysis, ghirust_benchmark, ghirust_wall = run_ghirust(args, env)

    with open(ghirust_analysis, encoding="utf-8") as handle:
        ghirust_raw = json.load(handle)
    ghidra_raw = load_ghidra(ghidra_export)
    normalized_ghidra = normalize_ghidra(ghidra_raw)
    normalized_ghirust = normalize_ghirust(ghirust_raw)

    functions = compare_functions(normalized_ghidra, normalized_ghirust)
    sets = compare_sets(normalized_ghidra, normalized_ghirust)

    wall_samples = [sample["wall_ms"] for sample in ghirust_benchmark.get("samples", [])]
    timings = {
        "ghidra_wall_s": ghidra_wall,
        "ghirust_wall_s": ghirust_wall,
        "ghirust_samples_ms": wall_samples,
        "ghirust_wall_median_ms": statistics.median(wall_samples) if wall_samples else None,
        "ghirust_wall_mean_ms": round(statistics.mean(wall_samples), 1) if wall_samples else None,
        "ghirust_wall_min_ms": min(wall_samples) if wall_samples else None,
        "ghirust_wall_max_ms": max(wall_samples) if wall_samples else None,
        "memory_measured": False,
        "memory_note": "Peak memory is not captured by this run; no psutil integration is active.",
    }

    comparison = {
        "name": name,
        "normalized_ghidra": normalized_ghidra,
        "normalized_ghirust": normalized_ghirust,
        "functions": functions,
        "sets": sets,
        "timings": timings,
        "environment": environment,
    }
    (output_dir / "comparison.json").write_text(
        json.dumps(comparison, indent=2), encoding="utf-8"
    )
    (output_dir / "environment.json").write_text(
        json.dumps(environment, indent=2), encoding="utf-8"
    )
    write_csv(output_dir / "functions.csv", functions["function_rows"])
    write_markdown(output_dir / "comparison.md", comparison, environment, timings)

    print(f"Comparison written to {output_dir}")
    print(
        f"Functions: Ghidra {functions['total_ghidra']} · GHIRUST {functions['total_ghirust']} "
        f"· common {functions['common']}"
    )
    print(f"Sections: {sets['sections']['common']} common")
    print(f"Imports: {sets['imports']['common']} common")
    print(f"Strings: {sets['strings']['common']} common")


if __name__ == "__main__":
    main()
