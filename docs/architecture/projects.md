# Projects and Persistence

A GHIRUST project is a self-contained directory that stores imported binaries,
complete analyses, user annotations and named sessions. The format is JSON plus
ordinary files so it can be inspected and recovered without a database engine.

## Layout

```text
project/
  project.json                    manifest (name, settings, programs)
  programs/
    <program-id>/
      binary                      imported copy (copy mode only)
      analysis.json               complete ProgramAnalysis
      user.json                   renames, comments, types, bookmarks
  sessions/
    <name>.json                   saved UI/session state
```

`<program-id>` is the first 16 hexadecimal characters of the binary SHA-256,
with a numeric suffix if an ID collision occurs. Re-importing identical bytes
returns the existing program instead of creating a duplicate.

## Manifest

`project.json` records:

- format version (`PROJECT_VERSION = 1`);
- project name and creation/update timestamps;
- import settings and language/theme defaults;
- one entry per program: ID, display name, source path, stored path, SHA-256,
  format, architecture, bitness, object kind, entry point, import time,
  last analysis time and recovered function/instruction counts.

## Import modes

- **Copy** — the binary is copied to `programs/<id>/binary`, making the project
  portable.
- **Reference** — only the absolute source path is recorded. The binary must
  remain available for analysis.

## Analysis persistence

`project analyze` runs the same `analyze_path` engine as the CLI and GUI and
writes the complete `ProgramAnalysis` to `analysis.json`. Before saving, it
checks that the binary still has the SHA-256 recorded at import time. If the
file changed, the analysis is rejected and the user must re-import.

## User overrides

`user.json` stores:

```json
{
  "format_version": 1,
  "functions": { "6442455040": { "name": "...", "return_type": "...", "comment": "..." } },
  "comments": { "6442455040": "..." },
  "data_types": { "6442455040": "..." },
  "bookmarks": [ { "address": 6442455040, "label": "...", "note": "..." } ]
}
```

JSON object keys are decimal strings because JSON requires string keys. When an
analysis is loaded with `load_analysis_with_overrides`, the overlay applies
renames to function records and signatures, return-type overrides to signatures,
and comments/types to the affected function text.

Overrides never modify `analysis.json`; re-running analysis preserves user work.

## Sessions

A session stores the selected program, function and cursor addresses, last search
query, notes and a timestamp. Session names are restricted to ASCII letters,
digits, `-`, `_` and `.`, and may not contain `..`, preventing path traversal.

## Durability and recovery

Every JSON write is atomic:

1. write to `.<name>.tmp-<pid>`;
2. flush and `sync_all`;
3. move the previous file to `<name>.bak`;
4. rename the temporary file into place;
5. remove the backup.

On project open, `recover()`:

- removes stale `.tmp-` files;
- restores a `.bak` file when the destination is missing;
- removes obsolete backups when the destination exists;
- recurses into `programs/<id>` so a crash during analysis is recoverable.

## Verification

`Project::verify()` checks each program in two steps:

1. the binary exists and hashes to the recorded SHA-256;
2. `analysis.json` exists and its embedded SHA-256 matches the binary.

The CLI exposes this as `ghirust project verify <root> [--json]`.

## CLI workflow

```text
ghirust project create <root> --name "Analysis"
ghirust project import <root> <binary>
ghirust project analyze <root> <program-id>
ghirust project list <root>
ghirust project show <root> <program-id>
ghirust project rename <root> <program-id> 0x401000 my_function
ghirust project comment <root> <program-id> 0x401000 "reviewed"
ghirust project type <root> <program-id> 0x401000 "uint64_t"
ghirust project bookmark <root> <program-id> 0x401000 entry --note "start"
ghirust project session save <root> main --program <id> --function 0x401000
ghirust project session list <root>
ghirust project verify <root>
```
