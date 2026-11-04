# GHIRUST vs Ghidra comparison

Generated: 2026-11-04T18:06:06+0000

## Input

- Binary: `./tests\objectives\binaries\demo.dll`
- Size: 9728 bytes
- SHA-256: `8e333cc5e9f91a82c675beaf108e8cfccb33e9d5e2c34e8c8fb30705cedd8773`
- Ghidra: 12.2 at `$GHIDRA_HOME`
- Java: java version "25.0.4.1" 2026-08-18 LTS ($JAVA_HOME)
- GHIRUST: ghirust 0.1.0 (./ghirust\target\release\ghirust.exe)
- Rust: rustc 1.98.1 (48a229cea 2026-09-01) · Python: 3.12.9
- Hardware: Intel64 Family 6 Model 186 Stepping 2, GenuineIntel · 16 logical processors

## Program identification

- Format: Ghidra `Portable Executable (PE)` vs GHIRUST `PE`
- Architecture: Ghidra `x86:LE:64:default` vs GHIRUST `X86_64:LE:64:default`
- PE entry point (GHIRUST loader, RVA): `0x1440`
- External entry points/exports: Ghidra 7 · GHIRUST 6 · common 6
  - Only Ghidra: 0x1440

## Functions

- Ghidra: 57 functions
- GHIRUST: 57 functions
- Common entry addresses: 53
- Only Ghidra: 4
- Only GHIRUST: 4

Only Ghidra (first 60):

- `0x1a40` _guard_check_icall
- `0x1da0` _guard_dispatch_icall
- `0x1dc0` _guard_dispatch_icall
- `0x1e0a` FUN_180001e0a

Only GHIRUST:

- `0x10d8` FUN_1800010d8
- `0x1426` FUN_180001426
- `0x14c0` FUN_1800014c0
- `0x17bc` FUN_1800017bc

## Disassembly and CFG (matched functions only)

- Instruction addresses (matched functions): GHIRUST 875 · common with Ghidra 875 · Ghidra 891
- Instructions only in GHIRUST: 0 · only in Ghidra: 16
- Mnemonics agreeing on common addresses: 778/875
- CFG edges: GHIRUST 253 · common with Ghidra 242 · Ghidra 249

| Function | Name match | GHIDRA insn | Common insn | Only GHIRUST | Mnemonic agree | GHIDRA blocks | Common blocks | GHIDRA edges | Common edges | Lexical sim |
|---|---|---|---|---|---|---|---|---|---|---|
| 0x1000 demo_add | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.25 |
| 0x1010 demo_classify | yes | 8 | 8 | 0 | 7/8 | 1 | 1 | 0 | 0 | 0.2905 |
| 0x1030 demo_fact | yes | 9 | 9 | 0 | 8/9 | 4 | 4 | 5 | 5 | 0.3612 |
| 0x1050 demo_max | yes | 4 | 4 | 0 | 4/4 | 1 | 1 | 0 | 0 | 0.2132 |
| 0x1060 demo_mix | yes | 6 | 6 | 0 | 6/6 | 1 | 1 | 0 | 0 | 0.2199 |
| 0x1070 demo_sum_loop | yes | 36 | 30 | 0 | 27/30 | 10 | 7 | 12 | 8 | 0.2779 |
| 0x10f0 FUN_1800010f0 | yes | 27 | 27 | 0 | 22/27 | 9 | 9 | 8 | 8 | 0.2492 |
| 0x1150 FUN_180001150 | yes | 73 | 73 | 0 | 65/73 | 13 | 13 | 18 | 18 | 0.2821 |
| 0x1260 FUN_180001260 | yes | 40 | 40 | 0 | 39/40 | 5 | 5 | 4 | 4 | 0.3101 |
| 0x1300 FUN_180001300 | yes | 98 | 91 | 0 | 79/91 | 22 | 21 | 33 | 33 | 0.2255 |
| 0x1440 entry | yes | 18 | 18 | 0 | 17/18 | 3 | 3 | 3 | 3 | 0.2627 |
| 0x1490 __chkstk | no | 19 | 19 | 0 | 16/19 | 4 | 4 | 5 | 5 | 0.2782 |
| 0x14e0 FUN_1800014e0 | yes | 20 | 20 | 0 | 14/20 | 6 | 6 | 8 | 8 | 0.2573 |
| 0x1530 FUN_180001530 | yes | 20 | 20 | 0 | 18/20 | 5 | 5 | 4 | 4 | 0.24 |
| 0x1570 FUN_180001570 | yes | 26 | 26 | 0 | 22/26 | 8 | 8 | 10 | 10 | 0.2591 |
| 0x15f0 FUN_1800015f0 | yes | 14 | 14 | 0 | 12/14 | 5 | 5 | 5 | 5 | 0.4599 |
| 0x1620 FUN_180001620 | yes | 6 | 6 | 0 | 6/6 | 1 | 1 | 0 | 0 | 0.4808 |
| 0x1640 FUN_180001640 | yes | 27 | 27 | 0 | 25/27 | 4 | 4 | 5 | 5 | 0.1699 |
| 0x1690 FUN_180001690 | yes | 14 | 14 | 0 | 12/14 | 5 | 5 | 4 | 4 | 0.2768 |
| 0x16d0 FUN_1800016d0 | yes | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.4091 |
| 0x16f0 FUN_1800016f0 | yes | 19 | 19 | 0 | 16/19 | 7 | 7 | 8 | 8 | 0.2443 |
| 0x1730 FUN_180001730 | yes | 44 | 42 | 0 | 36/42 | 14 | 13 | 20 | 20 | 0.299 |
| 0x17d0 FUN_1800017d0 | yes | 13 | 13 | 0 | 11/13 | 4 | 4 | 5 | 5 | 0.2113 |
| 0x1800 FUN_180001800 | yes | 14 | 14 | 0 | 12/14 | 4 | 4 | 5 | 5 | 0.3136 |
| 0x1830 FUN_180001830 | yes | 42 | 42 | 0 | 40/42 | 3 | 3 | 2 | 2 | 0.3051 |
| 0x18f0 FUN_1800018f0 | yes | 9 | 9 | 0 | 7/9 | 4 | 4 | 5 | 5 | 0.2307 |
| 0x1920 FUN_180001920 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2421 |
| 0x1930 FUN_180001930 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1905 |
| 0x1940 FUN_180001940 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2548 |
| 0x1950 FUN_180001950 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2548 |
| 0x1960 FUN_180001960 | yes | 7 | 7 | 0 | 7/7 | 1 | 1 | 0 | 0 | 0.5303 |
| 0x1980 FUN_180001980 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2548 |
| 0x1990 FUN_180001990 | yes | 3 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1627 |
| 0x19a0 FUN_1800019a0 | yes | 19 | 19 | 0 | 16/19 | 6 | 6 | 8 | 8 | 0.2635 |
| 0x19f0 FUN_1800019f0 | yes | 19 | 19 | 0 | 16/19 | 6 | 6 | 8 | 8 | 0.2635 |
| 0x1a50 FUN_180001a50 | yes | 160 | 160 | 0 | 141/160 | 40 | 39 | 64 | 61 | 0.3182 |
| 0x1d00 FUN_180001d00 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.4588 |
| 0x1d10 FUN_180001d10 | yes | 4 | 4 | 0 | 3/4 | 1 | 1 | 0 | 0 | 0.4482 |
| 0x1d2c __std_type_info_destroy_list | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1d32 _initterm | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1d38 _initterm_e | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1d3e _seh_filter_dll | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1d44 _configure_narrow_argv | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1d4a _initialize_narrow_environment | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1d50 _initialize_onexit_table | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1d56 _execute_onexit_table | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1d5c _cexit | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2002 |
| 0x1d70 FUN_180001d70 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.4588 |
| 0x1d80 FUN_180001d80 | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.4588 |
| 0x1dd0 FUN_180001dd0 | yes | 7 | 7 | 0 | 7/7 | 1 | 1 | 0 | 0 | 0.1019 |
| 0x1df0 FUN_180001df0 | yes | 9 | 9 | 0 | 9/9 | 1 | 1 | 0 | 0 | 0.1544 |
| 0x1e20 FUN_180001e20 | yes | 16 | 16 | 0 | 16/16 | 1 | 1 | 0 | 0 | 0.1583 |
| 0x1e60 FUN_180001e60 | yes | 9 | 9 | 0 | 8/9 | 1 | 1 | 0 | 0 | 0.2426 |

## Sets

- Sections: 5 common · 2 only Ghidra · 0 only GHIRUST
- Imports: 17 common · 0 only Ghidra · 0 only GHIRUST
- Strings (by value): 32 common · 2 only Ghidra · 73 only GHIRUST

## Timing

- Ghidra headless (import + auto-analysis + export): 36.6 s (1 run)
- GHIRUST (3 runs, release CLI): 0.1 s total

## Interpretation rules

- Addresses are normalized to relative virtual addresses (RVA) using each tool's image base.
- "Lexical sim" is a token Jaccard/containment average over decompiled text; it is NOT semantic equivalence.
- Ghidra exports more functions because GHIRUST function discovery is seed-based; see the only-Ghidra list.
- This comparison covers one small PE DLL. Results do not generalize to other formats or architectures.

## Artifacts

- `ghidra.ndjson` — raw Ghidra export (`ExportProgram.java`).
- `ghirust.analysis.json` — complete GHIRUST analysis.
- `ghirust.benchmark.json` — per-run GHIRUST samples.
- `comparison.json` — machine-readable comparison.
- `functions.csv` — per-function rows.
- `environment.json` — tool versions and hardware.
