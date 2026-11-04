# GHIRUST vs Ghidra comparison

Generated: 2026-11-04T18:05:17+0000

## Input

- Binary: `./tests\objectives\binaries\demo_bridge.dll`
- Size: 9216 bytes
- SHA-256: `17491795c347b57bdbfd4cb007a09cfd3a0ccdec27bf9bd5d076edb2ee3fba99`
- Ghidra: 12.2 at `$GHIDRA_HOME`
- Java: java version "25.0.4.1" 2026-08-18 LTS ($JAVA_HOME)
- GHIRUST: ghirust 0.1.0 (./ghirust\target\release\ghirust.exe)
- Rust: rustc 1.98.1 (48a229cea 2026-09-01) · Python: 3.12.9
- Hardware: Intel64 Family 6 Model 186 Stepping 2, GenuineIntel · 16 logical processors

## Program identification

- Format: Ghidra `Portable Executable (PE)` vs GHIRUST `PE`
- Architecture: Ghidra `x86:LE:64:default` vs GHIRUST `X86_64:LE:64:default`
- PE entry point (GHIRUST loader, RVA): `0x1380`
- External entry points/exports: Ghidra 3 · GHIRUST 2 · common 2
  - Only Ghidra: 0x1380

## Functions

- Ghidra: 55 functions
- GHIRUST: 52 functions
- Common entry addresses: 49
- Only Ghidra: 6
- Only GHIRUST: 3

Only Ghidra (first 60):

- `0x1980` _guard_check_icall_nop
- `0x1c60` memcpy
- `0x1c66` __C_specific_handler
- `0x1ce0` _guard_dispatch_icall_nop
- `0x1d00` _guard_xfg_dispatch_icall_nop
- `0x1d4a` fin$1

Only GHIRUST:

- `0x1366` FUN_180001366
- `0x1400` FUN_180001400
- `0x16fc` FUN_1800016fc

## Disassembly and CFG (matched functions only)

- Instruction addresses (matched functions): GHIRUST 823 · common with Ghidra 818 · Ghidra 828
- Instructions only in GHIRUST: 5 · only in Ghidra: 10
- Mnemonics agreeing on common addresses: 726/818
- CFG edges: GHIRUST 240 · common with Ghidra 229 · Ghidra 232

| Function | Name match | GHIDRA insn | Common insn | Only GHIRUST | Mnemonic agree | GHIDRA blocks | Common blocks | GHIDRA edges | Common edges | Lexical sim |
|---|---|---|---|---|---|---|---|---|---|---|
| 0x1000 bridge_direct | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.25 |
| 0x1010 bridge_roundtrip | yes | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.3409 |
| 0x1030 dllmain_crt_dispatch | no | 27 | 27 | 0 | 22/27 | 9 | 9 | 8 | 8 | 0.1487 |
| 0x1090 dllmain_crt_process_attach | no | 71 | 71 | 2 | 63/71 | 13 | 13 | 18 | 18 | 0.1878 |
| 0x11a0 dllmain_crt_process_detach | no | 37 | 37 | 3 | 36/37 | 5 | 5 | 4 | 4 | 0.2216 |
| 0x1240 dllmain_dispatch | no | 98 | 91 | 0 | 79/91 | 22 | 21 | 33 | 33 | 0.1566 |
| 0x1380 _DllMainCRTStartup | no | 18 | 18 | 0 | 17/18 | 3 | 3 | 3 | 3 | 0.1475 |
| 0x13d0 __chkstk | no | 19 | 19 | 0 | 16/19 | 4 | 4 | 5 | 5 | 0.3367 |
| 0x1420 __scrt_acquire_startup_lock | no | 20 | 20 | 0 | 14/20 | 6 | 6 | 8 | 8 | 0.2137 |
| 0x1470 __scrt_dllmain_after_initialize_c | no | 20 | 20 | 0 | 18/20 | 5 | 5 | 4 | 4 | 0.1607 |
| 0x14b0 __scrt_dllmain_before_initialize_c | no | 26 | 26 | 0 | 22/26 | 8 | 8 | 10 | 10 | 0.2353 |
| 0x1530 __scrt_dllmain_crt_thread_attach | no | 14 | 14 | 0 | 12/14 | 5 | 5 | 5 | 5 | 0.2169 |
| 0x1560 __scrt_dllmain_crt_thread_detach | no | 6 | 6 | 0 | 6/6 | 1 | 1 | 0 | 0 | 0.1661 |
| 0x1580 __scrt_dllmain_exception_filter | no | 27 | 27 | 0 | 25/27 | 4 | 4 | 5 | 5 | 0.1325 |
| 0x15d0 __scrt_dllmain_uninitialize_c | no | 14 | 14 | 0 | 12/14 | 5 | 5 | 4 | 4 | 0.2304 |
| 0x1610 __scrt_dllmain_uninitialize_critical | no | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.1106 |
| 0x1630 __scrt_initialize_crt | no | 19 | 19 | 0 | 16/19 | 7 | 7 | 8 | 8 | 0.1227 |
| 0x1670 __scrt_is_nonwritable_in_current_image | no | 44 | 42 | 0 | 36/42 | 14 | 13 | 20 | 20 | 0.2828 |
| 0x1710 __scrt_release_startup_lock | no | 13 | 13 | 0 | 11/13 | 4 | 4 | 5 | 5 | 0.1695 |
| 0x1740 __scrt_uninitialize_crt | no | 14 | 14 | 0 | 12/14 | 4 | 4 | 5 | 5 | 0.1006 |
| 0x1770 __security_init_cookie | no | 42 | 42 | 0 | 40/42 | 3 | 3 | 2 | 2 | 0.2504 |
| 0x1830 DllMain | no | 9 | 9 | 0 | 7/9 | 4 | 4 | 5 | 5 | 0.1713 |
| 0x1860 __scrt_initialize_type_info | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2036 |
| 0x1870 __scrt_uninitialize_type_info | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.0828 |
| 0x1880 __local_stdio_printf_options | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1875 |
| 0x1890 __local_stdio_scanf_options | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1875 |
| 0x18a0 __scrt_initialize_default_local_stdio_options | no | 7 | 7 | 0 | 7/7 | 1 | 1 | 0 | 0 | 0.3421 |
| 0x18c0 __scrt_get_dyn_tls_init_callback | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1506 |
| 0x18d0 __scrt_fastfail | no | 3 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1003 |
| 0x18e0 _RTC_Initialize | no | 19 | 19 | 0 | 16/19 | 6 | 6 | 8 | 8 | 0.2063 |
| 0x1930 _RTC_Terminate | no | 19 | 19 | 0 | 16/19 | 6 | 6 | 8 | 8 | 0.2063 |
| 0x1990 __isa_available_init | no | 160 | 160 | 0 | 141/160 | 40 | 39 | 64 | 61 | 0.3017 |
| 0x1c40 _get_startup_argv_mode | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1937 |
| 0x1c50 __scrt_is_ucrt_dll_in_use | no | 4 | 4 | 0 | 3/4 | 1 | 1 | 0 | 0 | 0.3359 |
| 0x1c6c __std_type_info_destroy_list | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1c72 _initterm | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1c78 _initterm_e | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1c7e _seh_filter_dll | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1c84 _configure_narrow_argv | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1c8a _initialize_narrow_environment | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1c90 _initialize_onexit_table | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x1c96 _execute_onexit_table | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1c9c _cexit | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2002 |
| 0x1cb0 __scrt_stub_for_acrt_initialize | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1937 |
| 0x1cc0 __scrt_stub_for_is_c_termination_complete | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2917 |
| 0x1d10 fin$0 | no | 7 | 7 | 0 | 7/7 | 1 | 1 | 0 | 0 | 0.0842 |
| 0x1d30 fin$0 | no | 9 | 9 | 0 | 9/9 | 1 | 1 | 0 | 0 | 0.0848 |
| 0x1d60 filt$0 | no | 16 | 16 | 0 | 16/16 | 1 | 1 | 0 | 0 | 0.0873 |
| 0x1da0 __scrt_is_nonwritable_in_current_image$filt$0 | no | 9 | 9 | 0 | 8/9 | 1 | 1 | 0 | 0 | 0.1812 |

## Sets

- Sections: 5 common · 2 only Ghidra · 0 only GHIRUST
- Imports: 18 common · 0 only Ghidra · 0 only GHIRUST
- Strings (by value): 30 common · 2 only Ghidra · 73 only GHIRUST

## Timing

- Ghidra headless (import + auto-analysis + export): not measured (reused export)
- GHIRUST (3 runs, release CLI): 0.2 s total

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
