# GHIRUST vs Ghidra comparison

Generated: 2026-11-04T18:05:05+0000

## Input

- Binary: `./tests\objectives\binaries\demo_features.dll`
- Size: 116736 bytes
- SHA-256: `36af896e2fbad67aa8485735ffa62a333926db35df607faa2138a74b3336f039`
- Ghidra: 12.2 at `$GHIDRA_HOME`
- Java: java version "25.0.4.1" 2026-08-18 LTS ($JAVA_HOME)
- GHIRUST: ghirust 0.1.0 (./ghirust\target\release\ghirust.exe)
- Rust: rustc 1.98.1 (48a229cea 2026-09-01) · Python: 3.12.9
- Hardware: Intel64 Family 6 Model 186 Stepping 2, GenuineIntel · 16 logical processors

## Program identification

- Format: Ghidra `Portable Executable (PE)` vs GHIRUST `PE`
- Architecture: Ghidra `x86:LE:64:default` vs GHIRUST `X86_64:LE:64:default`
- PE entry point (GHIRUST loader, RVA): `0x13990`
- External entry points/exports: Ghidra 23 · GHIRUST 22 · common 22
  - Only Ghidra: 0x13990

## Functions

- Ghidra: 385 functions
- GHIRUST: 468 functions
- Common entry addresses: 327
- Only Ghidra: 58
- Only GHIRUST: 141

Only Ghidra (first 60):

- `0x1820` drop_glue<alloc::vec::Vec<u8,alloc::alloc::Global>_>
- `0x1900` drop_glue<std::sys::backtrace::_print_fmt::closure_env$0>
- `0x19a0` destroy<core::cell::Cell<enum2$<core::option::Option<alloc::sync::Arc<std::sync::poison::mutex::Mutex<alloc::vec::Vec<u8,alloc::alloc::Global>_>,alloc::alloc::Global>_>_>_>_>
- `0x21ba` Unwind@1800021ba
- `0x22b0` closure$0
- `0x22d0` call_once<std::sys::backtrace::_print_fmt::closure$1::closure_env$0,tuple$<ref$<std::backtrace_rs::symbolize::Symbol>_>_>
- `0x3abf` default_alloc_error_hook
- `0x3c25` Unwind@180003c25
- `0x3e9d` Unwind@180003e9d
- `0x4159` Unwind@180004159
- `0x5f80` free_fls_key_at_exit
- `0x6560` is_interrupted
- `0x6570` decode_error_kind
- `0x69b0` type_id<alloc::string::String>
- `0x69c0` type_id<ref$<str$>_>
- `0x70b0` fmt
- `0x71c0` get
- `0x71d0` as_str
- `0x72b0` fmt<core::num::error::IntErrorKind>
- `0x72e0` fmt<u8>
- `0x7380` fmt<str$>
- `0x73a0` fmt<dyn$<core::panic::PanicPayload>_>
- `0x74b0` fmt
- `0x74d0` write
- `0x7a90` fmt
- `0x80c0` fmt<core::ffi::c_void>
- `0x89a0` write_fmt<std::io::default_write_fmt::Adapter<alloc::vec::Vec<u8,alloc::alloc::Global>_>_>
- `0x8b40` write_fmt<std::io::default_write_fmt::Adapter<core::io::cursor::Cursor<ref_mut$<slice2$<u8>_>_>_>_>
- `0x8ca0` write_fmt<std::io::default_write_fmt::Adapter<std::sys::stdio::windows::Stderr>_>
- `0x8d60` write_fmt<alloc::string::String>
- `0x8d80` write_vectored<std::sys::stdio::windows::Stderr>
- `0xe665` fmt
- `0xe68f` fmt
- `0xe6a1` fmt
- `0xe6c0` fmt
- `0xe6d2` fmt
- `0xe74b` FUN_18000e74b
- `0xeb42` write_char
- `0xebee` write_fmt
- `0xf3a0` fmt
- `0xf540` write_fmt<alloc::string::String>
- `0x11b40` char_count_general_case
- `0x12860` fmt<str$>
- `0x12ab0` fmt
- `0x135f0` fmt
- `0x13610` call_once<core::io::error::impl$7::DEFAULT::closure_env$1,tuple$<i32>_>
- `0x13620` write_fmt<core::fmt::builders::PadAdapter>
- `0x13fd0` _guard_check_icall_nop
- `0x142bc` __CxxFrameHandler3
- `0x142c8` __C_specific_handler
- `0x142d4` strlen
- `0x14340` _guard_dispatch_icall_nop
- `0x14360` _guard_xfg_dispatch_icall_nop
- `0x148a0` wake_writer_or_readers
- `0x1521a` fin$1
- `0x18f24` WHITESPACE_MAP
- `0x1a9d8` CURRENT
- `0x1a9e0` ID

Only GHIRUST:

- `0x1690` FUN_180001690
- `0x1837` FUN_180001837
- `0x1917` FUN_180001917
- `0x19b7` FUN_1800019b7
- `0x22a7` FUN_1800022a7
- `0x2352` FUN_180002352
- `0x238e` FUN_18000238e
- `0x2624` FUN_180002624
- `0x26c0` FUN_1800026c0
- `0x2796` FUN_180002796
- `0x2867` FUN_180002867
- `0x2dc8` FUN_180002dc8
- `0x3aae` FUN_180003aae
- `0x3b1d` FUN_180003b1d
- `0x3eb7` FUN_180003eb7
- `0x3ec0` FUN_180003ec0
- `0x41e0` FUN_1800041e0
- `0x4358` FUN_180004358
- `0x4489` FUN_180004489
- `0x4624` FUN_180004624
- `0x48d0` FUN_1800048d0
- `0x5047` FUN_180005047
- `0x509d` FUN_18000509d
- `0x548e` FUN_18000548e
- `0x54de` FUN_1800054de
- `0x5b20` FUN_180005b20
- `0x5f9b` FUN_180005f9b
- `0x5f9c` FUN_180005f9c
- `0x61e0` FUN_1800061e0
- `0x654a` FUN_18000654a
- `0x65a8` FUN_1800065a8
- `0x6642` FUN_180006642
- `0x6993` FUN_180006993
- `0x6a30` FUN_180006a30
- `0x6b60` FUN_180006b60
- `0x6e2b` FUN_180006e2b
- `0x6ea9` FUN_180006ea9
- `0x6ecc` FUN_180006ecc
- `0x6f8f` FUN_180006f8f
- `0x705c` FUN_18000705c
- `0x70c9` FUN_1800070c9
- `0x7222` FUN_180007222
- `0x7288` FUN_180007288
- `0x7400` FUN_180007400
- `0x7452` FUN_180007452
- `0x75d5` FUN_1800075d5
- `0x75ee` FUN_1800075ee
- `0x767c` FUN_18000767c
- `0x7759` FUN_180007759
- `0x77d8` FUN_1800077d8
- `0x7899` FUN_180007899
- `0x78bf` FUN_1800078bf
- `0x7919` FUN_180007919
- `0x793c` FUN_18000793c
- `0x79ac` FUN_1800079ac
- `0x7b1d` FUN_180007b1d
- `0x7b58` FUN_180007b58
- `0x7bd5` FUN_180007bd5
- `0x7c7a` FUN_180007c7a
- `0x7cba` FUN_180007cba
- `0x7d81` FUN_180007d81
- `0x7fae` FUN_180007fae
- `0x7fdf` FUN_180007fdf
- `0x8408` FUN_180008408
- `0x85d6` FUN_1800085d6
- `0x882a` FUN_18000882a
- `0x885d` FUN_18000885d
- `0x88c6` FUN_1800088c6
- `0x89f7` FUN_1800089f7
- `0x8b90` FUN_180008b90
- `0x8d13` FUN_180008d13
- `0x8d49` FUN_180008d49
- `0x8d90` FUN_180008d90
- `0x8e10` FUN_180008e10
- `0x8e3b` FUN_180008e3b
- `0x8e70` FUN_180008e70
- `0x905f` FUN_18000905f
- `0x9070` FUN_180009070
- `0x90d0` FUN_1800090d0
- `0x91cf` FUN_1800091cf
- `0x91e0` FUN_1800091e0
- `0xbecb` FUN_18000becb
- `0xbf62` FUN_18000bf62
- `0xbfba` FUN_18000bfba
- `0xc060` FUN_18000c060
- `0xc0f7` FUN_18000c0f7
- `0xc143` FUN_18000c143
- `0xc373` FUN_18000c373
- `0xc460` FUN_18000c460
- `0xc5a0` FUN_18000c5a0
- `0xc646` FUN_18000c646
- `0xc707` FUN_18000c707
- `0xc7eb` FUN_18000c7eb
- `0xc818` FUN_18000c818
- `0xc868` FUN_18000c868
- `0xc875` FUN_18000c875
- `0xdc4f` FUN_18000dc4f
- `0xdddf` FUN_18000dddf
- `0xeaa9` FUN_18000eaa9
- `0xeb66` FUN_18000eb66
- `0xec70` FUN_18000ec70
- `0xeeb2` FUN_18000eeb2
- `0xf1a2` FUN_18000f1a2
- `0xf210` FUN_18000f210
- `0xf38e` FUN_18000f38e
- `0xf3fc` FUN_18000f3fc
- `0xf4f9` FUN_18000f4f9
- `0xf51c` FUN_18000f51c
- `0xf6e2` FUN_18000f6e2
- `0xfe91` FUN_18000fe91
- `0xff86` FUN_18000ff86
- `0x103a0` FUN_1800103a0
- `0x106d6` FUN_1800106d6
- `0x10a30` FUN_180010a30
- `0x10ac0` FUN_180010ac0
- `0x10b50` FUN_180010b50
- `0x10c10` FUN_180010c10
- `0x10fb0` FUN_180010fb0
- `0x116d4` FUN_1800116d4
- `0x117b0` FUN_1800117b0
- `0x11af2` FUN_180011af2
- `0x11be6` FUN_180011be6
- `0x11c50` FUN_180011c50
- `0x124ac` FUN_1800124ac
- `0x12540` FUN_180012540
- `0x125b0` FUN_1800125b0
- `0x127c1` FUN_1800127c1
- `0x127ef` FUN_1800127ef
- `0x128bd` FUN_1800128bd
- `0x12b70` FUN_180012b70
- `0x12c90` FUN_180012c90
- `0x12d64` FUN_180012d64
- `0x12df1` FUN_180012df1
- `0x12e1f` FUN_180012e1f
- `0x13170` FUN_180013170
- `0x1338f` FUN_18001338f
- `0x134e0` FUN_1800134e0
- `0x13976` FUN_180013976
- `0x13d0c` FUN_180013d0c
- `0x14490` FUN_180014490
- `0x14740` FUN_180014740

## Disassembly and CFG (matched functions only)

- Instruction addresses (matched functions): GHIRUST 18357 · common with Ghidra 18112 · Ghidra 21137
- Instructions only in GHIRUST: 245 · only in Ghidra: 3025
- Mnemonics agreeing on common addresses: 16242/18112
- CFG edges: GHIRUST 4970 · common with Ghidra 4826 · Ghidra 6207

| Function | Name match | GHIDRA insn | Common insn | Only GHIRUST | Mnemonic agree | GHIDRA blocks | Common blocks | GHIDRA edges | Common edges | Lexical sim |
|---|---|---|---|---|---|---|---|---|---|---|
| 0x1000 .text | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.0965 |
| 0x1010 features_add | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.25 |
| 0x1020 features_array_sum | yes | 42 | 42 | 0 | 36/42 | 11 | 11 | 15 | 15 | 0.3251 |
| 0x10c0 features_call_internal | yes | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.296 |
| 0x10e0 features_classify | yes | 11 | 11 | 0 | 10/11 | 5 | 5 | 4 | 4 | 0.304 |
| 0x1100 features_counter_run | yes | 50 | 50 | 0 | 45/50 | 10 | 10 | 13 | 13 | 0.2469 |
| 0x11d0 features_div | yes | 17 | 17 | 0 | 15/17 | 5 | 5 | 4 | 4 | 0.3423 |
| 0x1200 features_export_marker | yes | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.3453 |
| 0x1210 features_fib | yes | 20 | 20 | 0 | 19/20 | 4 | 4 | 6 | 5 | 0.2988 |
| 0x1240 features_float_loop | yes | 74 | 74 | 0 | 69/74 | 10 | 10 | 13 | 13 | 0.2488 |
| 0x1370 features_for_loop | yes | 16 | 16 | 0 | 14/16 | 4 | 4 | 5 | 5 | 0.2106 |
| 0x13b0 features_many_args | yes | 11 | 11 | 0 | 11/11 | 1 | 1 | 0 | 0 | 0.2456 |
| 0x13e0 features_memzero | yes | 8 | 8 | 0 | 6/8 | 4 | 4 | 4 | 4 | 0.2771 |
| 0x1400 features_mul | yes | 3 | 3 | 0 | 3/3 | 1 | 1 | 0 | 0 | 0.2735 |
| 0x1410 features_pointer_swap | yes | 9 | 9 | 0 | 7/9 | 4 | 4 | 5 | 5 | 0.2932 |
| 0x1430 features_reverse_in_place | yes | 30 | 30 | 2 | 24/30 | 8 | 8 | 9 | 9 | 0.2931 |
| 0x14c0 features_string_length | yes | 4 | 4 | 1 | 3/4 | 2 | 2 | 1 | 1 | 0.2595 |
| 0x14d0 features_struct_area | yes | 8 | 8 | 0 | 7/8 | 3 | 3 | 2 | 2 | 0.2981 |
| 0x14f0 features_struct_by_value | yes | 4 | 4 | 0 | 4/4 | 1 | 1 | 0 | 0 | 0.3556 |
| 0x1500 features_sub | yes | 3 | 3 | 0 | 3/3 | 1 | 1 | 0 | 0 | 0.25 |
| 0x1510 features_sum_loop | yes | 47 | 47 | 0 | 40/47 | 10 | 10 | 14 | 14 | 0.2749 |
| 0x15d0 features_tagged_area | yes | 18 | 18 | 0 | 15/18 | 7 | 7 | 6 | 6 | 0.3428 |
| 0x1600 __rust_alloc | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.0471 |
| 0x1610 __rust_dealloc | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.1149 |
| 0x1620 __rust_realloc | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.0883 |
| 0x1630 __rust_no_alloc_shim_is_unstable_v2 | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.3125 |
| 0x1640 __rust_start_panic | no | 4 | 4 | 1 | 4/4 | 1 | 1 | 0 | 0 | 0.204 |
| 0x1660 extend_desugared<u16,alloc::alloc::Global,std::os::windows::ffi::EncodeWide> | no | 104 | 16 | 0 | 16/16 | 17 | 1 | 25 | 0 | 0.0569 |
| 0x17e0 drop_glue<enum2$<core::result::Result<tuple$<>,core::io::error::Error>_>_> | no | 22 | 22 | 0 | 19/22 | 5 | 5 | 7 | 7 | 0.2342 |
| 0x1840 drop_glue<alloc::sync::Arc<std::sync::poison::mutex::Mutex<alloc::vec::Vec<u8,alloc::alloc::Global>_>,alloc::alloc::Global>_> | no | 5 | 5 | 0 | 3/5 | 3 | 3 | 2 | 2 | 0.1402 |
| 0x1850 drop_glue<std::sync::poison::mutex::MutexGuard<alloc::vec::Vec<u8,alloc::alloc::Global>_>_> | no | 29 | 29 | 0 | 25/29 | 7 | 7 | 9 | 9 | 0.2028 |
| 0x18a0 drop_glue<std::sync::nonpoison::rwlock::RwLockReadGuard<enum2$<std::panicking::Hook>_>_> | no | 8 | 8 | 51 | 7/8 | 2 | 2 | 1 | 1 | 0.2322 |
| 0x18c0 drop_glue<std::io::default_write_fmt::Adapter<alloc::vec::Vec<u8,alloc::alloc::Global>_>_> | no | 22 | 22 | 0 | 19/22 | 5 | 5 | 7 | 7 | 0.2459 |
| 0x1920 drop_glue<core::io::error::Error> | no | 20 | 20 | 0 | 18/20 | 4 | 4 | 5 | 5 | 0.2812 |
| 0x1960 <std[2a1f8e54e2930f4]::alloc::rust_oom::{closure#0},!> | no | 4 | 4 | 1 | 4/4 | 1 | 1 | 0 | 0 | 0.1235 |
| 0x1980 <std[2a1f8e54e2930f4]::panicking::panic_handler::{closure#0},!> | no | 4 | 4 | 1 | 4/4 | 1 | 1 | 0 | 0 | 0.1235 |
| 0x19c0 closure$0<std::panicking::default_hook::closure$0::closure_env$0,tuple$<>_> | no | 191 | 191 | 4 | 167/191 | 38 | 36 | 54 | 50 | 0.2318 |
| 0x1d30 Unwind@180001d30 | no | 24 | 24 | 0 | 24/24 | 1 | 1 | 0 | 0 | 0.0725 |
| 0x1d70 closure$0 | no | 175 | 175 | 0 | 158/175 | 31 | 27 | 45 | 36 | 0.1659 |
| 0x2010 Unwind@180002010 | no | 19 | 19 | 0 | 19/19 | 1 | 1 | 0 | 0 | 0.3214 |
| 0x2040 closure$0 | no | 14 | 13 | 0 | 12/13 | 1 | 1 | 0 | 0 | 0.2075 |
| 0x2075 closure$0 | no | 95 | 95 | 0 | 91/95 | 12 | 11 | 16 | 14 | 0.1514 |
| 0x21f0 closure$0 | no | 30 | 30 | 3 | 29/30 | 4 | 3 | 3 | 2 | 0.3263 |
| 0x2280 Unwind@180002280 | no | 14 | 14 | 0 | 14/14 | 3 | 3 | 3 | 3 | 0.1976 |
| 0x22e0 call_once<std::sys::backtrace::_print_fmt::closure_env$0,tuple$<ref_mut$<core::fmt::Formatter>,enum2$<std::backtrace_rs::types::BytesOrWideString>_>_> | no | 35 | 35 | 0 | 34/35 | 5 | 3 | 5 | 1 | 0.1423 |
| 0x2360 Unwind@180002360 | no | 17 | 17 | 0 | 17/17 | 3 | 3 | 3 | 3 | 0.254 |
| 0x23a0 rust_panic | no | 4 | 4 | 15 | 4/4 | 1 | 1 | 0 | 0 | 0.1954 |
| 0x2400 __rdl_alloc | no | 35 | 35 | 0 | 33/35 | 5 | 5 | 5 | 5 | 0.2794 |
| 0x2460 __rust_abort | no | 3 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2416 |
| 0x2470 __rdl_dealloc | no | 16 | 16 | 0 | 15/16 | 3 | 3 | 3 | 3 | 0.1957 |
| 0x24b0 __rdl_realloc | no | 61 | 61 | 0 | 58/61 | 5 | 5 | 5 | 5 | 0.2263 |
| 0x2560 rust_begin_unwind | no | 8 | 8 | 1 | 8/8 | 1 | 1 | 0 | 0 | 0.1242 |
| 0x2580 __rust_alloc_error_handler | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.2029 |
| 0x25a0 is_absolute | no | 98 | 54 | 0 | 48/54 | 27 | 11 | 42 | 15 | 0.1609 |
| 0x26f0 _strip_prefix | no | 259 | 209 | 0 | 196/209 | 41 | 23 | 59 | 31 | 0.1642 |
| 0x2b70 lock<alloc::vec::Vec<u8,alloc::alloc::Global>_> | no | 43 | 43 | 0 | 38/43 | 6 | 6 | 8 | 8 | 0.186 |
| 0x2c00 synchronous_write | no | 75 | 74 | 0 | 69/74 | 8 | 8 | 9 | 9 | 0.1823 |
| 0x2d20 include_cur_dir | no | 53 | 53 | 0 | 40/53 | 14 | 14 | 19 | 19 | 0.0 |
| 0x2e40 parse_next_component_back | no | 140 | 117 | 2 | 104/117 | 36 | 29 | 53 | 39 | 0.2575 |
| 0x3020 as_path | no | 219 | 209 | 2 | 180/209 | 61 | 54 | 96 | 82 | 0.212 |
| 0x3360 print_raw_with_column | no | 229 | 229 | 0 | 205/229 | 31 | 31 | 53 | 53 | 0.1906 |
| 0x3700 drop_slow | no | 26 | 26 | 0 | 22/26 | 6 | 6 | 7 | 7 | 0.2517 |
| 0x3760 drop_slow | no | 30 | 30 | 0 | 25/30 | 7 | 7 | 9 | 9 | 0.2384 |
| 0x37c0 current_dir | no | 148 | 148 | 4 | 134/148 | 24 | 24 | 34 | 34 | 0.1715 |
| 0x3a70 Unwind@180003a70 | no | 29 | 29 | 0 | 28/29 | 3 | 3 | 3 | 3 | 0.255 |
| 0x3c50 rust_oom | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.1511 |
| 0x3c70 get_backtrace_style | no | 63 | 63 | 0 | 51/63 | 16 | 16 | 25 | 25 | 0.27 |
| 0x3d3d default_hook | no | 85 | 85 | 0 | 78/85 | 13 | 10 | 18 | 13 | 0.2038 |
| 0x3e70 Unwind@180003e70 | no | 17 | 17 | 0 | 17/17 | 1 | 1 | 0 | 0 | 0.1214 |
| 0x3ed0 payload_as_str | no | 37 | 37 | 0 | 35/37 | 6 | 6 | 7 | 7 | 0.0964 |
| 0x3f54 panic_with_hook | no | 132 | 130 | 1 | 122/130 | 15 | 14 | 18 | 16 | 0.14 |
| 0x4190 enum_loaded_modules_callback | no | 141 | 141 | 2 | 125/141 | 33 | 32 | 49 | 47 | 0.2049 |
| 0x4390 Catch_All@180004390 | no | 12 | 12 | 1 | 12/12 | 1 | 1 | 0 | 0 | 0.2302 |
| 0x43b0 try_set_output_capture | no | 49 | 49 | 0 | 42/49 | 11 | 10 | 13 | 10 | 0.1544 |
| 0x4460 Unwind@180004460 | no | 15 | 15 | 0 | 12/15 | 4 | 4 | 5 | 5 | 0.221 |
| 0x4490 output_filename | no | 98 | 98 | 0 | 89/98 | 14 | 13 | 20 | 18 | 0.1851 |
| 0x45f0 Unwind@1800045f0 | no | 24 | 24 | 0 | 24/24 | 3 | 3 | 3 | 3 | 0.2138 |
| 0x4630 lock | no | 27 | 27 | 0 | 23/27 | 6 | 6 | 8 | 8 | 0.1635 |
| 0x46a0 increase | no | 15 | 15 | 0 | 13/15 | 5 | 5 | 5 | 5 | 0.2366 |
| 0x46e0 resolve_with_inline | no | 220 | 124 | 0 | 108/124 | 33 | 22 | 53 | 36 | 0.1187 |
| 0x4b10 resolve | no | 302 | 302 | 3 | 267/302 | 66 | 59 | 96 | 82 | 0.2252 |
| 0x5010 Unwind@180005010 | no | 29 | 29 | 0 | 28/29 | 3 | 3 | 3 | 3 | 0.2345 |
| 0x5060 Unwind@180005060 | no | 33 | 33 | 0 | 31/33 | 4 | 4 | 5 | 5 | 0.2566 |
| 0x50c0 Unwind@1800050c0 | no | 24 | 24 | 0 | 24/24 | 1 | 1 | 0 | 0 | 0.1533 |
| 0x5100 getenv | no | 191 | 191 | 4 | 169/191 | 40 | 38 | 58 | 54 | 0.2006 |
| 0x5450 Unwind@180005450 | no | 29 | 29 | 0 | 28/29 | 3 | 3 | 3 | 3 | 0.255 |
| 0x54a0 Unwind@1800054a0 | no | 29 | 29 | 0 | 28/29 | 3 | 3 | 3 | 3 | 0.255 |
| 0x54f0 parse_prefix | no | 317 | 317 | 0 | 257/317 | 87 | 87 | 137 | 137 | 0.4244 |
| 0x5920 process_heap_alloc | no | 24 | 24 | 0 | 23/24 | 3 | 3 | 2 | 2 | 0.2226 |
| 0x5960 write_valid_utf8_to_console | no | 150 | 132 | 4 | 122/132 | 31 | 27 | 43 | 36 | 0.1935 |
| 0x5c00 write | no | 202 | 202 | 6 | 183/202 | 42 | 41 | 57 | 55 | 0.1904 |
| 0x5f50 Unwind@180005f50 | no | 18 | 18 | 0 | 18/18 | 1 | 1 | 0 | 0 | 0.1533 |
| 0x5fc0 enable | no | 105 | 102 | 0 | 86/102 | 19 | 17 | 25 | 23 | 0.1944 |
| 0x6170 Unwind@180006170 | no | 12 | 12 | 0 | 11/12 | 1 | 1 | 0 | 0 | 0.2719 |
| 0x6190 cleanup | no | 68 | 68 | 2 | 60/68 | 13 | 13 | 18 | 18 | 0.2049 |
| 0x62c0 Catch_All@1800062c0 | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.2302 |
| 0x62e0 error_string | no | 113 | 113 | 3 | 104/113 | 22 | 22 | 30 | 30 | 0.178 |
| 0x6510 Unwind@180006510 | no | 22 | 22 | 0 | 21/22 | 3 | 3 | 3 | 3 | 0.255 |
| 0x6750 inner | no | 146 | 146 | 1 | 118/146 | 40 | 38 | 66 | 61 | 0.171 |
| 0x6960 Unwind@180006960 | no | 27 | 27 | 0 | 26/27 | 3 | 3 | 3 | 3 | 0.255 |
| 0x69d0 fmt | no | 208 | 99 | 0 | 95/99 | 33 | 10 | 50 | 11 | 0.1105 |
| 0x6df0 Unwind@180006df0 | no | 28 | 28 | 0 | 28/28 | 3 | 3 | 3 | 3 | 0.1976 |
| 0x6e40 Unwind@180006e40 | no | 23 | 23 | 0 | 23/23 | 1 | 1 | 0 | 0 | 0.2743 |
| 0x6e80 write_str<alloc::vec::Vec<u8,alloc::alloc::Global>_> | no | 40 | 40 | 0 | 39/40 | 5 | 5 | 6 | 6 | 0.2213 |
| 0x6f00 write_str<core::io::cursor::Cursor<ref_mut$<slice2$<u8>_>_>_> | no | 60 | 60 | 0 | 53/60 | 9 | 8 | 12 | 10 | 0.2096 |
| 0x6fc0 Unwind@180006fc0 | no | 22 | 22 | 0 | 22/22 | 1 | 1 | 0 | 0 | 0.2147 |
| 0x7000 write_str<std::sys::stdio::windows::Stderr> | no | 37 | 37 | 0 | 32/37 | 9 | 8 | 12 | 10 | 0.273 |
| 0x7080 Unwind@180007080 | no | 12 | 12 | 0 | 12/12 | 1 | 1 | 0 | 0 | 0.2423 |
| 0x70f0 eq | no | 45 | 45 | 0 | 37/45 | 10 | 10 | 14 | 14 | 0.0 |
| 0x71e0 take_box | no | 24 | 24 | 1 | 23/24 | 3 | 3 | 2 | 2 | 0.2025 |
| 0x7240 fmt<enum2$<core::option::Option<u8>_>_> | no | 26 | 26 | 0 | 25/26 | 3 | 3 | 2 | 2 | 0.1329 |
| 0x7310 fmt<core::panic::location::Location> | no | 26 | 26 | 0 | 26/26 | 1 | 1 | 0 | 0 | 0.2065 |
| 0x73c0 fmt | no | 78 | 78 | 1 | 70/78 | 15 | 15 | 20 | 20 | 0.1873 |
| 0x74e0 fmt | no | 16 | 16 | 0 | 16/16 | 1 | 1 | 0 | 0 | 0.1003 |
| 0x7520 fmt | no | 26 | 26 | 0 | 26/26 | 1 | 1 | 0 | 0 | 0.0976 |
| 0x75a0 write_vectored<alloc::alloc::Global> | no | 108 | 80 | 0 | 75/80 | 19 | 12 | 27 | 17 | 0.2736 |
| 0x7710 is_write_vectored<alloc::alloc::Global> | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1412 |
| 0x7720 write_all_vectored<alloc::alloc::Global> | no | 106 | 78 | 0 | 73/78 | 18 | 12 | 26 | 17 | 0.2736 |
| 0x7870 write<alloc::alloc::Global> | no | 41 | 41 | 0 | 40/41 | 5 | 5 | 6 | 6 | 0.2364 |
| 0x78f0 write_all<alloc::alloc::Global> | no | 40 | 40 | 0 | 39/40 | 5 | 5 | 6 | 6 | 0.2364 |
| 0x7970 write_char | no | 78 | 78 | 0 | 73/78 | 13 | 13 | 19 | 19 | 0.3467 |
| 0x7ab0 get | no | 32 | 32 | 0 | 31/32 | 5 | 3 | 5 | 2 | 0.2069 |
| 0x7b30 Unwind@180007b30 | no | 16 | 16 | 0 | 15/16 | 3 | 3 | 3 | 3 | 0.256 |
| 0x7b60 take_box | no | 56 | 56 | 2 | 54/56 | 6 | 5 | 6 | 4 | 0.2034 |
| 0x7c50 Unwind@180007c50 | no | 20 | 20 | 0 | 19/20 | 3 | 3 | 3 | 3 | 0.256 |
| 0x7c90 Unwind@180007c90 | no | 20 | 20 | 0 | 19/20 | 3 | 3 | 3 | 3 | 0.255 |
| 0x7cd0 next | no | 208 | 60 | 0 | 56/60 | 46 | 3 | 67 | 3 | 0.0 |
| 0x80d0 is_contained_in | no | 465 | 388 | 3 | 341/388 | 110 | 87 | 170 | 134 | 0.1192 |
| 0x87e0 write_fmt<alloc::vec::Vec<u8,alloc::alloc::Global>_> | no | 43 | 43 | 2 | 38/43 | 11 | 9 | 13 | 9 | 0.1833 |
| 0x8880 Unwind@180008880 | no | 10 | 10 | 0 | 10/10 | 1 | 1 | 0 | 0 | 0.0725 |
| 0x88a0 write_char<std::io::default_write_fmt::Adapter<alloc::vec::Vec<u8,alloc::alloc::Global>_>_> | no | 73 | 73 | 0 | 71/73 | 10 | 10 | 13 | 13 | 0.2374 |
| 0x89c0 write_char<std::io::default_write_fmt::Adapter<core::io::cursor::Cursor<ref_mut$<slice2$<u8>_>_>_>_> | no | 99 | 99 | 0 | 90/99 | 16 | 15 | 22 | 20 | 0.2215 |
| 0x8b00 Unwind@180008b00 | no | 22 | 22 | 0 | 22/22 | 1 | 1 | 0 | 0 | 0.2138 |
| 0x8b60 write_char<std::io::default_write_fmt::Adapter<std::sys::stdio::windows::Stderr>_> | no | 77 | 77 | 0 | 70/77 | 16 | 15 | 22 | 20 | 0.2571 |
| 0x8c70 Unwind@180008c70 | no | 12 | 12 | 0 | 12/12 | 1 | 1 | 0 | 0 | 0.2423 |
| 0x8cc0 call_once<std::io::error::impl$0::from_raw_os_error::FUNCTIONS::closure_env$0,tuple$<i32,ref_mut$<core::fmt::Formatter>_>_> | no | 29 | 29 | 0 | 28/29 | 5 | 3 | 5 | 1 | 0.1255 |
| 0x8d20 Unwind@180008d20 | no | 18 | 18 | 0 | 17/18 | 3 | 3 | 3 | 3 | 0.256 |
| 0x8dd0 write_all_vectored<std::sys::stdio::windows::Stderr> | no | 163 | 43 | 1 | 39/43 | 45 | 10 | 62 | 13 | 0.175 |
| 0x9040 Unwind@180009040 | no | 26 | 26 | 0 | 25/26 | 3 | 3 | 3 | 3 | 0.2482 |
| 0x9080 write_all<std::sys::stdio::windows::Stderr> | no | 89 | 18 | 0 | 18/18 | 20 | 1 | 29 | 1 | 0.0725 |
| 0x91b0 Unwind@1800091b0 | no | 26 | 26 | 0 | 25/26 | 3 | 3 | 3 | 3 | 0.2482 |
| 0x91f0 write_fmt<std::sys::stdio::windows::Stderr> | no | 43 | 43 | 2 | 38/43 | 11 | 9 | 13 | 9 | 0.1874 |
| 0x9290 Unwind@180009290 | no | 10 | 10 | 0 | 10/10 | 1 | 1 | 0 | 0 | 0.0725 |
| 0x92b0 <&str> | no | 40 | 40 | 0 | 38/40 | 6 | 6 | 7 | 7 | 0.2488 |
| 0x9328 FUN_180009328 | yes | 72 | 72 | 0 | 65/72 | 11 | 11 | 15 | 15 | 0.2001 |
| 0x940e FUN_18000940e | yes | 72 | 72 | 0 | 65/72 | 11 | 11 | 15 | 15 | 0.2077 |
| 0x94f4 FUN_1800094f4 | yes | 67 | 67 | 0 | 60/67 | 11 | 11 | 15 | 15 | 0.2084 |
| 0x95d2 FUN_1800095d2 | yes | 51 | 51 | 0 | 43/51 | 14 | 14 | 21 | 21 | 0.2476 |
| 0x965e FUN_18000965e | yes | 55 | 55 | 0 | 47/55 | 15 | 15 | 22 | 22 | 0.2463 |
| 0x96f2 FUN_1800096f2 | yes | 132 | 132 | 0 | 109/132 | 31 | 31 | 51 | 51 | 0.2424 |
| 0x98c9 FUN_1800098c9 | yes | 54 | 54 | 0 | 46/54 | 15 | 15 | 22 | 22 | 0.2527 |
| 0x995b FUN_18000995b | yes | 169 | 169 | 0 | 136/169 | 46 | 46 | 77 | 77 | 0.2471 |
| 0x9bb0 FUN_180009bb0 | yes | 97 | 97 | 0 | 81/97 | 25 | 25 | 39 | 39 | 0.291 |
| 0x9ce9 FUN_180009ce9 | yes | 25 | 25 | 1 | 24/25 | 3 | 3 | 2 | 2 | 0.3218 |
| 0x9d45 FUN_180009d45 | yes | 77 | 77 | 0 | 70/77 | 17 | 17 | 23 | 23 | 0.2492 |
| 0x9e22 FUN_180009e22 | yes | 114 | 114 | 0 | 98/114 | 24 | 24 | 36 | 36 | 0.2729 |
| 0x9f8c FUN_180009f8c | yes | 111 | 111 | 0 | 95/111 | 23 | 23 | 36 | 36 | 0.2756 |
| 0xa0f7 FUN_18000a0f7 | yes | 250 | 250 | 1 | 206/250 | 61 | 61 | 100 | 100 | 0.214 |
| 0xa47f try_demangle | no | 27 | 27 | 0 | 26/27 | 4 | 4 | 4 | 4 | 0.1647 |
| 0xa4d3 demangle | no | 702 | 702 | 3 | 624/702 | 197 | 197 | 293 | 293 | 0.2997 |
| 0xaef0 FUN_18000aef0 | yes | 32 | 32 | 0 | 24/32 | 6 | 6 | 8 | 8 | 0.2271 |
| 0xaf71 FUN_18000af71 | yes | 152 | 152 | 0 | 130/152 | 34 | 34 | 53 | 53 | 0.3686 |
| 0xb173 FUN_18000b173 | yes | 78 | 78 | 1 | 73/78 | 17 | 17 | 22 | 22 | 0.3125 |
| 0xb285 FUN_18000b285 | yes | 56 | 56 | 0 | 47/56 | 19 | 19 | 28 | 28 | 0.2546 |
| 0xb327 FUN_18000b327 | yes | 62 | 62 | 1 | 55/62 | 13 | 13 | 19 | 19 | 0.2693 |
| 0xb3e7 FUN_18000b3e7 | yes | 40 | 40 | 0 | 36/40 | 11 | 11 | 14 | 14 | 0.3237 |
| 0xb45b FUN_18000b45b | yes | 148 | 148 | 1 | 126/148 | 49 | 49 | 76 | 76 | 0.226 |
| 0xb63e FUN_18000b63e | yes | 43 | 43 | 0 | 41/43 | 9 | 9 | 11 | 11 | 0.2524 |
| 0xb6b7 FUN_18000b6b7 | yes | 438 | 438 | 0 | 349/438 | 111 | 111 | 197 | 194 | 0.289 |
| 0xbda1 FUN_18000bda1 | yes | 326 | 88 | 0 | 79/88 | 85 | 20 | 155 | 25 | 0.158 |
| 0xc293 FUN_18000c293 | yes | 422 | 132 | 0 | 112/132 | 113 | 31 | 204 | 44 | 0.1648 |
| 0xc913 FUN_18000c913 | yes | 105 | 105 | 1 | 92/105 | 20 | 20 | 29 | 29 | 0.2661 |
| 0xca6c FUN_18000ca6c | yes | 160 | 160 | 1 | 141/160 | 33 | 33 | 48 | 48 | 0.2726 |
| 0xccaf FUN_18000ccaf | yes | 74 | 74 | 0 | 67/74 | 14 | 14 | 19 | 19 | 0.2644 |
| 0xcd92 FUN_18000cd92 | yes | 95 | 95 | 0 | 83/95 | 19 | 19 | 30 | 29 | 0.2412 |
| 0xced4 FUN_18000ced4 | yes | 135 | 135 | 0 | 112/135 | 36 | 36 | 60 | 58 | 0.2856 |
| 0xd0ac FUN_18000d0ac | yes | 102 | 102 | 1 | 89/102 | 24 | 24 | 34 | 34 | 0.2646 |
| 0xd1e0 FUN_18000d1e0 | yes | 12 | 12 | 0 | 12/12 | 3 | 3 | 2 | 2 | 0.2484 |
| 0xd208 FUN_18000d208 | yes | 28 | 28 | 0 | 23/28 | 11 | 11 | 15 | 15 | 0.3454 |
| 0xd25b fmt | no | 793 | 787 | 3 | 682/787 | 219 | 216 | 341 | 337 | 0.288 |
| 0xddf6 FUN_18000ddf6 | yes | 4 | 4 | 41 | 3/4 | 2 | 2 | 1 | 1 | 0.2032 |
| 0xde08 FUN_18000de08 | yes | 191 | 191 | 3 | 173/191 | 33 | 33 | 49 | 49 | 0.3343 |
| 0xe0f4 write_str | no | 15 | 15 | 0 | 13/15 | 3 | 3 | 2 | 2 | 0.2205 |
| 0xe126 fmt | no | 277 | 277 | 1 | 252/277 | 58 | 58 | 88 | 88 | 0.2348 |
| 0xe55c fmt | no | 69 | 69 | 1 | 63/69 | 14 | 14 | 18 | 18 | 0.2335 |
| 0xe704 fmt | no | 22 | 22 | 0 | 21/22 | 3 | 3 | 2 | 2 | 0.1558 |
| 0xe79c fmt | no | 37 | 37 | 0 | 35/37 | 4 | 4 | 5 | 5 | 0.1936 |
| 0xe818 FUN_18000e818 | yes | 225 | 223 | 2 | 192/223 | 58 | 57 | 88 | 87 | 0.321 |
| 0xec00 from_utf16 | no | 162 | 43 | 1 | 41/43 | 32 | 5 | 45 | 5 | 0.1161 |
| 0xee80 Unwind@18000ee80 | no | 28 | 28 | 0 | 27/28 | 3 | 3 | 3 | 3 | 0.256 |
| 0xeed0 from_wide | no | 180 | 180 | 1 | 170/180 | 34 | 33 | 45 | 43 | 0.2665 |
| 0xf170 Unwind@18000f170 | no | 28 | 28 | 0 | 27/28 | 3 | 3 | 3 | 3 | 0.255 |
| 0xf1c0 format_inner | no | 118 | 57 | 2 | 54/57 | 23 | 7 | 30 | 6 | 0.2008 |
| 0xf360 Unwind@18000f360 | no | 24 | 24 | 0 | 23/24 | 3 | 3 | 3 | 3 | 0.255 |
| 0xf3c0 write_char | no | 76 | 76 | 0 | 71/76 | 13 | 13 | 19 | 19 | 0.3476 |
| 0xf4d0 write_str | no | 38 | 38 | 0 | 37/38 | 5 | 5 | 6 | 6 | 0.2297 |
| 0xf560 is_assigned | no | 34 | 34 | 0 | 26/34 | 6 | 6 | 7 | 7 | 0.1875 |
| 0xf5f0 escape_debug_ext | no | 158 | 131 | 0 | 117/131 | 31 | 20 | 51 | 29 | 0.1838 |
| 0xf840 field | no | 111 | 111 | 0 | 100/111 | 14 | 14 | 23 | 23 | 0.2225 |
| 0xf9d0 entry | no | 85 | 85 | 0 | 78/85 | 11 | 11 | 17 | 17 | 0.2204 |
| 0xfaf0 finish | no | 19 | 19 | 0 | 18/19 | 3 | 3 | 3 | 3 | 0.2206 |
| 0xfb30 debug_list | no | 21 | 21 | 0 | 21/21 | 1 | 1 | 0 | 0 | 0.2264 |
| 0xfb70 pad_integral | no | 342 | 272 | 0 | 253/272 | 47 | 28 | 72 | 41 | 0.1902 |
| 0x10050 debug_tuple_field1_finish | no | 95 | 95 | 0 | 85/95 | 13 | 13 | 22 | 22 | 0.2135 |
| 0x10190 debug_struct_field1_finish | no | 56 | 56 | 0 | 54/56 | 7 | 7 | 8 | 8 | 0.2024 |
| 0x10240 debug_struct_field2_finish | no | 69 | 69 | 0 | 67/69 | 7 | 7 | 8 | 8 | 0.2002 |
| 0x10330 pad | no | 297 | 215 | 0 | 201/215 | 50 | 24 | 73 | 35 | 0.1924 |
| 0x10770 write_str | no | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.2273 |
| 0x10790 _fmt_inner | no | 108 | 108 | 2 | 99/108 | 17 | 17 | 24 | 24 | 0.2321 |
| 0x10930 new | no | 364 | 117 | 2 | 108/117 | 73 | 19 | 106 | 23 | 0.2049 |
| 0x10eb0 pointer_fmt_inner | no | 44 | 44 | 0 | 41/44 | 7 | 7 | 9 | 9 | 0.4066 |
| 0x10f60 write | no | 137 | 39 | 0 | 37/39 | 33 | 5 | 49 | 6 | 0.2108 |
| 0x11120 slice_error_fail_rt | no | 252 | 252 | 10 | 230/252 | 59 | 59 | 84 | 84 | 0.3138 |
| 0x11520 do_count_chars | no | 381 | 107 | 0 | 99/107 | 47 | 16 | 72 | 23 | 0.1717 |
| 0x11c00 from_utf8 | no | 144 | 23 | 0 | 21/23 | 54 | 3 | 88 | 4 | 0.1486 |
| 0x11e10 memchr_aligned | no | 68 | 68 | 0 | 59/68 | 18 | 18 | 27 | 27 | 0.3719 |
| 0x11f00 get_os_functions | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2042 |
| 0x11f10 lookup | no | 32 | 32 | 0 | 24/32 | 10 | 10 | 11 | 11 | 0.3206 |
| 0x11f70 lookup_slow | no | 68 | 68 | 0 | 63/68 | 8 | 8 | 12 | 12 | 0.316 |
| 0x12070 lookup_slow | no | 74 | 74 | 0 | 68/74 | 9 | 9 | 14 | 14 | 0.3057 |
| 0x12180 lookup_slow | no | 58 | 58 | 0 | 53/58 | 8 | 8 | 12 | 12 | 0.2901 |
| 0x12260 lookup_slow | no | 65 | 65 | 0 | 59/65 | 9 | 9 | 14 | 14 | 0.2778 |
| 0x12350 write_prefix | no | 41 | 41 | 0 | 38/41 | 6 | 6 | 7 | 7 | 0.2706 |
| 0x123b0 fmt | no | 46 | 46 | 0 | 42/46 | 5 | 5 | 6 | 6 | 0.2502 |
| 0x12460 write_char | no | 40 | 40 | 0 | 37/40 | 4 | 4 | 4 | 4 | 0.2228 |
| 0x124d0 write_str | no | 171 | 27 | 0 | 27/27 | 41 | 1 | 63 | 1 | 0.1233 |
| 0x12760 fmt<usize> | no | 66 | 66 | 0 | 62/66 | 10 | 10 | 13 | 13 | 0.3021 |
| 0x12880 fmt | no | 140 | 53 | 0 | 51/53 | 26 | 5 | 36 | 1 | 0.1719 |
| 0x12a40 fmt | no | 28 | 28 | 0 | 27/28 | 3 | 3 | 3 | 3 | 0.3088 |
| 0x12ad0 fmt | no | 28 | 28 | 0 | 27/28 | 3 | 3 | 3 | 3 | 0.3088 |
| 0x12b40 fmt | no | 72 | 72 | 0 | 69/72 | 9 | 9 | 13 | 13 | 0.2064 |
| 0x12c50 fmt | no | 79 | 79 | 0 | 76/79 | 11 | 11 | 16 | 16 | 0.2089 |
| 0x12d80 fmt<usize> | no | 136 | 136 | 0 | 125/136 | 22 | 22 | 32 | 32 | 0.267 |
| 0x12f90 write_char | no | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.2273 |
| 0x12fb0 drop | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1895 |
| 0x12fc0 fmt | no | 27 | 27 | 0 | 27/27 | 1 | 1 | 0 | 0 | 0.0864 |
| 0x13020 fmt | no | 28 | 28 | 0 | 27/28 | 3 | 3 | 3 | 3 | 0.3166 |
| 0x13090 fmt | no | 28 | 28 | 0 | 27/28 | 3 | 3 | 3 | 3 | 0.3166 |
| 0x13100 fmt | no | 237 | 62 | 0 | 59/62 | 53 | 6 | 83 | 6 | 0.1418 |
| 0x13460 fmt | no | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.1196 |
| 0x13480 fmt | no | 54 | 54 | 0 | 50/54 | 7 | 7 | 10 | 10 | 0.2317 |
| 0x13520 fmt | no | 60 | 60 | 0 | 57/60 | 10 | 10 | 12 | 12 | 0.2869 |
| 0x13640 dllmain_crt_dispatch | no | 27 | 27 | 0 | 22/27 | 9 | 9 | 8 | 8 | 0.1487 |
| 0x136a0 dllmain_crt_process_attach | no | 71 | 71 | 2 | 63/71 | 13 | 13 | 18 | 18 | 0.1878 |
| 0x137b0 dllmain_crt_process_detach | no | 37 | 37 | 3 | 36/37 | 5 | 5 | 4 | 4 | 0.2216 |
| 0x13850 dllmain_dispatch | no | 98 | 91 | 0 | 79/91 | 22 | 21 | 33 | 33 | 0.1566 |
| 0x13990 _DllMainCRTStartup | no | 18 | 18 | 0 | 17/18 | 3 | 3 | 3 | 3 | 0.1475 |
| 0x139e0 __chkstk | no | 19 | 19 | 0 | 16/19 | 4 | 4 | 5 | 5 | 0.3367 |
| 0x13a30 __scrt_acquire_startup_lock | no | 20 | 20 | 0 | 14/20 | 6 | 6 | 8 | 8 | 0.2137 |
| 0x13a80 __scrt_dllmain_after_initialize_c | no | 20 | 20 | 0 | 18/20 | 5 | 5 | 4 | 4 | 0.1607 |
| 0x13ac0 __scrt_dllmain_before_initialize_c | no | 26 | 26 | 0 | 22/26 | 8 | 8 | 10 | 10 | 0.2353 |
| 0x13b40 __scrt_dllmain_crt_thread_attach | no | 14 | 14 | 0 | 12/14 | 5 | 5 | 5 | 5 | 0.1915 |
| 0x13b70 __scrt_dllmain_crt_thread_detach | no | 6 | 6 | 0 | 6/6 | 1 | 1 | 0 | 0 | 0.1171 |
| 0x13b90 __scrt_dllmain_exception_filter | no | 27 | 27 | 0 | 25/27 | 4 | 4 | 5 | 5 | 0.1325 |
| 0x13be0 __scrt_dllmain_uninitialize_c | no | 14 | 14 | 0 | 12/14 | 5 | 5 | 4 | 4 | 0.2304 |
| 0x13c20 __scrt_dllmain_uninitialize_critical | no | 5 | 5 | 0 | 5/5 | 1 | 1 | 0 | 0 | 0.0845 |
| 0x13c40 __scrt_initialize_crt | no | 19 | 19 | 0 | 16/19 | 7 | 7 | 8 | 8 | 0.1424 |
| 0x13c80 __scrt_is_nonwritable_in_current_image | no | 44 | 42 | 0 | 36/42 | 14 | 13 | 20 | 20 | 0.2828 |
| 0x13d20 __scrt_release_startup_lock | no | 13 | 13 | 0 | 11/13 | 4 | 4 | 5 | 5 | 0.1695 |
| 0x13d50 __scrt_uninitialize_crt | no | 14 | 14 | 0 | 12/14 | 4 | 4 | 5 | 5 | 0.0906 |
| 0x13d80 atexit | no | 20 | 20 | 0 | 18/20 | 4 | 4 | 4 | 4 | 0.285 |
| 0x13dc0 __security_init_cookie | no | 42 | 42 | 0 | 40/42 | 3 | 3 | 2 | 2 | 0.2504 |
| 0x13e80 DllMain | no | 9 | 9 | 0 | 7/9 | 4 | 4 | 5 | 5 | 0.1713 |
| 0x13eb0 __scrt_initialize_type_info | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2036 |
| 0x13ec0 __scrt_uninitialize_type_info | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.0828 |
| 0x13ed0 __local_stdio_printf_options | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1875 |
| 0x13ee0 __local_stdio_scanf_options | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1875 |
| 0x13ef0 __scrt_initialize_default_local_stdio_options | no | 7 | 7 | 0 | 7/7 | 1 | 1 | 0 | 0 | 0.3421 |
| 0x13f10 __scrt_get_dyn_tls_init_callback | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1506 |
| 0x13f20 __scrt_fastfail | no | 3 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1003 |
| 0x13f30 _RTC_Initialize | no | 19 | 19 | 0 | 16/19 | 6 | 6 | 8 | 8 | 0.2063 |
| 0x13f80 _RTC_Terminate | no | 19 | 19 | 0 | 16/19 | 6 | 6 | 8 | 8 | 0.2063 |
| 0x13fe0 __isa_available_init | no | 160 | 160 | 0 | 141/160 | 40 | 39 | 64 | 61 | 0.3017 |
| 0x14290 _get_startup_argv_mode | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.1937 |
| 0x142a0 __scrt_is_ucrt_dll_in_use | no | 4 | 4 | 0 | 3/4 | 1 | 1 | 0 | 0 | 0.3359 |
| 0x142b0 memset | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.1855 |
| 0x142b6 memcpy | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.191 |
| 0x142c2 memcmp | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.1855 |
| 0x142ce __std_type_info_destroy_list | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x142da _initterm | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x142e0 _initterm_e | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x142e6 _seh_filter_dll | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x142ec _configure_narrow_argv | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x142f2 _initialize_narrow_environment | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x142f8 _initialize_onexit_table | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x142fe _register_onexit_function | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x14304 _execute_onexit_table | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2081 |
| 0x1430a _crt_atexit | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2428 |
| 0x14310 _cexit | no | 1 | 1 | 0 | 1/1 | 1 | 1 | 0 | 0 | 0.2002 |
| 0x14320 __scrt_stub_for_is_c_termination_complete | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2917 |
| 0x14370 do_reserve_and_handle<alloc::alloc::Global> | no | 41 | 41 | 2 | 38/41 | 5 | 5 | 4 | 4 | 0.2355 |
| 0x14400 closure$2 | no | 73 | 46 | 0 | 39/46 | 21 | 12 | 33 | 17 | 0.1968 |
| 0x14510 get_or_init_slow<core::cell::Cell<enum2$<core::option::Option<alloc::sync::Arc<std::sync::poison::mutex::Mutex<alloc::vec::Vec<u8,alloc::alloc::Global>_>,alloc::alloc::Global>_>_>_>_> | no | 60 | 59 | 0 | 55/59 | 10 | 9 | 12 | 9 | 0.1552 |
| 0x14600 Unwind@180014600 | no | 13 | 13 | 0 | 13/13 | 1 | 1 | 0 | 0 | 0.2615 |
| 0x14620 lock_contended | no | 66 | 66 | 0 | 54/66 | 17 | 17 | 27 | 27 | 0.1747 |
| 0x146e0 read_contended | no | 112 | 84 | 1 | 67/84 | 30 | 23 | 47 | 34 | 0.3021 |
| 0x14960 grow_one | no | 12 | 12 | 1 | 11/12 | 3 | 3 | 2 | 2 | 0.1563 |
| 0x14990 grow_one | no | 30 | 30 | 1 | 28/30 | 3 | 3 | 2 | 2 | 0.2292 |
| 0x14a00 finish_grow<std::alloc::System> | no | 56 | 56 | 0 | 50/56 | 11 | 11 | 15 | 15 | 0.2805 |
| 0x14ab0 grow_amortized<std::alloc::System> | no | 33 | 33 | 0 | 31/33 | 4 | 4 | 4 | 4 | 0.2445 |
| 0x14b20 finish_grow<alloc::alloc::Global> | no | 60 | 60 | 0 | 55/60 | 11 | 11 | 15 | 15 | 0.2295 |
| 0x14be0 is_zero_slow_path | no | 6 | 6 | 0 | 5/6 | 1 | 1 | 0 | 0 | 0.2188 |
| 0x14c00 exhausted | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.2506 |
| 0x14c30 do_reserve_and_handle<alloc::alloc::Global> | no | 35 | 35 | 2 | 32/35 | 5 | 5 | 4 | 4 | 0.2075 |
| 0x14cb0 finish_grow<alloc::alloc::Global> | no | 47 | 47 | 0 | 43/47 | 11 | 11 | 15 | 15 | 0.2636 |
| 0x14d41 handle_alloc_error | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.2029 |
| 0x14d5b handle_error | no | 7 | 7 | 2 | 6/7 | 3 | 3 | 2 | 2 | 0.2506 |
| 0x14d80 capacity_overflow | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.191 |
| 0x14da4 <usize,usize> | no | 15 | 15 | 1 | 15/15 | 1 | 1 | 0 | 0 | 0.1677 |
| 0x14df0 slice_error_fail | no | 6 | 6 | 1 | 6/6 | 1 | 1 | 0 | 0 | 0.2148 |
| 0x14e10 panic_already_borrowed | no | 11 | 11 | 1 | 11/11 | 1 | 1 | 0 | 0 | 0.2 |
| 0x14e50 unwrap_failed | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.2024 |
| 0x14e70 unwrap_failed | no | 20 | 20 | 1 | 20/20 | 1 | 1 | 0 | 0 | 0.1961 |
| 0x14ed0 panic_nounwind | no | 7 | 7 | 1 | 7/7 | 1 | 1 | 0 | 0 | 0.2565 |
| 0x14ef3 panic_bounds_check | no | 15 | 15 | 1 | 15/15 | 1 | 1 | 0 | 0 | 0.2538 |
| 0x14f40 panic_nounwind_fmt | no | 13 | 13 | 2 | 13/13 | 2 | 1 | 1 | 0 | 0.2755 |
| 0x14f80 Catch_All@180014f80 | no | 5 | 5 | 1 | 5/5 | 1 | 1 | 0 | 0 | 0.2302 |
| 0x14f95 assert_failed_inner | no | 56 | 56 | 2 | 55/56 | 3 | 3 | 2 | 2 | 0.2774 |
| 0x1508f panic_cannot_unwind | no | 6 | 6 | 1 | 6/6 | 1 | 1 | 0 | 0 | 0.2124 |
| 0x150b0 panic | no | 5 | 5 | 1 | 5/5 | 1 | 1 | 0 | 0 | 0.2578 |
| 0x150d0 panic_fmt | no | 11 | 11 | 1 | 11/11 | 1 | 1 | 0 | 0 | 0.1879 |
| 0x15100 slice_index_fail | no | 48 | 48 | 3 | 48/48 | 6 | 6 | 6 | 6 | 0.2051 |
| 0x151d0 set_functions_inner | no | 2 | 2 | 0 | 2/2 | 1 | 1 | 0 | 0 | 0.2248 |
| 0x151e0 fin$0 | no | 7 | 7 | 0 | 7/7 | 1 | 1 | 0 | 0 | 0.0842 |
| 0x15200 fin$0 | no | 9 | 9 | 0 | 9/9 | 1 | 1 | 0 | 0 | 0.0848 |
| 0x15230 filt$0 | no | 16 | 16 | 0 | 16/16 | 1 | 1 | 0 | 0 | 0.0873 |
| 0x15270 __scrt_is_nonwritable_in_current_image$filt$0 | no | 9 | 9 | 0 | 8/9 | 1 | 1 | 0 | 0 | 0.1812 |

## Sets

- Sections: 5 common · 2 only Ghidra · 0 only GHIRUST
- Imports: 61 common · 0 only Ghidra · 0 only GHIRUST
- Strings (by value): 148 common · 59 only Ghidra · 411 only GHIRUST

## Timing

- Ghidra headless (import + auto-analysis + export): not measured (reused export)
- GHIRUST (3 runs, release CLI): 1.0 s total

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
