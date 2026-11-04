# Analysis Pipeline

The pipeline in `ghirust/crates/ghirust-core/src/analysis.rs` is intentionally
inspectable: every stage produces data that can be saved to JSON and reviewed.

## 1. Loading

`load_or_hint` uses the `object` crate to map PE, ELF, Mach-O and WebAssembly
files. The loader records:

- container format, architecture, bitness, endianness, object kind and OS;
- image base and entry point;
- sections with addresses, virtual/file sizes, permissions and coarse kind;
- imports, exports and symbols;
- printable strings.

Section data is stored as offsets into the memory-mapped file. BSS-like tails
are synthesized as zero-filled reads so the decoder never reads unrelated file
bytes.

## 2. Seed discovery

A seed is a candidate function entry. Seeds are collected from:

1. the loader entry point;
2. exported symbols;
3. named function symbols;
4. direct call targets found during the linear sweep;
5. direct branch (jump) targets found during the sweep — low confidence, they
   are needed for shared-return thunks and handler functions;
6. aligned prologue candidates (`push rbp/rbx/rsi/rdi/r12..r15`, `mov rbp, rsp`,
   `mov [rsp+disp], reg` spills, `sub rsp, imm`, `lea rsp, …`). `int3`/`nop`
   padding never resets the function-boundary state; `call` is treated as a
   thunk terminator.

Each seed records a discovery kind and a confidence value. Duplicate addresses
are merged, keeping the strongest discovery reason.

## 3. Recursive decoding

For each seed, the decoder walks reachable instructions with `iced-x86` in
64-bit or 32-bit mode. It stops a path at returns, unconditional jumps,
invalid instructions, already-visited addresses and configured limits.

Tail-call handling:

- a direct `call` whose return address equals its target ends the function
  (`DecodedTerminator::TailCall`);
- a `jmp` into a known function entry stops the walk instead of swallowing the
  target function;
- after all functions are decoded, jumps that land strictly inside another
  function's block are normalized to `TailCall` terminators.

Decoded functions contribute their direct call targets back to the seed
worklist, so functions reachable only through calls (for example `__chkstk`)
are recovered like Ghidra does.

Control-flow terminators are classified as:

- `fallthrough`;
- `jump`;
- `conditional` (mnemonic, taken target, fallthrough);
- `return`;
- `indirect`.

## 4. Block splitting

Recursive descent can decode a branch target as part of an earlier block when
the target is reached later. A second pass splits any block whose interior
contains a known block start or successor target. This keeps the invariant that
every basic block has one entry and contiguous instructions.

## 5. Function construction

Decoded blocks become `FunctionAnalysis` records containing:

- name, address, size, end, discovery kind and confidence;
- block list, instruction count and direct call destinations;
- decompiled signature/pseudocode (`DecompiledFunction`);
- warnings and unsupported instruction names.

Overlap is decided per basic-block interval, not per full span, so a tail jump
into another function does not hide later functions. When a seed lies inside
an already-decoded block, it is counted in `overlapping_functions_skipped`
rather than silently discarded.

## 6. Cross-references

The analysis records `call`, `jump`, `data` and `string` references. Direct
calls and branches are exact. RIP-relative data references are resolved to
absolute virtual addresses. References into string records are derived from
those addresses.

## 7. GUIR lifting

The analysis emits an `ir::Module` with a block per recovered basic block and
operations for the instruction families that are modelled. The module is
validated structurally (unique block IDs, existing branch targets) and saved
with the analysis. It is not Ghidra p-code.

## 8. Pseudocode

`pseudocode.rs` receives the decoded CFG and performs:

- symbolic register and stack environment tracking;
- parameter naming from the active calling convention (Win64 or SysV);
- expression building for arithmetic, logic, shifts, comparisons and memory;
- condition recovery from `cmp`/`test` plus flags;
- structuring of if/else, while, do-while-like loops and `break`;
- emission of a C-like signature and annotated body.

Instructions without a semantic model are recorded in
`unsupported_instructions` and appended to `warnings`. They are never guessed.

## Limits

Default limits are defined in `AnalysisOptions`:

- `max_functions`: functions retained;
- `max_instructions_per_function`: instructions per function;
- `max_blocks_per_function`: blocks per function;
- `max_linear_scan_instructions`: instructions visited during the seed sweep;
- `max_prologue_candidates`: prologue seeds considered;
- `discover_prologues`: whether prologue heuristics are enabled;
- `max_strings`: strings retained in the analysis;
- `max_xrefs`: cross-references retained;
- `decompile`: whether pseudocode is reconstructed.

Hitting a limit sets `stats.truncated` and produces a warning.
