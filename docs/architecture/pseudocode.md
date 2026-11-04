# Heuristic Pseudocode Reconstruction

`ghirust/crates/ghirust-core/src/pseudocode.rs` reconstructs C-like pseudocode
from the decoded CFG. It is an original heuristic decompiler. It is not a port
of Ghidra's decompiler and does not claim Ghidra parity.

## Pipeline

1. **Input preparation** — blocks are collected and indexed by start address;
   the entry is block 0.
2. **Dominators and post-dominators** — computed over reachable blocks.
3. **Loop discovery** — back edges (`source` dominated by `target`) produce loop
   headers, latches and exits. Bodies are bounded to avoid pathological CFGs.
4. **Label computation** — branch targets, loop headers and merge points receive
   labels.
5. **Symbolic execution** — each block is walked with a register/stack
   environment. Expressions are built for arithmetic, logic, shifts,
   comparisons, `lea`, loads, stores and calls.
6. **Control-flow structuring** — if/else, loops and `break` statements are
   emitted, with explicit `goto`/labels when a region cannot be structured.
7. **Rendering** — signature, local declarations and body are rendered as
   C-like text; warnings are attached.

## Expression environment

The environment maps canonical register names (`rax`, `rcx`, ...) to symbolic
expressions. Entry-state argument registers are named `a0`, `a1`, ... according
to the detected calling convention:

- **Win64**: `rcx`, `rdx`, `r8`, `r9`;
- **SysV**: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`.

Important correctness rules:

- An assignment updates the environment as well as the printed statement.
  Without this, later reads would keep returning entry-state expressions.
- `x = x + 1` stores the variable `x`, not the expanded expression, so a loop
  body does not accumulate increments incorrectly.
- Before executing a loop body, loop-carried registers are reset to variables
  so first-iteration constants are not propagated into later iterations.
- `xor r, r` and `sub r, r` are treated as zeroing idioms and do not mark the
  old argument value as used.
- Register reads used by memory addressing go through the same environment, so
  `lea rax, [rcx+rdx]` uses `a0`/`a1` rather than raw register names.

## Control flow

- Simple `if`/`else` regions are rendered with braces.
- While-style loops are rendered as `while (condition)` when the condition is
  known.
- Do-while-style regions are rendered as `while (1)` with an explicit
  `if (!condition) break;` when necessary, because this is always semantically
  valid even if less pretty.
- Unstructured regions fall back to labels and `goto` statements rather than
  guessing an invalid structure.

## Calls and returns

- Direct and indirect calls are rendered as expressions assigned to `rax` when
  a result may be used.
- Volatile registers are clobbered after calls according to the calling
  convention.
- Return values are recovered from `rax` when the function returns it.
- Parameters appear in the signature only when their values are semantically
  used.

## Explicit limitations

- Only x86/x86-64 instructions with a semantic model are reconstructed.
- SSE/AVX/x87/string/system instructions are listed in
  `unsupported_instructions` and `warnings`. For example, the auto-vectorized
  `demo_sum_loop` fixture reports `movq`, `paddq`, `pshufd`, `punpckldq` and
  `pxor` instead of pretending to understand the vector loop.
- Types are mostly `uint64_t`; there is no struct, array, pointer or aggregate
  type recovery.
- Alias analysis, SSA construction and interprocedural data flow are absent.
- Indirect jumps prevent complete CFG recovery.
- The output is pseudocode, not the original source. Semantics must be verified
  before reuse.

## Validated examples

The objective fixture in `tests/objectives/source/demo.rs` produces, among
others:

```c
uint64_t demo_add(uint64_t a0, uint64_t a1)
{
    uint64_t rax; // register

    rax = (a0 + a1);
    return (a0 + a1);
}
```

```c
uint64_t demo_fact(uint64_t a0)
{
    uint64_t rax; // register
    uint64_t rdx; // register

    rax = 1;
    if ((a0 >= 2)) {
        rdx = 2;
        LAB_180001040:;
        while (1) {
            rax = (rax * rdx);
            rdx = (rdx + 1);
            if ((rdx > a0)) {
                break;
            }
        }
    }
    return rax;
}
```

These are checked by `crates/ghirust-core/tests/real_binary.rs`.
