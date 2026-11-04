//! Known-source objective fixture for GHIRUST end-to-end analysis.
//!
//! The functions below are deliberately simple, use integer arithmetic and
//! explicit control flow, and are exported with stable names. They are compiled
//! into a real PE DLL with the local Rust toolchain; no hand-crafted bytes are
//! used for the primary objective.

#![allow(dead_code)]

/// Adds two unsigned 64-bit values.
#[unsafe(no_mangle)]
pub extern "C" fn demo_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Returns 0 for negative values, 1 for zero, 2 for positive values.
#[unsafe(no_mangle)]
pub extern "C" fn demo_classify(value: i64) -> u64 {
    if value < 0 {
        0
    } else if value == 0 {
        1
    } else {
        2
    }
}

/// Returns the larger of two unsigned values.
#[unsafe(no_mangle)]
pub extern "C" fn demo_max(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

/// Sums `count` unsigned 32-bit values from `values`.
#[unsafe(no_mangle)]
pub extern "C" fn demo_sum_loop(values: *const u32, count: usize) -> u64 {
    let mut total = 0u64;
    let mut index = 0usize;
    while index < count {
        total = total.wrapping_add(unsafe { *values.add(index) } as u64);
        index += 1;
    }
    total
}

/// Iterative factorial with wrapping multiplication.
#[unsafe(no_mangle)]
pub extern "C" fn demo_fact(n: u64) -> u64 {
    let mut result = 1u64;
    let mut factor = 2u64;
    while factor <= n {
        result = result.wrapping_mul(factor);
        factor += 1;
    }
    result
}

/// Bit-mixing helper used to check shifts and xor reconstruction.
#[unsafe(no_mangle)]
pub extern "C" fn demo_mix(value: u64, shift: u32) -> u64 {
    (value ^ (value << shift)) & 0xffff_ffff
}

fn main() {}
