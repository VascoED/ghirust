// GHIRUST objective fixture: Rust feature DLL.
//
// Every function has a known result so recovered pseudocode can be checked
// against intended behavior. All exports use extern "C" and a stable ABI:
// no panics are allowed to unwind across the FFI boundary, so the bodies use
// safe arithmetic on plain integers and raw pointers.
//
// Build (from this directory):
//   rustc --edition 2024 -O --crate-type cdylib -C panic=abort `
//       --crate-name demo_features demo_features.rs `
//       -o ..\..\binaries\demo_features.dll
//
// The export names are the single source of truth for what analysis should
// recover.

/// Plain C-compatible rectangle passed by pointer or by value.
#[repr(C)]
pub struct Rect {
    pub width: u32,
    pub height: u32,
}

/// Tagged union style enum: circle or rectangle payloads.
#[repr(C)]
pub struct Shape {
    pub tag: u32,
    pub first: u64,
    pub second: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn features_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

#[unsafe(no_mangle)]
pub extern "C" fn features_sub(a: u64, b: u64) -> u64 {
    a.wrapping_sub(b)
}

#[unsafe(no_mangle)]
pub extern "C" fn features_mul(a: u64, b: u64) -> u64 {
    a.wrapping_mul(b)
}

#[unsafe(no_mangle)]
pub extern "C" fn features_div(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    a / b
}

#[unsafe(no_mangle)]
pub extern "C" fn features_many_args(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f
}

#[unsafe(no_mangle)]
pub extern "C" fn features_classify(value: i64) -> i32 {
    if value < 0 {
        0
    } else if value == 0 {
        1
    } else if value < 100 {
        2
    } else {
        3
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn features_sum_loop(n: u64) -> u64 {
    let mut total: u64 = 0;
    let mut index: u64 = 1;
    while index <= n {
        total += index;
        index += 1;
    }
    total
}

#[unsafe(no_mangle)]
pub extern "C" fn features_for_loop(n: u64) -> u64 {
    let mut even_sum: u64 = 0;
    for index in 0..=n {
        if index % 2 == 0 {
            even_sum += index;
        }
    }
    even_sum
}

#[unsafe(no_mangle)]
pub extern "C" fn features_fib(n: u32) -> u64 {
    if n < 2 {
        return n as u64;
    }
    features_fib(n - 1) + features_fib(n - 2)
}

#[unsafe(no_mangle)]
pub extern "C" fn features_array_sum(values: *const u64, length: usize) -> u64 {
    if values.is_null() {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(values, length) };
    let mut total: u64 = 0;
    for value in slice {
        total = total.wrapping_add(*value);
    }
    total
}

#[unsafe(no_mangle)]
pub extern "C" fn features_reverse_in_place(bytes: *mut u8, length: usize) {
    if bytes.is_null() || length < 2 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(bytes, length) };
    let mut left = 0usize;
    let mut right = length - 1;
    while left < right {
        slice.swap(left, right);
        left += 1;
        right -= 1;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn features_struct_area(rect: *const Rect) -> u64 {
    if rect.is_null() {
        return 0;
    }
    let rect = unsafe { &*rect };
    rect.width as u64 * rect.height as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn features_struct_by_value(rect: Rect) -> u64 {
    rect.width as u64 + 2 * rect.height as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn features_tagged_area(shape: *const Shape) -> u64 {
    if shape.is_null() {
        return 0;
    }
    let shape = unsafe { &*shape };
    match shape.tag {
        0 => shape.first * shape.second,
        1 => (shape.first + shape.second) / 2,
        _ => shape.first ^ shape.second,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn features_pointer_swap(a: *mut u64, b: *mut u64) {
    if a.is_null() || b.is_null() {
        return;
    }
    unsafe {
        let temporary = *a;
        *a = *b;
        *b = temporary;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn features_memzero(destination: *mut u8, length: usize) {
    if destination.is_null() {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(destination, length) };
    for byte in slice {
        *byte = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn features_string_length(text: *const u8) -> usize {
    if text.is_null() {
        return 0;
    }
    let mut length = 0usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    length
}

#[unsafe(no_mangle)]
pub extern "C" fn features_float_loop(steps: u64) -> u64 {
    let mut total: f64 = 0.0;
    let mut index: u64 = 0;
    while index < steps {
        total += index as f64 * 0.5;
        index += 1;
    }
    total.to_bits()
}

// Internal (non-exported) helper: private function call from an export.
#[inline(never)]
fn internal_double(value: u64) -> u64 {
    value.wrapping_mul(2)
}

#[unsafe(no_mangle)]
pub extern "C" fn features_call_internal(value: u64) -> u64 {
    internal_double(value).wrapping_add(1)
}

/// Style of the C++ side: a small "class" exposed through C wrappers.
pub struct Counter {
    value: u64,
}

impl Counter {
    fn new() -> Self {
        Counter { value: 0 }
    }

    fn increment(&mut self, step: u64) {
        self.value = self.value.wrapping_add(step);
    }

    fn read(&self) -> u64 {
        self.value
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn features_counter_run(steps: u64) -> u64 {
    let mut counter = Counter::new();
    let mut remaining = steps;
    while remaining > 0 {
        counter.increment(remaining & 3);
        remaining -= 1;
    }
    counter.read()
}

/// Export marker value, readable through the export table.
#[unsafe(no_mangle)]
pub static FEATURES_EXPORTED: u32 = 0xFE_AB;

#[unsafe(no_mangle)]
pub extern "C" fn features_export_marker() -> u32 {
    FEATURES_EXPORTED
}
