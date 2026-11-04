// GHIRUST objective fixture: Rust <-> C++ interop bridge.
//
// This DLL imports cpp_calls_rust from demo_cpp.dll, which itself imports
// features_add from demo_features.dll. One call therefore crosses
// Rust -> C++ -> Rust.
//
// Expected behavior: bridge_roundtrip(a, b) = (features_add(a, b) + 1) * 2
//                                               = (a + b + 1) * 2
//
// Build (after demo_features.dll and demo_cpp.dll exist):
//   rustc --edition 2024 -O --crate-type cdylib -C panic=abort `
//       --crate-name demo_bridge demo_bridge.rs `
//       -L ..\..\binaries -o ..\..\binaries\demo_bridge.dll

#[link(name = "demo_cpp")]
unsafe extern "C" {
    fn cpp_calls_rust(a: u64, b: u64) -> u64;
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge_roundtrip(a: u64, b: u64) -> u64 {
    unsafe { cpp_calls_rust(a, b) }.wrapping_mul(2)
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge_direct(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}
