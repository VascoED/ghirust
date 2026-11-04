# GHIRUST objective behavior harness.
#
# Loads the fixture DLLs and calls the exported functions with known inputs,
# checking the documented expected outputs. This validates that the binaries
# behave as their source declares, which is the reference for judging whether
# recovered pseudocode preserves the original logic.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests\objectives\run_behavior.ps1
#
# Output: tests\objectives\results\behavior.json

$ErrorActionPreference = 'Stop'

$objectives = $PSScriptRoot
$root = Split-Path -Parent (Split-Path -Parent $objectives)
$binaries = Join-Path $objectives 'binaries'
$results = Join-Path $objectives 'results'
New-Item -ItemType Directory -Force -Path $results | Out-Null

# The C++ DLL imports the Rust DLL; make the binaries directory searchable
# so LoadLibrary can resolve those imports.
$env:PATH = "$binaries;$env:PATH"

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class NativeFixture {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryW(string path);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);

    public static Delegate Resolve(IntPtr module, string name, Type delegateType) {
        IntPtr address = GetProcAddress(module, name);
        if (address == IntPtr.Zero) {
            throw new InvalidOperationException("export not found: " + name);
        }
        return Marshal.GetDelegateForFunctionPointer(address, delegateType);
    }
}
"@

function Load-Exports {
    param([string]$DllName)
    $module = [NativeFixture]::LoadLibraryW((Join-Path $binaries $DllName))
    if ($module -eq [IntPtr]::Zero) {
        throw "LoadLibrary failed for $DllName"
    }
    return $module
}

function Call-U64([IntPtr]$module, [string]$name, [Int64[]]$args) {
    $delegateType = [System.Func[System.Int64[], System.UInt64]]
    $call = [NativeFixture]::Resolve($module, $name, $delegateType)
    return [uint64]$call.Invoke([object[]]$args)
}

# Simpler: define delegates per signature via Add-Type, then invoke.
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Callbacks {
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_2(ulong a, ulong b);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_6(ulong a, ulong b, ulong c, ulong d, ulong e, ulong f);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int I32_1(long value);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_1(ulong value);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U32_1(uint value);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_PTR_U64(IntPtr values, ulong length);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_PTR(IntPtr pointer);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_PTR_PTR(IntPtr a, IntPtr b);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void VOID_PTR_U64(IntPtr pointer, ulong length);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void VOID_PTR_PTR(IntPtr a, IntPtr b);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong U64_PTR_U8(IntPtr text);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate double F64_1(double value);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int I32_1_I64(long value);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint U32_0();
}
"@

function Resolve([IntPtr]$module, [string]$name, [Type]$delegateType) {
    return [NativeFixture]::Resolve($module, $name, $delegateType)
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        throw "FAIL $Label : expected $Expected got $Actual"
    }
}

$checks = @()

function Check {
    param([string]$Label, [object]$Expected, [object]$Actual)
    Assert-Equal $Expected $Actual $Label
    $script:checks += [pscustomobject]@{
        check = $Label
        expected = $Expected
        actual = $Actual
        passed = $true
    }
}

# --------------------------------------------------------------------------
# demo_features.dll (Rust)
# --------------------------------------------------------------------------
$module = Load-Exports 'demo_features.dll'
try {
    $u64_2 = Resolve $module 'features_add' ([Callbacks+U64_2])
    Check 'features_add(3,4)' 7 ([uint64]$u64_2.Invoke(3, 4))

    $sub = Resolve $module 'features_sub' ([Callbacks+U64_2])
    Check 'features_sub(10,4)' 6 ([uint64]$sub.Invoke(10, 4))

    $mul = Resolve $module 'features_mul' ([Callbacks+U64_2])
    Check 'features_mul(6,7)' 42 ([uint64]$mul.Invoke(6, 7))

    $div = Resolve $module 'features_div' ([Callbacks+U64_2])
    Check 'features_div(9,2)' 4 ([uint64]$div.Invoke(9, 2))
    Check 'features_div(9,0)' 0 ([uint64]$div.Invoke(9, 0))

    $many = Resolve $module 'features_many_args' ([Callbacks+U64_6])
    Check 'features_many_args(1..6)' 91 ([uint64]$many.Invoke(1, 2, 3, 4, 5, 6))

    $classify = Resolve $module 'features_classify' ([Callbacks+I32_1])
    Check 'features_classify(-5)' 0 ([int]$classify.Invoke(-5))
    Check 'features_classify(0)' 1 ([int]$classify.Invoke(0))
    Check 'features_classify(50)' 2 ([int]$classify.Invoke(50))
    Check 'features_classify(500)' 3 ([int]$classify.Invoke(500))

    $sum = Resolve $module 'features_sum_loop' ([Callbacks+U64_1])
    Check 'features_sum_loop(10)' 55 ([uint64]$sum.Invoke(10))

    $even = Resolve $module 'features_for_loop' ([Callbacks+U64_1])
    Check 'features_for_loop(6)' 12 ([uint64]$even.Invoke(6))

    $fib = Resolve $module 'features_fib' ([Callbacks+U32_1])
    Check 'features_fib(10)' 55 ([uint64]$fib.Invoke(10))

    $array = New-Object 'System.UInt64[]' 5
    $array[0] = 1; $array[1] = 2; $array[2] = 3; $array[3] = 4; $array[4] = 5
    $handle = [System.Runtime.InteropServices.GCHandle]::Alloc($array, 'Pinned')
    $arraySum = Resolve $module 'features_array_sum' ([Callbacks+U64_PTR_U64])
    Check 'features_array_sum(1..5)' 15 ([uint64]$arraySum.Invoke($handle.AddrOfPinnedObject(), 5))
    $handle.Free()

    $bytes = [System.Text.Encoding]::ASCII.GetBytes('abcd')
    $reverseHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($bytes, 'Pinned')
    $reverse = Resolve $module 'features_reverse_in_place' ([Callbacks+VOID_PTR_U64])
    $reverse.Invoke($reverseHandle.AddrOfPinnedObject(), 4) | Out-Null
    $reversed = [System.Text.Encoding]::ASCII.GetString($bytes)
    Check 'features_reverse_in_place(abcd)' 'dcba' $reversed
    $reverseHandle.Free()

    $rect = New-Object 'System.UInt32[]' 2
    $rect[0] = 6; $rect[1] = 7
    $rectHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($rect, 'Pinned')
    $area = Resolve $module 'features_struct_area' ([Callbacks+U64_PTR])
    Check 'features_struct_area(6x7)' 42 ([uint64]$area.Invoke($rectHandle.AddrOfPinnedObject()))
    $rectHandle.Free()

    $swapValues = New-Object 'System.UInt64[]' 2
    $swapValues[0] = 3; $swapValues[1] = 9
    $swapHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($swapValues, 'Pinned')
    $swap = Resolve $module 'features_pointer_swap' ([Callbacks+VOID_PTR_PTR])
    $swap.Invoke($swapHandle.AddrOfPinnedObject(), [IntPtr]::Add($swapHandle.AddrOfPinnedObject(), 8)) | Out-Null
    Check 'features_pointer_swap(3,9) a' 9 $swapValues[0]
    Check 'features_pointer_swap(3,9) b' 3 $swapValues[1]
    $swapHandle.Free()

    $tagged = New-Object 'System.UInt64[]' 3
    $tagged[0] = 0; $tagged[1] = 6; $tagged[2] = 7
    $taggedHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($tagged, 'Pinned')
    $taggedArea = Resolve $module 'features_tagged_area' ([Callbacks+U64_PTR])
    Check 'features_tagged_area(circle 6,7)' 42 ([uint64]$taggedArea.Invoke($taggedHandle.AddrOfPinnedObject()))
    $tagged[0] = 1
    Check 'features_tagged_area(rect 6,7)' 6 ([uint64]$taggedArea.Invoke($taggedHandle.AddrOfPinnedObject()))
    $tagged[0] = 9
    Check 'features_tagged_area(other 6,7)' 1 ([uint64]$taggedArea.Invoke($taggedHandle.AddrOfPinnedObject()))
    $taggedHandle.Free()

    $text = [System.Text.Encoding]::ASCII.GetBytes('hello' + [char]0)
    $textHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($text, 'Pinned')
    $stringLength = Resolve $module 'features_string_length' ([Callbacks+U64_PTR_U8])
    Check 'features_string_length(hello)' 5 ([uint64]$stringLength.Invoke($textHandle.AddrOfPinnedObject()))
    $textHandle.Free()

    $internal = Resolve $module 'features_call_internal' ([Callbacks+U64_1])
    Check 'features_call_internal(21)' 43 ([uint64]$internal.Invoke(21))

    $counter = Resolve $module 'features_counter_run' ([Callbacks+U64_1])
    Check 'features_counter_run(5)' 7 ([uint64]$counter.Invoke(5))

    $marker = Resolve $module 'features_export_marker' ([Callbacks+U32_0])
    Check 'features_export_marker()' 65195 ([uint32]$marker.Invoke())
}
finally {
    [NativeFixture]::FreeLibrary($module) | Out-Null
}

# --------------------------------------------------------------------------
# demo_cpp.dll (C++)
# --------------------------------------------------------------------------
$module = Load-Exports 'demo_cpp.dll'
try {
    $u64_2 = Resolve $module 'cpp_add' ([Callbacks+U64_2])
    Check 'cpp_add(3,4)' 7 ([uint64]$u64_2.Invoke(3, 4))

    $sub = Resolve $module 'cpp_sub' ([Callbacks+U64_2])
    Check 'cpp_sub(10,4)' 6 ([uint64]$sub.Invoke(10, 4))

    $mul = Resolve $module 'cpp_mul' ([Callbacks+U64_2])
    Check 'cpp_mul(6,7)' 42 ([uint64]$mul.Invoke(6, 7))

    $div = Resolve $module 'cpp_div' ([Callbacks+U64_2])
    Check 'cpp_div(9,2)' 4 ([uint64]$div.Invoke(9, 2))
    Check 'cpp_div(9,0)' 0 ([uint64]$div.Invoke(9, 0))

    $classify = Resolve $module 'cpp_classify' ([Callbacks+I32_1])
    Check 'cpp_classify(-5)' 0 ([int]$classify.Invoke(-5))
    Check 'cpp_classify(0)' 1 ([int]$classify.Invoke(0))
    Check 'cpp_classify(50)' 2 ([int]$classify.Invoke(50))
    Check 'cpp_classify(500)' 3 ([int]$classify.Invoke(500))

    $sum = Resolve $module 'cpp_sum_loop' ([Callbacks+U64_1])
    Check 'cpp_sum_loop(10)' 55 ([uint64]$sum.Invoke(10))

    $even = Resolve $module 'cpp_even_loop' ([Callbacks+U64_1])
    Check 'cpp_even_loop(6)' 12 ([uint64]$even.Invoke(6))

    $fact = Resolve $module 'cpp_fact' ([Callbacks+U32_1])
    Check 'cpp_fact(5)' 120 ([uint64]$fact.Invoke(5))

    $rect = New-Object 'System.UInt32[]' 2
    $rect[0] = 6; $rect[1] = 7
    $rectHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($rect, 'Pinned')
    $area = Resolve $module 'cpp_struct_area' ([Callbacks+U64_PTR])
    Check 'cpp_struct_area(6x7)' 42 ([uint64]$area.Invoke($rectHandle.AddrOfPinnedObject()))
    $rectHandle.Free()

    $array = New-Object 'System.UInt64[]' 5
    for ($i = 0; $i -lt 5; $i++) { $array[$i] = $i + 1 }
    $arrayHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($array, 'Pinned')
    $arraySum = Resolve $module 'cpp_array_sum' ([Callbacks+U64_PTR_U64])
    Check 'cpp_array_sum(1..5)' 15 ([uint64]$arraySum.Invoke($arrayHandle.AddrOfPinnedObject(), 5))
    $arrayHandle.Free()

    $counter = Resolve $module 'cpp_counter_run' ([Callbacks+U64_1])
    Check 'cpp_counter_run(5)' 7 ([uint64]$counter.Invoke(5))

    $virtualDispatch = Resolve $module 'cpp_virtual_dispatch' ([Callbacks+I32_1])
    Check 'cpp_virtual_dispatch(derived)' 42 ([uint64]$virtualDispatch.Invoke(1))
    Check 'cpp_virtual_dispatch(base)' 10 ([uint64]$virtualDispatch.Invoke(0))

    $overloadInt = Resolve $module 'cpp_overload_int' ([Callbacks+I32_1])
    Check 'cpp_overload_int(5)' 15 ([int]$overloadInt.Invoke(5))

    $overloadDouble = Resolve $module 'cpp_overload_double' ([Callbacks+F64_1])
    Check 'cpp_overload_double(2.5)' 7.5 ([double]$overloadDouble.Invoke(2.5))

    $method = Resolve $module 'cpp_method_call' ([Callbacks+U64_1])
    Check 'cpp_method_call(3)' 21 ([uint64]$method.Invoke(3))

    $exceptionSafe = Resolve $module 'cpp_exception_safe' ([Callbacks+I32_1])
    Check 'cpp_exception_safe(10)' 10 ([int]$exceptionSafe.Invoke(10))
    Check 'cpp_exception_safe(0)' -1 ([int]$exceptionSafe.Invoke(0))

    $callsRust = Resolve $module 'cpp_calls_rust' ([Callbacks+U64_2])
    Check 'cpp_calls_rust(3,4)' 8 ([uint64]$callsRust.Invoke(3, 4))
}
finally {
    [NativeFixture]::FreeLibrary($module) | Out-Null
}

# --------------------------------------------------------------------------
# demo_bridge.dll (Rust -> C++ -> Rust)
# --------------------------------------------------------------------------
$module = Load-Exports 'demo_bridge.dll'
try {
    $roundtrip = Resolve $module 'bridge_roundtrip' ([Callbacks+U64_2])
    Check 'bridge_roundtrip(3,4)' 16 ([uint64]$roundtrip.Invoke(3, 4))

    $direct = Resolve $module 'bridge_direct' ([Callbacks+U64_2])
    Check 'bridge_direct(3,4)' 7 ([uint64]$direct.Invoke(3, 4))
}
finally {
    [NativeFixture]::FreeLibrary($module) | Out-Null
}

$report = [pscustomobject]@{
    generated_at = (Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')
    total = $checks.Count
    passed = ($checks | Where-Object { $_.passed }).Count
    checks = $checks
}
$reportPath = Join-Path $results 'behavior.json'
$report | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 $reportPath
Write-Output "Behavior harness: $($report.passed)/$($report.total) checks passed"
Write-Output "Report: $reportPath"
