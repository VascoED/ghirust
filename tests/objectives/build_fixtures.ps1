# GHIRUST objective fixture build script.
#
# Reproducibly builds the four fixture DLLs from known source:
#
#   1. demo.dll            Rust (checked in; rebuilt by tests when needed)
#   2. demo_features.dll   Rust feature matrix
#   3. demo_cpp.dll        C++ feature matrix (imports demo_features.dll)
#   4. demo_bridge.dll     Rust -> C++ -> Rust interop bridge
#
# Requirements:
#   - rustc 1.98+ (edition 2024)
#   - MSVC toolchain (vcvars64.bat from Visual Studio)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests\objectives\build_fixtures.ps1
#
# Binaries, checksums and provenance are recorded in manifest.json.

$ErrorActionPreference = 'Stop'

$objectives = $PSScriptRoot
$source = Join-Path $objectives 'source'
$binaries = Join-Path $objectives 'binaries'
$build = Join-Path $objectives 'build'

New-Item -ItemType Directory -Force -Path $binaries | Out-Null
New-Item -ItemType Directory -Force -Path $build | Out-Null

$vcvars = @(
    'C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat'
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat'
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $vcvars) {
    throw 'vcvars64.bat not found; install the MSVC C++ toolchain or edit $vcvars.'
}

function Invoke-Checked {
    param([string]$Command)
    Write-Host "+ $Command"
    cmd /c $Command
    if ($LASTEXITCODE -ne 0) {
        throw "command failed with exit code $LASTEXITCODE: $Command"
    }
}

# 1. Rust feature DLL (also produces the import library for the C++ link).
Write-Host '=== demo_features.dll (Rust) ==='
Invoke-Checked "rustc --edition 2024 -O --crate-type cdylib -C panic=abort --crate-name demo_features `"$source\rust\demo_features.rs`" -o `"$binaries\demo_features.dll`""

# 2. C++ feature DLL, linking the Rust import library.
Write-Host '=== demo_cpp.dll (C++) ==='
Invoke-Checked "call `"$vcvars`" >nul && cd /d `"$source\cpp`" && cl /nologo /LD /O2 /EHsc /std:c++20 /Fo:$build\ demo_cpp.cpp /link /OUT:`"$binaries\demo_cpp.dll`" /IMPLIB:`"$binaries\demo_cpp.lib`" `"$binaries\demo_features.dll.lib`""
Move-Item "$source\cpp\demo_cpp.exp" "$binaries\demo_cpp.exp" -Force -ErrorAction SilentlyContinue

# 3. Interop bridge DLL (Rust calling C++ calling Rust).
Write-Host '=== demo_bridge.dll (Rust interop) ==='
Invoke-Checked "rustc --edition 2024 -O --crate-type cdylib -C panic=abort --crate-name demo_bridge `"$source\rust\demo_bridge.rs`" -L `"$binaries`" -o `"$binaries\demo_bridge.dll`""

Write-Host ''
Write-Host 'Built fixtures:'
Get-ChildItem $binaries -Filter '*.dll' | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    Write-Host ("  {0,-22} {1,10} bytes  {2}" -f $_.Name, $_.Length, $hash)
}
Write-Host ''
Write-Host 'Next: powershell -ExecutionPolicy Bypass -File tests\objectives\run_behavior.ps1'
