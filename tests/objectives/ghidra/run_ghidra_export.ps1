# GHIRUST Ghidra Export Prototype
#
# Runs the Ghidra headless analyzer on one binary and exports function metadata
# plus decompiled C to NDJSON. This script is UNEXECUTED in the GHIRUST
# development environment because no Java runtime/JDK is installed. It refuses
# to pretend otherwise.

param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$GhidraHome = $env:GHIDRA_HOME,

    [string]$ProjectDir = (Join-Path $env:TEMP 'ghirust-ghidra-project'),

    [string]$ProjectName = 'GhirustObjective'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Error @"
Java was not found on PATH. The Ghidra bridge is therefore NOT validated.
Install a JDK supported by your Ghidra release, set GHIDRA_HOME, and run this
script again. Do not create Ghidra comparison results manually.
"@
    exit 2
}

if ([string]::IsNullOrWhiteSpace($GhidraHome)) {
    Write-Error "Set GHIDRA_HOME to the Ghidra installation directory or pass -GhidraHome."
    exit 2
}

$headless = Join-Path $GhidraHome 'support\analyzeHeadless.bat'
if (-not (Test-Path $headless)) {
    Write-Error "Could not find analyzeHeadless.bat under '$GhidraHome'."
    exit 2
}

if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary"
    exit 2
}

$resolvedBinary = (Resolve-Path $Binary).Path
$outputPath = [System.IO.Path]::GetFullPath($Output)
$outputDirectory = Split-Path -Parent $outputPath
if ($outputDirectory -and -not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

$scriptDirectory = $PSScriptRoot
New-Item -ItemType Directory -Force -Path $ProjectDir | Out-Null

Write-Host "Ghidra home: $GhidraHome"
Write-Host "Input:       $resolvedBinary"
Write-Host "Output:      $outputPath"
Write-Host "Script:      $scriptDirectory\ExportProgram.java"

& $headless $ProjectDir $ProjectName `
    -import $resolvedBinary `
    -scriptPath $scriptDirectory `
    -postScript ExportProgram.java $outputPath `
    -deleteProject

if ($LASTEXITCODE -ne 0) {
    Write-Error "Ghidra headless analysis failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

if (-not (Test-Path $outputPath)) {
    Write-Error "Ghidra completed but did not produce $outputPath."
    exit 3
}

$size = (Get-Item $outputPath).Length
Write-Host "Ghidra export complete: $outputPath ($size bytes)"
