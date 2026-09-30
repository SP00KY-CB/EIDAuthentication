<#
.SYNOPSIS
    Run the EID libFuzzer targets and/or the PoC regression binary.

.DESCRIPTION
    Two gotchas this script exists to absorb:

    1. An ASan/libFuzzer binary needs clang_rt.asan_dynamic-x86_64.dll at
       process start, even when built /MT. Without it the process dies with
       0xC0000135 (STATUS_DLL_NOT_FOUND) before main() and you get no output
       at all - which reads like a hung or broken target. The DLL lives in
       <VS>\VC\Tools\MSVC\<ver>\bin\Hostx64\x64, so that directory is
       prepended to PATH here.

    2. libFuzzer writes crash reproducers into the CURRENT directory by
       default. Run from the repo root and they land next to the sources.
       -artifact_prefix pins them to fuzz\crashes\ instead.

.PARAMETER Target
    Run one fuzz target by name (cspinfo, tokenmessage, privatedata, json).
    Omit to run all of them.

.PARAMETER Seconds
    Wall-clock budget per fuzz target. Default 60.

.PARAMETER Regress
    Run only the deterministic PoC regression binary (fast, no fuzzing).

.EXAMPLE
    .\fuzz\Run-Fuzzers.ps1 -Regress
    .\fuzz\Run-Fuzzers.ps1 -Target cspinfo -Seconds 120
    .\fuzz\Run-Fuzzers.ps1 -Seconds 600
#>

param(
    [ValidateSet("cspinfo", "tokenmessage", "privatedata", "json", "remappointer", "all")]
    [string]$Target = "all",
    [int]$Seconds = 60,
    [switch]$Regress
)

$ErrorActionPreference = "Stop"

$repoRoot   = Split-Path $PSScriptRoot -Parent
$outDir     = Join-Path $repoRoot "x64\Fuzz"
$corpusRoot = Join-Path $PSScriptRoot "corpus"
$crashDir   = Join-Path $PSScriptRoot "crashes"

if (-not (Test-Path $outDir)) {
    Write-Host "ERROR: $outDir not found - run fuzz\Build-Fuzzers.ps1 first" -ForegroundColor Red
    exit 1
}
New-Item -ItemType Directory -Force $crashDir | Out-Null

# ---------------------------------------------------------------------------
# Gotcha 1: put the ASan runtime DLL on PATH
#
# Every step here is best-effort and must not throw: eidregress.exe does NOT
# need the ASan DLL, so a machine without Visual Studio should still be able to
# run the regression gate. $ErrorActionPreference is Stop, so guard each call
# rather than letting a missing vswhere terminate the script.
# ---------------------------------------------------------------------------
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$asanDir = $null
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsPath) {
        $asanDir = Get-ChildItem (Join-Path $vsPath "VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll") -ErrorAction SilentlyContinue |
                   Select-Object -Last 1
    }
}
if ($asanDir) {
    $env:PATH = "$(Split-Path $asanDir.FullName -Parent);$env:PATH"
} else {
    Write-Host "WARNING: clang_rt.asan_dynamic-x86_64.dll not found; fuzz targets will exit 0xC0000135" -ForegroundColor Yellow
}

$failures = 0

# ---------------------------------------------------------------------------
# Deterministic regression replay
# ---------------------------------------------------------------------------
$regressExe = Join-Path $outDir "eidregress.exe"
if (Test-Path $regressExe) {
    Write-Host "=== PoC regression replay ===" -ForegroundColor Cyan
    & $regressExe
    $regressExit = $LASTEXITCODE
    if ($regressExit -ne 0) {
        Write-Host "REGRESSION: $regressExit PoC case(s) not rejected" -ForegroundColor Red
        $failures += $regressExit
    } else {
        Write-Host "All PoC cases rejected." -ForegroundColor Green
    }
    Write-Host ""
} else {
    # A missing binary is a failure, never a silent pass. "Nothing ran" and
    # "everything passed" must not produce the same exit code.
    Write-Host "ERROR: eidregress.exe not built - run fuzz\Build-Fuzzers.ps1" -ForegroundColor Red
    exit 1
}

if ($Regress) {
    exit $failures
}

# ---------------------------------------------------------------------------
# Fuzz targets
# ---------------------------------------------------------------------------
$names = @("cspinfo", "tokenmessage", "privatedata", "json", "remappointer")
if ($Target -ne "all") { $names = @($Target) }

foreach ($name in $names) {
    $exe = Join-Path $outDir "eidfuzz_$name.exe"
    if (-not (Test-Path $exe)) {
        # Counts as a failure: a target that never ran cannot be "clean", and CI
        # must not report success for a tree that failed to build.
        Write-Host "  MISSING $name (not built)" -ForegroundColor Red
        $failures++
        continue
    }

    $corpus = Join-Path $corpusRoot $name
    New-Item -ItemType Directory -Force $corpus | Out-Null

    Write-Host "=== fuzzing $name for ${Seconds}s ===" -ForegroundColor Cyan
    $log = Join-Path $crashDir "$name.log"

    # -artifact_prefix keeps reproducers out of the repo root (gotcha 2).
    # Trailing separator is required; libFuzzer concatenates it verbatim.
    & $exe $corpus `
        "-max_total_time=$Seconds" `
        "-artifact_prefix=$crashDir\" `
        "-print_final_stats=1" *> $log
    $exit = $LASTEXITCODE

    $crashLines = Select-String -Path $log -Pattern 'ERROR: AddressSanitizer|ERROR: libFuzzer|SEGV|Test unit written' -ErrorAction SilentlyContinue
    if ($exit -ne 0 -or $crashLines) {
        Write-Host "  CRASH in $name (exit $exit) - see $log" -ForegroundColor Red
        $crashLines | Select-Object -First 5 | ForEach-Object { Write-Host "    $($_.Line)" -ForegroundColor Yellow }
        $failures++
    } else {
        $stats = Select-String -Path $log -Pattern 'stat::number_of_executed_units' -ErrorAction SilentlyContinue
        $execs = if ($stats) { ($stats.Line -split ':')[-1].Trim() } else { "?" }
        Write-Host "  clean ($execs execs)" -ForegroundColor Green
    }
}

Write-Host ""
if ($failures -gt 0) {
    Write-Host "$failures target(s) reported findings - reproducers in $crashDir" -ForegroundColor Red
    exit 1
}
Write-Host "All targets clean." -ForegroundColor Green
# Explicit: without this the exit code is inherited from the last native
# command that happened to run.
exit 0
