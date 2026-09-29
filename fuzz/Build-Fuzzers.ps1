<#
.SYNOPSIS
    Build the EID libFuzzer targets and the PoC regression binary.

.DESCRIPTION
    These binaries are deliberately NOT part of EIDCredentialProvider.sln and
    NOT written to x64\Debug or x64\Release. Two things in the shipping
    pipeline glob that directory:

      * .github/workflows/windows-ci.yaml runs BinSkim over x64\Release\*.exe
        and *.dll - a fuzz target would be scanned as a shipped binary and
        fail the mitigation checks (ASan/libFuzzer builds have no CFG etc).
      * build.ps1 globs the same directory to build Installer\SHA256SUMS.txt,
        so a fuzz target would be listed in the release manifest.

    Output therefore goes to x64\Fuzz\. Keep it that way.

    Each target is its own EXE because libFuzzer supplies main(). Targets
    compile ..\EIDCardLibrary\InputValidation.cpp directly rather than linking
    EIDCardLibrary.lib, so the code under test is ASan-instrumented and the
    target inherits no LSA/crypt link dependencies. This only works because
    InputValidation.cpp is dependency-free by design - if you find yourself
    adding more library sources here, fix the layering instead.

.PARAMETER Target
    Build one target by name (cspinfo, tokenmessage, privatedata, json,
    regress). Omit to build all.

.EXAMPLE
    .\fuzz\Build-Fuzzers.ps1
    .\fuzz\Build-Fuzzers.ps1 -Target cspinfo
#>

param(
    [ValidateSet("cspinfo", "tokenmessage", "privatedata", "json", "remappointer", "regress", "all")]
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent
$outDir   = Join-Path $repoRoot "x64\Fuzz"
$libDir   = Join-Path $repoRoot "EIDCardLibrary"
$tgtDir   = Join-Path $PSScriptRoot "targets"

# ---------------------------------------------------------------------------
# Locate Visual Studio (same detection as build.ps1)
# ---------------------------------------------------------------------------
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) {
    Write-Host "ERROR: vswhere.exe not found - is Visual Studio 2022 installed?" -ForegroundColor Red
    exit 1
}
$vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    Write-Host "ERROR: no VS installation with the C++ toolset found" -ForegroundColor Red
    exit 1
}
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    Write-Host "ERROR: vcvars64.bat not found under $vsPath" -ForegroundColor Red
    exit 1
}

# ASan ships with the MSVC toolset; a missing clang_rt.fuzzer lib means the
# install predates 17.0 or the ASan component was deselected.
$fuzzerLib = Get-ChildItem (Join-Path $vsPath "VC\Tools\MSVC\*\lib\x64\clang_rt.fuzzer_MT-x86_64.lib") -ErrorAction SilentlyContinue
if (-not $fuzzerLib) {
    Write-Host "ERROR: clang_rt.fuzzer_MT-x86_64.lib not found." -ForegroundColor Red
    Write-Host "Install the VS component 'C++ AddressSanitizer' (Individual components > search 'sanitizer')." -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force $outDir | Out-Null

# ---------------------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------------------
# /MT so the target does not need the VC redist DLLs; note this does NOT
# remove the runtime dependency on clang_rt.asan_dynamic-x86_64.dll, which
# Run-Fuzzers.ps1 handles by putting the toolset bin dir on PATH.
#
# The two /fsanitize flags MUST be separate arguments - MSVC rejects the
# comma-joined form /fsanitize=address,fuzzer.
$commonFlags = @(
    # /std:c++latest to match <LanguageStandard>stdcpp23</LanguageStandard> in
    # the product vcxproj files - EIDCardLibrary headers use std::expected
    # (C++23) and std::span (C++20), so anything lower fails to parse them.
    "/nologo", "/EHsc", "/Zi", "/Od", "/MT", "/std:c++latest",
    "/DUNICODE", "/D_UNICODE", "/DEID_FUZZING_BUILD",
    "/I`"$libDir`"",
    "/fsanitize=address"
)

$targets = @(
    @{ Name = "cspinfo";      Sources = @("fuzz_cspinfo.cpp");      Fuzzer = $true  }
    @{ Name = "tokenmessage"; Sources = @("fuzz_tokenmessage.cpp"); Fuzzer = $true  }
    @{ Name = "privatedata";  Sources = @("fuzz_privatedata.cpp");  Fuzzer = $true  }
    @{ Name = "json";         Sources = @("fuzz_json.cpp");         Fuzzer = $true  }
    @{ Name = "remappointer"; Sources = @("fuzz_remappointer.cpp"); Fuzzer = $true  }
    @{ Name = "regress";      Sources = @("regress_main.cpp");      Fuzzer = $false }
)

if ($Target -ne "all") {
    $targets = $targets | Where-Object { $_.Name -eq $Target }
}

$failed = 0
foreach ($t in $targets) {
    $exeName = if ($t.Fuzzer) { "eidfuzz_$($t.Name).exe" } else { "eid$($t.Name).exe" }
    $exePath = Join-Path $outDir $exeName

    Write-Host "Building $exeName ..." -ForegroundColor Cyan

    $flags = @($commonFlags)
    if ($t.Fuzzer) {
        # regress_main.cpp has its own main(); libFuzzer would collide with it.
        $flags += "/fsanitize=fuzzer"
    }

    $srcArgs = @()
    foreach ($s in $t.Sources) { $srcArgs += "`"$(Join-Path $tgtDir $s)`"" }
    # The JSON target needs the parser under test; everything else needs only
    # the validation module.
    if ($t.Name -eq "json") {
        $srcArgs += "`"$(Join-Path $repoRoot 'EIDMigrate\JsonHelper.cpp')`""
    } else {
        $srcArgs += "`"$(Join-Path $libDir 'InputValidation.cpp')`""
    }

    # Object/PDB files go to a per-target scratch dir so parallel builds of
    # different targets cannot collide on vc140.pdb.
    $objDir = Join-Path $outDir "obj\$($t.Name)"
    New-Item -ItemType Directory -Force $objDir | Out-Null

    $clLine = "cl $($flags -join ' ') /Fo`"$objDir\\`" /Fd`"$objDir\vc.pdb`" $($srcArgs -join ' ') /Fe`"$exePath`""
    $cmd = "call `"$vcvars`" >nul 2>&1 && $clLine"

    $out = cmd.exe /c $cmd 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exePath)) {
        Write-Host "  FAILED" -ForegroundColor Red
        $out | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        $failed++
    } else {
        Write-Host "  OK -> $exePath" -ForegroundColor Green
    }
}

if ($failed -gt 0) {
    Write-Host ""
    Write-Host "$failed target(s) failed to build" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "All targets built into $outDir" -ForegroundColor Green
