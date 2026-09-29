# EID fuzzing harness

Windows-native libFuzzer + AddressSanitizer targets for the parsers that handle
attacker-influenced input, plus a deterministic replay of the proof-of-concept
inputs for the four defects found on 2026-07-30.

Full rationale, target-by-target coverage, and the list of deliberate
non-targets are in [`../docs/FUZZING.md`](../docs/FUZZING.md). This file is the
quick reference.

## Quick start

```powershell
.\fuzz\Seed-Corpus.ps1          # once, or after changing a struct layout
.\fuzz\Build-Fuzzers.ps1        # all targets -> x64\Fuzz\
.\fuzz\Run-Fuzzers.ps1 -Regress # fast: PoC replay only, no fuzzing
.\fuzz\Run-Fuzzers.ps1 -Seconds 600
```

Single target:

```powershell
.\fuzz\Build-Fuzzers.ps1 -Target cspinfo
.\fuzz\Run-Fuzzers.ps1   -Target cspinfo -Seconds 120
```

## Targets

| Target | Code under test | Asserts |
|---|---|---|
| `cspinfo` | `EIDValidateCspInfo`, `EIDCspInfoStringAt` | validator TRUE ⇒ all four name reads stay in bounds, and `dwCspInfoLen` ≤ the caller's length |
| `tokenmessage` | `EIDValidateChallengeMessage`, `EIDValidateResponseMessage` | validator TRUE ⇒ the SSP copies (including the `+sizeof(WCHAR)` allocation) stay in bounds |
| `privatedata` | `EIDValidatePrivateDataLayout`, `EIDPrivateDataSpan` | validator TRUE ⇒ every region read is in bounds **and** the zeroize span fits the allocation |
| `json` | `JsonParser` (`EIDMigrate/JsonHelper.cpp`) | memory safety only — parse errors are thrown by design and are caught in the harness |
| `regress` | all validators | the 16 PoC / benign cases; exit code = number of failures |

Each fuzz target is a differential oracle: it does not just call the validator,
it then performs **the same arithmetic the production consumer performs**. A
validator that wrongly returns TRUE therefore produces an ASan report rather
than a silent pass. This was verified by deliberately removing the
`dwCspInfoLen <= dwCspDataLength` check — the fuzzer found it in under 30
seconds and wrote a replayable reproducer.

## Reproducing a finding

Crashes and per-target logs land in `fuzz\crashes\`. Replay one input:

```powershell
$vs   = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
$asan = (Get-ChildItem "$vs\VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll" | Select-Object -Last 1).DirectoryName
$env:PATH = "$asan;$env:PATH"
x64\Fuzz\eidfuzz_cspinfo.exe fuzz\crashes\crash-<sha1>
```

`Run-Fuzzers.ps1` does that PATH fix-up for you; the snippet above is for
replaying by hand.

## Gotchas that cost time

- **`clang_rt.asan_dynamic-x86_64.dll` must be on PATH**, even for a `/MT`
  build. Without it the target exits `0xC0000135` (STATUS_DLL_NOT_FOUND)
  before `main`, producing no output at all — which looks like a hang.
  `Run-Fuzzers.ps1` prepends the toolset `bin\Hostx64\x64` directory.
- **Never report an oracle violation with `__debugbreak()`.** It raises
  `STATUS_BREAKPOINT`, which terminates the process before libFuzzer's handler
  runs: no report, and **no reproducer file is written**. Use
  `EID_ORACLE_REQUIRE` / `EIDOracleViolation` from `targets/oracle.h`, which
  `abort()`s so libFuzzer saves the input.
- **`-artifact_prefix` must end with a separator** and be passed explicitly, or
  libFuzzer drops `crash-<sha1>` files into the current directory — which,
  when run from the repo root, means into the source tree.
- **Build with `/std:c++latest`.** `EIDCardLibrary` headers use `std::expected`
  (C++23) and `std::span`; the product projects set `stdcpp23`.
- **Output must stay in `x64\Fuzz\`.** `windows-ci.yaml` runs BinSkim over
  `x64\Release\*.exe|*.dll`, and `build.ps1` globs the same directory to build
  `Installer\SHA256SUMS.txt`. A fuzz binary in there would be scanned as a
  shipped artifact and listed in the release manifest.

## Adding a target

1. Write `targets/fuzz_<name>.cpp` with `LLVMFuzzerTestOneInput`, including the
   consumer-arithmetic oracle — a target that only calls a validator and
   discards the result finds almost nothing.
2. Add `<name>` to the `$targets` list in `Build-Fuzzers.ps1`, the
   `ValidateSet` on both scripts, and the `$names` list in `Run-Fuzzers.ps1`.
3. Add seeds in `Seed-Corpus.ps1`. Valid structure matters far more than volume.
4. Prove the oracle can fail: break the rule under test on purpose, confirm the
   fuzzer catches it, then revert. An oracle that cannot fail is decoration.
