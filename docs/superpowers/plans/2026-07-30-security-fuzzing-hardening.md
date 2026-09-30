# Input-Validation Hardening + Fuzzing Capability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four verified memory-safety defects in LSASS-reachable parsers by routing every attacker-influenced buffer through one canonical, pure, testable validation module, and add a Windows-native libFuzzer/ASan capability that would have found them.

**Architecture:** All offset/length validation moves into a new dependency-free module `EIDCardLibrary/InputValidation.{h,cpp}` — pure functions over caller-supplied pointers and sizes, no LSA/registry/crypto state, no allocation. Because they are pure, the same functions are directly callable from both deterministic regression tests and libFuzzer targets without LSASS. Each of the four bug sites is rewired to call them, and the two divergent re-implementations (in `EIDMigrate/LsaClient.cpp` and the hand-rolled CSP-info checks) are replaced so there is exactly one implementation of each rule. Fuzz/test binaries live in a separate `fuzz/` tree with their own solution and output directory so the shipping build, BinSkim scan, and SHA256SUMS manifest are untouched.

**Tech Stack:** MSVC v143 (14.44.35207), C++17, `/fsanitize=fuzzer` + `/fsanitize=address`, PowerShell build/run scripts, GitHub Actions on `windows-2022`.

## Global Constraints

- Platform toolset **v143**, x64 only, `CharacterSet=Unicode` (so `TCHAR` == `WCHAR`).
- **`EID_SMARTCARD_CSP_INFO.bBuffer` is `TCHAR[4]`; its four `nXxxNameOffset` fields are ULONG offsets in WCHAR units, not bytes.** Every bound on them must be computed in WCHAR units.
- **Fuzz/test binaries must never be written to `x64\Release` or `x64\Debug`.** `windows-ci.yaml` runs BinSkim over `x64\Release\*.exe|*.dll` and `build.ps1` globs the same directory to build `Installer\SHA256SUMS.txt`. Fuzz output goes to `x64\Fuzz\`.
- **Fuzz targets and the product solution stay separate.** Do not add fuzz projects to `EIDCredentialProvider.sln`; do not modify `build.ps1`'s build of that solution.
- **Running an ASan/libFuzzer binary requires `clang_rt.asan_dynamic-x86_64.dll` on PATH** (from `<VS>\VC\Tools\MSVC\<ver>\bin\Hostx64\x64`), even with `/MT`. Without it the process dies with 0xC0000135 before `main`. Run scripts must handle this.
- `/fsanitize=address` and `/fsanitize=fuzzer` **must be passed as separate flags** — comma-joined syntax is rejected by MSVC.
- Never change the `L$_EID_` LSA secret name prefix.
- Preserve existing code style in modified files: tabs, `EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, ...)` on rejection, `// NOSONAR - <TAG>: <reason>` when suppressing a rule.
- Validation functions must be **total**: never allocate, never trace, never dereference beyond what the caller-supplied size permits, and return a plain `BOOL`.

---

## File Structure

**Created:**
- `EIDCardLibrary/InputValidation.h` — declarations of the canonical validators + PoC-input constants shared with tests.
- `EIDCardLibrary/InputValidation.cpp` — the single implementation of every offset/length rule.
- `fuzz/README.md` — how to build/run, and what each target covers.
- `fuzz/EIDFuzz.sln`, `fuzz/targets/EIDFuzzTargets.vcxproj` — fuzz + regression binaries, output `x64\Fuzz\`.
- `fuzz/targets/fuzz_cspinfo.cpp`, `fuzz_tokenmessage.cpp`, `fuzz_privatedata.cpp`, `fuzz_json.cpp` — one libFuzzer entry point each.
- `fuzz/targets/regress_main.cpp` — deterministic replay of the four PoC inputs; exit non-zero on any regression.
- `fuzz/Build-Fuzzers.ps1`, `fuzz/Run-Fuzzers.ps1` — build and run wrappers that resolve VS + fix PATH.
- `fuzz/corpus/<target>/*.bin` — seed corpora, including the four PoC inputs.
- `.github/workflows/fuzz.yml` — PR-time regression + smoke run; weekly long run.
- `docs/FUZZING.md` — operator documentation.

**Modified:**
- `EIDCardLibrary/EIDCardLibrary.vcxproj` — add the two new files.
- `EIDCardLibrary/CredentialManagement.cpp:443,:495` — Fix 1.
- `EIDCardLibrary/Package.cpp:553,:628` — Fix 2 and Fix 3.
- `EIDCardLibrary/StoredCredentialManagement.cpp:77,:1726-1751,:1768,:2063` — Fix 4.
- `EIDCardLibrary/CertificateValidation.cpp:222` and `EIDCardLibrary/smartcardmodule.cpp:789` — delegate to canonical CSP-info validator.
- `EIDMigrate/LsaClient.cpp:200-310,:388-430` — delete duplicate blob validation, call canonical.
- `.gitignore` — ignore `x64/Fuzz/`, `fuzz/crashes/`, `fuzz/corpus-generated/`.

---

### Task 1: Canonical validation module

**Files:**
- Create: `EIDCardLibrary/InputValidation.h`, `EIDCardLibrary/InputValidation.cpp`
- Modify: `EIDCardLibrary/EIDCardLibrary.vcxproj` (add both to the existing `ClCompile`/`ClInclude` ItemGroups)

**Interfaces:**
- Consumes: `EID_PRIVATE_DATA` (`StoredCredentialManagement.h`), `EID_SMARTCARD_CSP_INFO`, `EID_CHALLENGE_MESSAGE`, `EID_RESPONSE_MESSAGE` (`EIDCardLibrary.h`).
- Produces — every later task depends on these exact signatures:
  ```cpp
  BOOL EIDValidatePrivateDataLayout(const EID_PRIVATE_DATA* pData, DWORD cbBlob);
  DWORD EIDPrivateDataSpan(const EID_PRIVATE_DATA* pData);
  BOOL EIDValidateCspInfo(const EID_SMARTCARD_CSP_INFO* pCspInfo, DWORD cbCspData);
  PCWSTR EIDCspInfoStringAt(const EID_SMARTCARD_CSP_INFO* pCspInfo, DWORD cbCspData, ULONG nOffsetInChars);
  BOOL EIDValidateChallengeMessage(const void* pToken, DWORD cbToken);
  BOOL EIDValidateResponseMessage(const void* pToken, DWORD cbToken);
  ```

- [ ] **Step 1: Write `InputValidation.h`**

Declare the six functions above with `__in`/`__in_opt` SAL annotations matching repo style, plus a file-header comment stating the module invariant: *pure, total, no allocation, no tracing, no Windows state — so it can be fuzzed and unit-tested outside LSASS.*

- [ ] **Step 2: Write `InputValidation.cpp`**

Implement, with these rules (each rule exists here and nowhere else):

`EIDValidatePrivateDataLayout` — supersedes the `static IsPrivateDataLayoutValid`. Keep the existing per-region "does it fit" test, and **add**:
- reject `usPasswordLen == 0` (it underflows `dwRoundNumber` at the decrypt site),
- reject when the three regions overlap or their cumulative span exceeds `cbBlob` (needed so the `SecureZeroMemory` span is safe),
- use `FIELD_OFFSET(EID_PRIVATE_DATA, Data)` (not `sizeof`) as the header size, consistently.

`EIDPrivateDataSpan` — returns the exact byte count that is valid to zeroize: `FIELD_OFFSET(...Data) + max(offset+size)` across the three regions. Callers must use this instead of summing sizes.

`EIDValidateCspInfo` — the missing link between the two layers:
- `cbCspData >= FIELD_OFFSET(EID_SMARTCARD_CSP_INFO, bBuffer)`,
- **`dwCspInfoLen >= FIELD_OFFSET(...bBuffer)` and `dwCspInfoLen <= cbCspData`** (this is the check whose absence is Fix 3),
- for each of the four offsets: byte offset `FIELD_OFFSET(...bBuffer) + nOffset * sizeof(WCHAR)` must not overflow and must lie strictly inside `dwCspInfoLen`,
- each referenced string must be NUL-terminated before `dwCspInfoLen` ends.

`EIDCspInfoStringAt` — returns the string pointer only when the offset is non-zero and validates NUL-termination within bounds; returns `nullptr` otherwise. This is the only sanctioned way to read those four strings.

`EIDValidateChallengeMessage` / `EIDValidateResponseMessage`:
- `pToken != nullptr` and `cbToken >= sizeof(EID_CHALLENGE_MESSAGE|EID_RESPONSE_MESSAGE)`,
- for each (offset, len) pair: reject if `offset > cbToken`, if `len > cbToken - offset`, or if `len + sizeof(WCHAR)` would overflow a DWORD (the `UsernameLen + sizeof(WCHAR)` wrap),
- `UsernameLen` must be even (it is copied as WCHARs).

- [ ] **Step 3: Add both files to `EIDCardLibrary.vcxproj`**

Insert `<ClCompile Include="InputValidation.cpp" />` and `<ClInclude Include="InputValidation.h" />` into the existing ItemGroups, keeping alphabetical-ish placement near `GPO.cpp` / `guid.h`.

- [ ] **Step 4: Build and verify it compiles**

Run: `.\build.ps1 Debug x64`
Expected: `========== Rebuild All: N succeeded, 0 failed` in `build.log`.

- [ ] **Step 5: Commit**

```bash
git add EIDCardLibrary/InputValidation.h EIDCardLibrary/InputValidation.cpp EIDCardLibrary/EIDCardLibrary.vcxproj
git commit -m "feat(security): canonical pure input-validation module"
```

---

### Task 2: Fuzz + regression harness infrastructure

**Files:**
- Create: `fuzz/EIDFuzz.sln`, `fuzz/targets/EIDFuzzTargets.vcxproj`, `fuzz/Build-Fuzzers.ps1`, `fuzz/Run-Fuzzers.ps1`, `fuzz/targets/regress_main.cpp`, `fuzz/README.md`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `EIDValidate*` from Task 1.
- Produces: `x64\Fuzz\eidfuzz_<target>.exe` per fuzz target and `x64\Fuzz\eidregress.exe`; `fuzz\Build-Fuzzers.ps1 [-Target <name>]`; `fuzz\Run-Fuzzers.ps1 [-Target <name>] [-Seconds <n>] [-Regress]`.

**Design note (why not one big project):** each fuzz target needs its own `main` from libFuzzer, so each is its own EXE. They compile `InputValidation.cpp` **directly into the target** (rather than linking `EIDCardLibrary.lib`) so the code under test is ASan-instrumented and the target has no LSA/crypt link dependencies. This is only possible because Task 1 made the module dependency-free — do not let the targets pull in other library sources.

- [ ] **Step 1: Write `Build-Fuzzers.ps1`**

Resolve VS via `vswhere`, then for each target invoke `cl` through `vcvars64.bat` with exactly:
`/nologo /EHsc /Zi /Od /MT /std:c++17 /DUNICODE /D_UNICODE /I..\..\EIDCardLibrary /fsanitize=address /fsanitize=fuzzer` plus `..\..\EIDCardLibrary\InputValidation.cpp` and the target `.cpp`, output into `x64\Fuzz\`. Note in a comment that the two `/fsanitize` flags cannot be comma-joined. For `regress_main.cpp` use `/fsanitize=address` only (it has its own `main`, so no `fuzzer` flag).

- [ ] **Step 2: Write `Run-Fuzzers.ps1`**

Prepend `<VS>\VC\Tools\MSVC\<ver>\bin\Hostx64\x64` to `$env:PATH` before launching (the ASan DLL requirement from Global Constraints), pass `-max_total_time=$Seconds`, point each target at `fuzz\corpus\<target>`, write reproducers to `fuzz\crashes\`, and return a non-zero exit code if any target reports a crash so CI fails.

- [ ] **Step 3: Write `regress_main.cpp` with the four PoC inputs**

A plain `main` with one `CHECK_REJECT(...)` per PoC, printing `PASS`/`FAIL` per case and returning the failure count. The four cases, which must all be **rejected** after Tasks 3-5:
1. `EID_CHALLENGE_MESSAGE` with `UsernameLen = 0xFFFFFFFF` (the `+sizeof(WCHAR)` wrap).
2. `EID_CHALLENGE_MESSAGE` with `ChallengeOffset = 0xFFFFFF00`, `ChallengeLen = 0x100` (offset past end).
3. `EID_SMARTCARD_CSP_INFO` with `cbCspData = 40`, `dwCspInfoLen = 0x10000`, `nCardNameOffset = 0xFFF0` (inner length exceeding outer).
4. `EID_PRIVATE_DATA` with `usPasswordLen = 0` (the `dwRoundNumber` underflow), and a second with three regions overlapping at offset 0 (the oversized zeroize span).

- [ ] **Step 4: Build and run the regression binary — expect FAILURES**

Run: `.\fuzz\Build-Fuzzers.ps1 -Target regress; .\fuzz\Run-Fuzzers.ps1 -Regress`
Expected: it builds, and reports `FAIL` for the cases whose fixes land in Tasks 3-5 (Task 1's validator already rejects some). This is the red half of the TDD cycle and proves the harness detects real defects rather than trivially passing.

- [ ] **Step 5: Commit**

```bash
git add fuzz .gitignore
git commit -m "test(security): libFuzzer/ASan harness + PoC regression replay"
```

---

### Task 3: Fix 1 — SSP token message validation

**Files:**
- Modify: `EIDCardLibrary/CredentialManagement.cpp:443` (`ReceiveChallengeMessage`), `:495` (`ReceiveResponseMessage`)
- Create: `fuzz/targets/fuzz_tokenmessage.cpp`

**Interfaces:**
- Consumes: `EIDValidateChallengeMessage`, `EIDValidateResponseMessage`.

- [ ] **Step 1: Add the guard to both functions**

At the top of each, before the existing `MessageType`/`Signature` checks, add a `cBuffers`/`pvBuffer` check and the corresponding `EIDValidate*Message(Buffer->pBuffers[0].pvBuffer, Buffer->pBuffers[0].cbBuffer)` call, returning `SEC_E_INVALID_TOKEN` with a `WINEVENT_LEVEL_WARNING` trace on rejection — matching the shape of `ReceiveNegociateMessage:341`. Also NULL-check both `EIDAlloc` results (currently unchecked) and return `SEC_E_INSUFFICIENT_MEMORY`.

- [ ] **Step 2: Write `fuzz_tokenmessage.cpp`**

`LLVMFuzzerTestOneInput` treats the input as a raw token: call `EIDValidateChallengeMessage`, and when it returns TRUE, perform the same offset arithmetic the production code performs (bounded reads into a local buffer) so a validator that wrongly returns TRUE trips ASan. Do the same for the response message. This is the key oracle pattern — the fuzzer tests the validator *against* the consumer's arithmetic.

- [ ] **Step 3: Build and fuzz for 120s**

Run: `.\fuzz\Build-Fuzzers.ps1 -Target tokenmessage; .\fuzz\Run-Fuzzers.ps1 -Target tokenmessage -Seconds 120`
Expected: no crash, no ASan report, non-zero `exec/s`, and `Done` in the output.

- [ ] **Step 4: Run the regression binary**

Run: `.\fuzz\Run-Fuzzers.ps1 -Regress`
Expected: PoC cases 1 and 2 now report `PASS`.

- [ ] **Step 5: Commit**

```bash
git add EIDCardLibrary/CredentialManagement.cpp fuzz/targets/fuzz_tokenmessage.cpp fuzz/corpus/tokenmessage
git commit -m "fix(security): validate SSP challenge/response token buffers"
```

---

### Task 4: Fixes 2+3 — CSP-info bounds and the debug printer

**Files:**
- Modify: `EIDCardLibrary/Package.cpp:553` (`RemapPointer`), `:628` (`EIDDebugPrintEIDUnlockLogonStruct`); `EIDCardLibrary/CertificateValidation.cpp:222`; `EIDCardLibrary/smartcardmodule.cpp:789`
- Create: `fuzz/targets/fuzz_cspinfo.cpp`

**Interfaces:**
- Consumes: `EIDValidateCspInfo`, `EIDCspInfoStringAt`.

- [ ] **Step 1: Validate CSP info at the choke point**

In `RemapPointer`, after the existing `CspData`/`CspDataLength` checks and the rebase, call `EIDValidateCspInfo((PEID_SMARTCARD_CSP_INFO)pUnlockLogon->Logon.CspData, pUnlockLogon->Logon.CspDataLength)` and return `STATUS_INVALID_PARAMETER` on failure. This is the single point that closes Fix 3 for every downstream consumer.

- [ ] **Step 2: Make the debug printer total**

Change `EIDDebugPrintEIDUnlockLogonStruct` to take the authentication-buffer length as a third parameter, clamp every `wcsncpy_s` count to `min(Length/2, ARRAYSIZE(Buffer)-1)` (removing the unconditional `Buffer[Length/2]=0` overflow), and replace all four `&pCspInfo->bBuffer[...]` reads with `EIDCspInfoStringAt(...)`, printing `(invalid)` when it returns `nullptr`. Update the call site at `EIDAuthenticationPackage.cpp:926` to pass `AuthenticationInformationLength`.

- [ ] **Step 3: Delegate the two downstream validators**

In `CertificateValidation.cpp:222` and `smartcardmodule.cpp:789`, delete the hand-rolled offset checks and use `EIDCspInfoStringAt` for each string read, so the two divergent field-set checks become one rule.

- [ ] **Step 4: Write `fuzz_cspinfo.cpp` and fuzz for 120s**

Target: interpret the input as `(cbCspData, EID_SMARTCARD_CSP_INFO bytes)`, call `EIDValidateCspInfo`, and on TRUE call `EIDCspInfoStringAt` for all four offsets and `wcslen` each non-null result — so any bound the validator gets wrong is an immediate ASan report.

Run: `.\fuzz\Build-Fuzzers.ps1 -Target cspinfo; .\fuzz\Run-Fuzzers.ps1 -Target cspinfo -Seconds 120`
Expected: no crash; `Done`.

- [ ] **Step 5: Verify PoC 3 and commit**

Run: `.\fuzz\Run-Fuzzers.ps1 -Regress` — expect PoC 3 `PASS`.

```bash
git add EIDCardLibrary/Package.cpp EIDCardLibrary/CertificateValidation.cpp EIDCardLibrary/smartcardmodule.cpp EIDAuthenticationPackage/EIDAuthenticationPackage.cpp fuzz/targets/fuzz_cspinfo.cpp fuzz/corpus/cspinfo
git commit -m "fix(security): bound CSP-info offsets and the unlock-logon debug printer"
```

---

### Task 5: Fix 4 — private-data blob underflow and zeroize span

**Files:**
- Modify: `EIDCardLibrary/StoredCredentialManagement.cpp:77` (delete the static validator), `:1726-1751`, `:1768`, `:2063`
- Create: `fuzz/targets/fuzz_privatedata.cpp`

**Interfaces:**
- Consumes: `EIDValidatePrivateDataLayout`, `EIDPrivateDataSpan`.

- [ ] **Step 1: Replace the static validator**

Delete `static BOOL IsPrivateDataLayoutValid` and repoint its sole call site (`RetrievePrivateData:2542`) at `EIDValidatePrivateDataLayout`. Keep the existing explanatory comment about why the blob is attacker-influenced.

- [ ] **Step 2: Guard the decrypt loop and fix both zeroize calls**

At `:1726`, add an explicit `dwRoundNumber == 0` rejection (defence in depth even though the validator now rejects `usPasswordLen == 0`) so the `(dwRoundNumber-1)` expression can never underflow. Replace both `SecureZeroMemory(pEidPrivateData, sizeof(...) + ... + ...)` calls at `:1768` and `:2063` with `SecureZeroMemory(pEidPrivateData, EIDPrivateDataSpan(pEidPrivateData))`.

- [ ] **Step 3: Write `fuzz_privatedata.cpp` and fuzz for 120s**

Target: input becomes the blob; call `EIDValidatePrivateDataLayout`, and on TRUE read every region at its declared offset/size **and** write `EIDPrivateDataSpan` bytes of zeroes into a heap copy of exactly the blob size — so an over-large span is an immediate ASan heap-buffer-overflow.

Run: `.\fuzz\Build-Fuzzers.ps1 -Target privatedata; .\fuzz\Run-Fuzzers.ps1 -Target privatedata -Seconds 120`
Expected: no crash; `Done`.

- [ ] **Step 4: Verify PoC 4 and commit**

Run: `.\fuzz\Run-Fuzzers.ps1 -Regress` — expect all four PoC groups `PASS`.

```bash
git add EIDCardLibrary/StoredCredentialManagement.cpp fuzz/targets/fuzz_privatedata.cpp fuzz/corpus/privatedata
git commit -m "fix(security): reject zero-length password blob, bound zeroize span"
```

---

### Task 6: Retire the duplicate blob validators in EIDMigrate

**Files:**
- Modify: `EIDMigrate/LsaClient.cpp:200-310`, `:388-430`

- [ ] **Step 1: Replace both hand-rolled checks**

Delete the two divergent layout checks (they use `sizeof(EID_PRIVATE_DATA)` where the canonical rule uses `FIELD_OFFSET`, and bound the certificate against total length rather than the data region) and call `EIDValidatePrivateDataLayout` instead. Add `#include "InputValidation.h"`.

- [ ] **Step 2: Build and commit**

Run: `.\build.ps1 Debug x64` — expect `0 failed`.

```bash
git add EIDMigrate/LsaClient.cpp
git commit -m "refactor(security): single blob-layout rule shared with EIDMigrate"
```

---

### Task 7: JSON parser target, CI wiring, and documentation

**Files:**
- Create: `fuzz/targets/fuzz_json.cpp`, `.github/workflows/fuzz.yml`, `docs/FUZZING.md`

- [ ] **Step 1: Write `fuzz_json.cpp`**

Feed the input to the hand-rolled parser in `EIDMigrate/JsonHelper.cpp` inside a `try/catch(...)`, since the documented defect is an uncaught `std::runtime_error` reaching `main`. Catching it in the harness means the target reports *memory* faults only; note in a comment that the throw-escapes-to-main DoS is tracked separately and is not what this target asserts.

- [ ] **Step 2: Write `.github/workflows/fuzz.yml`**

`permissions: {}` at top level (repo convention), all actions SHA-pinned, `runs-on: windows-2022` (the only label with v143 + Spectre libs — see the CI notes). Two jobs: on `pull_request`/`push`, build all targets, run `-Regress` plus 60s per fuzz target; on `schedule` (weekly), 30 minutes per target. Upload `fuzz/crashes/` as an artifact when non-empty. Do **not** add this to the required-checks path for releases.

- [ ] **Step 3: Write `docs/FUZZING.md`**

Cover: what each target covers and why the four non-targets (crypt32-delegated cert/CRL parsing, minidriver-mediated card I/O, write-only CSV logger, kernel-parsed hives) are excluded; the exact build/run commands; the ASan-DLL PATH requirement; how to reproduce from a `fuzz/crashes/` file; and a prominent note that **OpenSSF Scorecard cannot credit this work** (OSS-Fuzz/ClusterFuzzLite are Linux/clang-only, OneFuzz was archived 2023-11-01) so the Fuzzing check stays at 0 by design.

- [ ] **Step 4: Verify the workflow parses and commit**

Run: `gh workflow list` after push, and confirm the new workflow appears and its first run succeeds.

```bash
git add fuzz/targets/fuzz_json.cpp .github/workflows/fuzz.yml docs/FUZZING.md
git commit -m "ci(security): scheduled fuzzing workflow + operator docs"
```

---

### Task 8: Full verification

- [ ] **Step 1: Release build green**

Run: `.\build.ps1 Release x64`
Expected: `0 failed`; confirm `x64\Release` contains **no** `eidfuzz_*` or `eidregress` binary.

- [ ] **Step 2: Confirm the release manifest is unpolluted**

Run: `Select-String -Path Installer\SHA256SUMS.txt -Pattern 'fuzz|regress'`
Expected: no matches.

- [ ] **Step 3: Extended fuzz run across all targets**

Run: `.\fuzz\Run-Fuzzers.ps1 -Seconds 600`
Expected: every target reports `Done`, zero crashes, `fuzz\crashes\` empty.

- [ ] **Step 4: Security review**

Run `/security-review` on the branch diff. The privileged-code lesson from the uninstaller work applies: the first review round of that feature passed CI green with a real flaw in it, so this step is mandatory, not optional.

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin security-fuzzing-hardening
gh pr create --title "Input-validation hardening + Windows fuzzing capability" --body-file <notes>
```

---

## Self-Review

**Spec coverage:** Bug 1 → Task 3. Bug 2 → Task 4 Step 2. Bug 3 → Task 4 Steps 1/3. Bug 4 → Task 5. Validator duplication → Tasks 4 Step 3 + 6. Fuzzing capability → Tasks 2, 3, 4, 5, 7. Scorecard reality → Task 7 Step 3. Release-pipeline safety → Global Constraints + Task 8 Steps 1-2.

**Placeholder scan:** none — every step names exact files, line anchors, commands, and expected output.

**Type consistency:** the six signatures in Task 1 are used verbatim in Tasks 3-6. `EIDPrivateDataSpan` (not `...Size`) is used in both Task 1 and Task 5. `EIDCspInfoStringAt` is used in Task 4 Steps 2 and 3 and Task 4 Step 4.

**Known risk:** Task 4 Step 3 may reveal that `CertificateValidation.cpp` / `smartcardmodule.cpp` need the CSP-info length threaded through from a caller that does not currently have it. If so, add the parameter rather than reading `dwCspInfoLen` from the buffer — that field is precisely what cannot be trusted.
