# OpenAccess EID Rename Implementation Plan

> **Status (2026-09-30):** implemented on `release/v2.0.00`, together with the `security-fuzzing-hardening` branch, for the v2.0.00 prerelease. Deviations from the steps below: the legacy baseline is v1.3.00, not v1.2.00; migration reuses the old uninstaller from `.onInit` (made to wait with `_?=`) instead of a hand-written deregistration block; the ProgramData folder is renamed rather than copied, keeping its protected DACL; GitHub URLs, the SonarCloud key and the Aikido repo name are left for Task 12; runtime checks are `docs/VM_TEST_PLAN.md` Part R.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the project from "EID Authentication" to "OpenAccess EID", eliminating every occurrence of the token `EIDAuthentication` from source, installer, Group Policy templates, documentation and CI, while preserving all existing smart-card enrollments and the repository's stars and history.

**Architecture:** The rename is applied in three concentric rings. The outer ring (docs, display strings, repo name) is cosmetic and reversible. The middle ring (project/file names, solution, CI) is mechanical and verified by the build. The inner ring (LSA authentication package name, ProgramData path, registry hives, ADMX namespace) changes runtime identity and requires explicit migration code plus a reboot, because a machine whose LSA registry references a package DLL that no longer exists is a machine that may not authenticate. The LSA secret prefix is deliberately **not** touched.

**Tech Stack:** C++/Win32 (Visual Studio 2022, x64), NSIS installer, Group Policy ADMX/ADML, GitHub Actions, PowerShell (`build.ps1`).

---

## Global Constraints

- **Target name:** the project is **OpenAccess EID**. Compact identifier token is `OpenAccessEID` (no spaces, PascalCase). Display name is `OpenAccess EID` (with a space).
- **Forbidden token:** the literal string `EIDAuthentication` must not appear in any git-tracked file or filename when this plan is complete. This is the plan's acceptance test.
- **`EID` is retained.** The bare `EID` prefix stays on all other component names. Do NOT rename `EIDCardLibrary`, `EIDCredentialProvider`, `EIDMigrate`, `EIDMigrateUI`, `EIDManageUsers`, `EIDTraceConsumer`, `EIDConfigurationWizard`, `EIDConfigurationWizardElevated`, or `EIDPasswordChangeNotification`.
- **NEVER change `CREDENTIAL_LSAPREFIX`.** `EIDCardLibrary/StoredCredentialManagement.cpp:48` defines `constexpr LPCWSTR CREDENTIAL_LSAPREFIX = L"L$_EID_";`. Every enrolled user's credential is stored in an LSA secret named `L$_EID__<RID>`. Changing this orphans every existing enrollment — users' cards stop working and each must be re-enrolled by hand. It contains `EID` but not `EIDAuthentication`, so it is out of scope by the rule above. Leave it exactly as it is.
- **NEVER change any GUID.** The credential provider CLSID `{546f5d01-6cc1-4a16-82da-5aae70cff802}`, `{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}`, the ETW provider `{B4866A0A-DB08-4835-A26F-414B46F3244C}` and the shell namespace `{F5D846B4-14B0-11DE-B23C-27A355D89593}` are opaque identifiers that do not encode the name. Changing them breaks registration continuity for no benefit.
- **Do not touch** `SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider`. The `RequireCardBoundCredentials` and `RequireRevocationCheck` policies live under Microsoft's key, not the project's, and are unaffected by this rename.
- **Build with `.\build.ps1 Debug x64`.** Never invoke msbuild on a single `.vcxproj` — the inter-project lib path only resolves through the solution build, and `build.ps1` also performs minidriver and icon staging.
- **Base branch:** cut a branch `rename/openaccess-eid` from `main` at or after the v1.2.00 prerelease tag. The rename ships as **v2.0.00** because it is a breaking change for anyone who scripted against the old paths, registry keys or Group Policy namespace.
- **Keep the original author's attribution and the LGPL-2.1 license (issue #63).** Every `Copyright (C) 2009 Vincent Le Toux` and `Copyright (C) 2009-2011 My Smart Logon` line, the README "Credits and license" section and fork notice, and the non-affiliation statement in `Installer/license.txt` must survive the rename unchanged apart from the product name. Never reintroduce `www.mysmartlogon.com` as a `CompanyName`. Any new source file gets the LGPL-2.1 header, not GPL. Add both checks to the Task 1 guard rails.
- **Every task ends with a commit.** Do not batch commits across tasks.

### Canonical mapping table

Every task must use exactly these replacements. Do not invent variants.

| Old | New |
|---|---|
| `EIDAuthentication` (bare token) | `OpenAccessEID` |
| `EID Authentication` (display) | `OpenAccess EID` |
| `EIDAuthenticationPackage` | `OpenAccessEIDPackage` |
| `EIDAuthenticationPackage.dll` | `OpenAccessEIDPackage.dll` |
| `EIDAuthenticationPackageDllRegister` | `OpenAccessEIDPackageDllRegister` |
| `EIDAuthenticationPackageDllUnRegister` | `OpenAccessEIDPackageDllUnRegister` |
| `EIDAuthentication.admx` / `.adml` | `OpenAccessEID.admx` / `.adml` |
| ADMX namespace `EIDAuthentication.Policies` | `OpenAccessEID.Policies` |
| ADMX target prefix `eidauth` | `oaeid` |
| ADMX string id `Cat_EIDAuthentication` | `Cat_OpenAccessEID` |
| `C:\ProgramData\EIDAuthentication` | `C:\ProgramData\OpenAccessEID` |
| `HKLM\Software\EIDAuthentication` | `HKLM\Software\OpenAccessEID` |
| `HKLM\SOFTWARE\EIDAuthentication\LogManager` | `HKLM\SOFTWARE\OpenAccessEID\LogManager` |
| `HKLM\SOFTWARE\Policies\EIDAuthentication\LogManager` | `HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager` |
| `...\Uninstall\EIDAuthentication` | `...\Uninstall\OpenAccessEID` |
| `$PROGRAMFILES64\EID Authentication` | `$PROGRAMFILES64\OpenAccess EID` |
| `$SMPROGRAMS\EID Authentication` | `$SMPROGRAMS\OpenAccess EID` |
| `EIDCredentialProvider.sln` | `OpenAccessEID.sln` |
| GitHub repo `EIDAuthentication` | `OpenAccessEID` |
| SonarCloud key `DangerDawgAU_EIDAuthentication` | `DangerDawgAU_OpenAccessEID` |

### Scope facts (measured 2026-07-25)

- **39** git-tracked files contain the token `EIDAuthentication`.
- **7** tracked files and **1** directory are named with it: the `EIDAuthenticationPackage/` directory plus `EIDAuthenticationPackage.{cpp,def,vcproj,vcxproj,vcxproj.filters}` and `Installer/PolicyDefinitions/EIDAuthentication.admx` / `en-US/EIDAuthentication.adml`.
- Build outputs under `x64/` and the `sonarqube_issues/` dumps are **not** tracked. Ignore them; they regenerate.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `tools/Verify-Rename.ps1` | **Create.** Acceptance test: asserts the forbidden token is absent from tracked files and filenames. | 1 |
| `EIDCardLibrary/EIDCardLibrary.h` | LSA package name constants. | 2 |
| `EIDCardLibrary/Registration.cpp` | Registers/deregisters the package in the LSA multi-sz values; gains legacy cleanup. | 2, 7 |
| `EIDAuthenticationPackage/` → `OpenAccessEIDPackage/` | Project directory and its 5 name-bearing files. | 3 |
| `EIDCredentialProvider.sln` → `OpenAccessEID.sln` | Solution; project path and name entries. | 3, 8 |
| `EIDCardLibrary/CSVConfig.h` | ProgramData paths and both LogManager registry keys. | 4 |
| `EIDTraceConsumer/EIDTraceConsumer.cpp` | Duplicated policy key + default log path. | 4 |
| `Installer/PolicyDefinitions/OpenAccessEID.admx` / `en-US/OpenAccessEID.adml` | Group Policy template: filename, namespace, prefix, category id. | 5 |
| `Installer/Installerx64.nsi` | Display names, install dir, Start Menu, registry, ADMX filenames, **legacy migration**. | 6, 7 |
| `build.ps1` | Solution filename, artifact list. | 8 |
| `.github/workflows/*.yml` | Solution filename, SonarCloud key, artifact paths, scanned binary names. | 8 |
| `README.md`, `docs/**`, `SECURITY_REVIEW.md` | Prose, tables, paths, URLs. | 9 |

---

## Task 1: Rename verification harness

This is the acceptance test for the whole plan. It must exist and **fail** before any renaming begins, so that later tasks have an objective definition of done.

**Files:**
- Create: `tools/Verify-Rename.ps1`

**Interfaces:**
- Produces: a script invoked as `pwsh -File tools/Verify-Rename.ps1`. Exit code 0 = clean, 1 = forbidden token still present. Every subsequent task re-runs this.

- [ ] **Step 1: Write the verification script**

Create `tools/Verify-Rename.ps1`:

```powershell
<#
.SYNOPSIS
  Acceptance test for the OpenAccess EID rename.
.DESCRIPTION
  Asserts that the legacy token "EIDAuthentication" appears nowhere in
  git-tracked file contents or filenames. Only tracked files are checked:
  build outputs under x64/ and the sonarqube_issues/ dumps are regenerated
  artefacts and are deliberately out of scope.

  The bare token "EID" is explicitly ALLOWED and must not be flagged -
  EIDCardLibrary, EIDCredentialProvider, the L$_EID_ LSA secret prefix and
  friends are all retained by design.
#>
[CmdletBinding()]
param(
    # Set to check a token other than the default (used by the self-test).
    [string]$ForbiddenToken = 'EIDAuthentication'
)

$ErrorActionPreference = 'Stop'
$failed = $false

Write-Host "Verifying absence of '$ForbiddenToken' in tracked files..." -ForegroundColor Cyan

# --- 1. Filenames -----------------------------------------------------------
$badNames = @(git ls-files | Where-Object { $_ -like "*$ForbiddenToken*" })
if ($badNames.Count -gt 0) {
    $failed = $true
    Write-Host "FAIL: $($badNames.Count) tracked path(s) still contain '$ForbiddenToken':" -ForegroundColor Red
    $badNames | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
} else {
    Write-Host "PASS: no tracked path contains '$ForbiddenToken'." -ForegroundColor Green
}

# --- 2. File contents -------------------------------------------------------
# git grep is used rather than Select-String so the tracked-file set and the
# search set are guaranteed identical.
$hits = @(git grep -n --fixed-strings $ForbiddenToken -- ':!tools/Verify-Rename.ps1' 2>$null)
if ($hits.Count -gt 0) {
    $failed = $true
    $fileCount = ($hits | ForEach-Object { ($_ -split ':')[0] } | Sort-Object -Unique).Count
    Write-Host "FAIL: $($hits.Count) occurrence(s) of '$ForbiddenToken' across $fileCount file(s):" -ForegroundColor Red
    $hits | Select-Object -First 40 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    if ($hits.Count -gt 40) { Write-Host "  ... and $($hits.Count - 40) more" -ForegroundColor Red }
} else {
    Write-Host "PASS: no tracked file contains '$ForbiddenToken'." -ForegroundColor Green
}

# --- 3. Guard rails: things that MUST still be present -----------------------
# A careless global search-and-replace could destroy these. Their absence is a
# worse failure than the rename being incomplete, so check them explicitly.
$mustExist = @{
    'L$_EID_ LSA secret prefix'      = 'EIDCardLibrary/StoredCredentialManagement.cpp'
    'EIDCardLibrary project'         = 'EIDCardLibrary/EIDCardLibrary.vcxproj'
    'EIDCredentialProvider project'  = 'EIDCredentialProvider/EIDCredentialProvider.vcxproj'
}
foreach ($entry in $mustExist.GetEnumerator()) {
    if (-not (Test-Path $entry.Value)) {
        $failed = $true
        Write-Host "FAIL: expected to still exist, but missing: $($entry.Key) ($($entry.Value))" -ForegroundColor Red
    }
}
$prefixHit = @(git grep -c --fixed-strings 'L"L$_EID_"' -- 'EIDCardLibrary/StoredCredentialManagement.cpp' 2>$null)
if ($prefixHit.Count -eq 0) {
    $failed = $true
    Write-Host 'FAIL: CREDENTIAL_LSAPREFIX L"L$_EID_" is missing - existing enrollments would be orphaned.' -ForegroundColor Red
} else {
    Write-Host 'PASS: CREDENTIAL_LSAPREFIX intact.' -ForegroundColor Green
}

if ($failed) { Write-Host "`nVERIFICATION FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`nVERIFICATION PASSED" -ForegroundColor Green
exit 0
```

- [ ] **Step 2: Run it to confirm it FAILS**

Run: `pwsh -File tools/Verify-Rename.ps1`

Expected: exit code 1, reporting roughly **39** files containing the token and **12** tracked paths matching it (the `EIDAuthenticationPackage/` directory contributes several). The three guard-rail PASS lines must appear. If the guard rails fail at this point the script is wrong — fix it before continuing.

- [ ] **Step 3: Self-test the harness against a token that is definitely absent**

Run: `pwsh -File tools/Verify-Rename.ps1 -ForbiddenToken 'ZzzNotPresentZzz'`

Expected: exit code 0, "VERIFICATION PASSED". This proves the script can pass and is not hard-wired to fail.

- [ ] **Step 4: Commit**

```bash
git add tools/Verify-Rename.ps1
git commit -m "test(rename): add OpenAccess EID rename verification harness

Fails today by design: 39 tracked files still contain EIDAuthentication.
Guards that CREDENTIAL_LSAPREFIX and the retained EID* projects survive,
because a careless global replace would orphan every enrollment."
```

---

## Task 2: LSA package name constants and registration

**Files:**
- Modify: `EIDCardLibrary/EIDCardLibrary.h:31-33`
- Modify: `EIDCardLibrary/Registration.cpp:278-286`

**Interfaces:**
- Consumes: nothing.
- Produces: `AUTHENTICATIONPACKAGENAME` / `AUTHENTICATIONPACKAGENAMEW` / `AUTHENTICATIONPACKAGENAMET` now expand to `OpenAccessEIDPackage`. Task 3 renames the DLL that this name must match. Task 7 consumes the new legacy constants for cleanup.

- [ ] **Step 1: Update the three name constants**

In `EIDCardLibrary/EIDCardLibrary.h`, replace lines 31-33:

```cpp
constexpr const char* AUTHENTICATIONPACKAGENAME = "OpenAccessEIDPackage";
constexpr const wchar_t* AUTHENTICATIONPACKAGENAMEW = L"OpenAccessEIDPackage";
#define AUTHENTICATIONPACKAGENAMET TEXT("OpenAccessEIDPackage")  // NOSONAR - MACRO-02: TEXT() requires macro context

// Legacy name from releases up to v1.2.00. Retained solely so the installer and
// uninstaller can strip stale entries out of the LSA multi-sz values. An entry
// naming a DLL that no longer exists in System32 is a machine that may fail to
// authenticate, so this must outlive the rename.
#define LEGACY_AUTHENTICATIONPACKAGENAMET TEXT("EIDAuthenticationPackage")  // NOSONAR - MACRO-02: TEXT() requires macro context
```

Only the `TEXT()` form is defined because only `RemoveValueFromMultiSz` consumes it. Do not add unused `char`/`wchar_t` variants for symmetry.

Note: the two legacy constants intentionally contain the forbidden token. Task 12 adds the single allow-listed exception for them; until then `Verify-Rename.ps1` will still report this file, which is expected.

- [ ] **Step 2: Add legacy cleanup to deregistration**

In `EIDCardLibrary/Registration.cpp`, immediately after the two existing `RemoveValueFromMultiSz` calls at lines 285-286, add:

```cpp
	// Strip the pre-v2.0.00 package name too. Upgrading without first running the
	// old uninstaller would otherwise leave LSA referencing EIDAuthenticationPackage.dll
	// after that file has been deleted.
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
```

- [ ] **Step 3: Also strip the legacy entries during registration**

In `EIDCardLibrary/Registration.cpp`, immediately **before** the two `AppendValueToMultiSz` calls at lines 278-280, add:

```cpp
	// Remove any stale pre-v2.0.00 entry before adding the new one, so an in-place
	// upgrade cannot leave both names registered.
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
```

- [ ] **Step 4: Build**

Run: `.\build.ps1 Debug x64`

Expected: `Rebuild All: 10 succeeded, 0 failed`. The DLL is still emitted as `EIDAuthenticationPackage.dll` at this point — Task 3 renames it. That mismatch is expected and temporary; do not ship between Task 2 and Task 3.

- [ ] **Step 5: Commit**

```bash
git add EIDCardLibrary/EIDCardLibrary.h EIDCardLibrary/Registration.cpp
git commit -m "refactor(rename): LSA package name becomes OpenAccessEIDPackage

Adds LEGACY_AUTHENTICATIONPACKAGENAME* and strips the old entry from the
Lsa Security/Authentication Packages multi-sz values on both register and
deregister. An entry naming a deleted DLL risks a machine that cannot
authenticate, so cleanup must not depend on the old uninstaller running."
```

---

## Task 3: Rename the authentication package project

**Files:**
- Rename: `EIDAuthenticationPackage/` → `OpenAccessEIDPackage/`
- Rename: `OpenAccessEIDPackage/EIDAuthenticationPackage.{cpp,def,vcproj,vcxproj,vcxproj.filters}` → `OpenAccessEIDPackage.*`
- Modify: `EIDCredentialProvider.sln:13`
- Modify: `OpenAccessEIDPackage/OpenAccessEIDPackage.vcxproj` (RootNamespace, ProjectName, TargetName, ModuleDefinitionFile)
- Modify: `OpenAccessEIDPackage/OpenAccessEIDPackage.def:1-2`
- Modify: `OpenAccessEIDPackage/resources.rc` (version resource strings)

**Interfaces:**
- Consumes: `AUTHENTICATIONPACKAGENAME` from Task 2 — the built DLL filename must equal that constant plus `.dll`.
- Produces: `x64\<Config>\OpenAccessEIDPackage.dll`. Tasks 6 and 8 reference this filename.

- [ ] **Step 1: Rename directory and files with git mv**

```bash
git mv EIDAuthenticationPackage OpenAccessEIDPackage
cd OpenAccessEIDPackage
for ext in cpp def vcproj vcxproj vcxproj.filters; do
  git mv "EIDAuthenticationPackage.$ext" "OpenAccessEIDPackage.$ext"
done
cd ..
```

- [ ] **Step 2: Update the solution's project entry**

In `EIDCredentialProvider.sln`, replace line 13 entirely:

```
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "OpenAccessEIDPackage", "OpenAccessEIDPackage\OpenAccessEIDPackage.vcxproj", "{4711AF6D-0E6C-4D71-9238-053FB0B287DA}"
```

The project GUID `{4711AF6D-...}` is unchanged — it is an opaque identifier and every `ProjectConfigurationPlatforms` entry references it.

- [ ] **Step 3: Update project settings**

In `OpenAccessEIDPackage/OpenAccessEIDPackage.vcxproj`, replace every occurrence of `EIDAuthenticationPackage` with `OpenAccessEIDPackage`. This covers `<RootNamespace>`, `<ProjectName>` if present, `<TargetName>`, and `<ModuleDefinitionFile>`. Do the same in `OpenAccessEIDPackage.vcxproj.filters`.

Verify the module definition reference specifically:

```bash
grep -n "ModuleDefinitionFile" OpenAccessEIDPackage/OpenAccessEIDPackage.vcxproj
```

Expected: `<ModuleDefinitionFile>OpenAccessEIDPackage.def</ModuleDefinitionFile>`

- [ ] **Step 4: Update the .def library name**

`OpenAccessEIDPackage/OpenAccessEIDPackage.def` begins with a `LIBRARY` line. Ensure it reads:

```
LIBRARY

EXPORTS
```

If a library name follows `LIBRARY`, replace it with `OpenAccessEIDPackage`. Leave the `EXPORTS` list untouched — those are Windows-defined entry points (`LsaApCallPackage`, `SpInitialize`, and so on) and renaming any of them breaks LSA.

- [ ] **Step 5: Update remaining in-file references**

```bash
grep -rn "EIDAuthenticationPackage" OpenAccessEIDPackage/
```

Replace each hit with `OpenAccessEIDPackage`, including `EIDAuthenticationPackageDllRegister` → `OpenAccessEIDPackageDllRegister` and `EIDAuthenticationPackageDllUnRegister` → `OpenAccessEIDPackageDllUnRegister`. Then update the declarations of those two functions:

```bash
grep -rn "EIDAuthenticationPackageDll" --include=*.h --include=*.cpp .
```

Replace in `EIDCardLibrary/Registration.h` and `EIDCardLibrary/Registration.cpp` as well.

- [ ] **Step 6: Build**

Run: `.\build.ps1 Debug x64`

Expected: `Rebuild All: 10 succeeded, 0 failed`, and the output listing now shows `OpenAccessEIDPackage.dll` in place of `EIDAuthenticationPackage.dll`.

- [ ] **Step 7: Confirm the DLL name matches the LSA constant**

```bash
ls x64/Debug/OpenAccessEIDPackage.dll
grep -n 'AUTHENTICATIONPACKAGENAME =' EIDCardLibrary/EIDCardLibrary.h
```

Expected: the file exists and the constant reads `"OpenAccessEIDPackage"`. These must agree exactly — LSA loads `<name>.dll` from System32 by this name.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(rename): EIDAuthenticationPackage project becomes OpenAccessEIDPackage

Directory, five name-bearing files, solution entry, project settings, .def
and the two Dll(Un)Register exports. Project GUID and the Windows-defined
export list are unchanged."
```

---

## Task 4: ProgramData paths and LogManager registry keys

**Files:**
- Modify: `EIDCardLibrary/CSVConfig.h:218-223`
- Modify: `EIDTraceConsumer/EIDTraceConsumer.cpp` (duplicated default path and policy key)
- Modify: `EIDCardLibrary/Registration.cpp` (trace config key, if it names the project)

**Interfaces:**
- Consumes: nothing.
- Produces: `EID_CSV_CONFIG_DIR`, `EID_CSV_CONFIG_PATH`, `EID_CSV_DEFAULT_LOG_PATH`, `EID_CSV_CONFIG_KEY`, `EID_CSV_POLICY_KEY` all pointing at `OpenAccessEID`. Task 6 migrates existing data to these locations; Task 5 must use the same policy key in the ADMX.

- [ ] **Step 1: Update the path and key macros**

In `EIDCardLibrary/CSVConfig.h`, replace lines 218-223:

```cpp
#define EID_CSV_CONFIG_DIR          L"C:\\ProgramData\\OpenAccessEID"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_CSV_CONFIG_PATH         L"C:\\ProgramData\\OpenAccessEID\\logging.json"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_CSV_DEFAULT_LOG_PATH    L"C:\\ProgramData\\OpenAccessEID\\logs\\events.csv"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_CSV_CONFIG_KEY          L"SOFTWARE\\OpenAccessEID\\LogManager"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
// Group Policy key: values present here override the local file/registry config (ADMX-managed).
#define EID_CSV_POLICY_KEY          L"SOFTWARE\\Policies\\OpenAccessEID\\LogManager"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
```

- [ ] **Step 2: Update the trace consumer's duplicated literals**

`EIDTraceConsumer` deliberately has no include path to `EIDCardLibrary`, so it repeats these strings. Find them:

```bash
grep -n "ProgramData\|Policies\\\\\\\\EIDAuthentication\|EIDAuthentication" EIDTraceConsumer/EIDTraceConsumer.cpp
```

Replace every `EIDAuthentication` with `OpenAccessEID` in that file. Both the fallback diagnostics path (`C:\\ProgramData\\...\\logs\\diagnostics.log`) and the policy key must match `CSVConfig.h` exactly — they are read by the same GPO.

- [ ] **Step 3: Sweep the remaining C++ sources**

```bash
git grep -n "EIDAuthentication" -- '*.cpp' '*.h'
```

Replace every remaining hit per the mapping table, **except** the two `LEGACY_AUTHENTICATIONPACKAGENAME*` constants added in Task 2, which must keep the old spelling.

- [ ] **Step 4: Build**

Run: `.\build.ps1 Debug x64`

Expected: `Rebuild All: 10 succeeded, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(rename): ProgramData path and LogManager registry keys

C:\\ProgramData\\OpenAccessEID, HKLM\\SOFTWARE\\OpenAccessEID\\LogManager and
the matching Policies key. EIDTraceConsumer's duplicated literals updated in
lockstep - they are read by the same GPO and must not drift."
```

---

## Task 5: Group Policy template

Renaming the ADMX namespace **orphans any deployed Group Policy**. Administrators must re-import the template and re-apply settings. Task 9 documents this; this task performs it.

**Files:**
- Rename: `Installer/PolicyDefinitions/EIDAuthentication.admx` → `OpenAccessEID.admx`
- Rename: `Installer/PolicyDefinitions/en-US/EIDAuthentication.adml` → `en-US/OpenAccessEID.adml`
- Modify: both files' contents

**Interfaces:**
- Consumes: `EID_CSV_POLICY_KEY` from Task 4 — every `key=` attribute must equal `SOFTWARE\Policies\OpenAccessEID\LogManager`.
- Produces: template filenames referenced by the installer in Task 6.

- [ ] **Step 1: Rename both files**

```bash
git mv Installer/PolicyDefinitions/EIDAuthentication.admx Installer/PolicyDefinitions/OpenAccessEID.admx
git mv Installer/PolicyDefinitions/en-US/EIDAuthentication.adml Installer/PolicyDefinitions/en-US/OpenAccessEID.adml
```

- [ ] **Step 2: Update the namespace and prefix**

In `Installer/PolicyDefinitions/OpenAccessEID.admx`, replace line 17:

```xml
    <target prefix="oaeid" namespace="OpenAccessEID.Policies" />
```

- [ ] **Step 3: Update the registry keys and category id**

In the same file, replace every `SOFTWARE\Policies\EIDAuthentication\LogManager` with `SOFTWARE\Policies\OpenAccessEID\LogManager`, and every `Cat_EIDAuthentication` with `Cat_OpenAccessEID`.

```bash
grep -n "EIDAuthentication" Installer/PolicyDefinitions/OpenAccessEID.admx
```

Expected after editing: no output.

- [ ] **Step 4: Update the ADML strings**

In `Installer/PolicyDefinitions/en-US/OpenAccessEID.adml`, replace `Cat_EIDAuthentication` with `Cat_OpenAccessEID`, update the category display string to `OpenAccess EID`, and replace every `HKLM\SOFTWARE\Policies\EIDAuthentication\LogManager` in the help text with the new key.

```bash
grep -n "EIDAuthentication" Installer/PolicyDefinitions/en-US/OpenAccessEID.adml
```

Expected after editing: no output.

- [ ] **Step 5: Verify ADMX/ADML consistency**

Every `$(string.X)` and `$(presentation.X)` in the ADMX must resolve to a definition in the ADML, and every `<decimal|text|enum>` `id` must have a matching `refId`:

```bash
python - <<'PY'
import re, io
admx = io.open('Installer/PolicyDefinitions/OpenAccessEID.admx', encoding='utf-8').read()
adml = io.open('Installer/PolicyDefinitions/en-US/OpenAccessEID.adml', encoding='utf-8').read()
refs = set(re.findall(r'\$\((?:string|presentation)\.([A-Za-z0-9_]+)\)', admx))
defs = set(re.findall(r'<(?:string|presentation) id="([A-Za-z0-9_]+)"', adml))
missing = sorted(refs - defs)
orphan  = sorted(defs - refs)
ids    = set(re.findall(r'<(?:decimal|text|enum|boolean)\s+id="([A-Za-z0-9_]+)"', admx))
refids = set(re.findall(r'refId="([A-Za-z0-9_]+)"', adml))
print('missing string/presentation definitions:', missing or 'none')
print('orphaned definitions:', orphan or 'none')
print('elements with no refId:', sorted(ids - refids) or 'none')
assert not missing, missing
assert not (ids - refids), ids - refids
print('ADMX/ADML CONSISTENT')
PY
```

Expected: `ADMX/ADML CONSISTENT`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(rename): Group Policy template becomes OpenAccessEID

Filenames, namespace OpenAccessEID.Policies, prefix oaeid, category id and
every policy key. BREAKING: deployed GPO under the old namespace is orphaned
and must be re-imported and re-applied."
```

---

## Task 6: Installer — names, paths and registry

**Files:**
- Modify: `Installer/Installerx64.nsi`

**Interfaces:**
- Consumes: `OpenAccessEIDPackage.dll` (Task 3), the ADMX filenames (Task 5), the new ProgramData and registry locations (Task 4).
- Produces: an installer writing to `$PROGRAMFILES64\OpenAccess EID` and `HKLM\Software\OpenAccessEID`. Task 7 adds migration on top.

- [ ] **Step 1: Update product identity**

In `Installer/Installerx64.nsi`:

- Line 14: `Name "OpenAccess EID"`
- Line 22: `InstallDir "$PROGRAMFILES64\OpenAccess EID"`
- Line 173 onward: replace every `$SMPROGRAMS\EID Authentication` with `$SMPROGRAMS\OpenAccess EID`

- [ ] **Step 2: Update binary and template filenames**

Replace every `EIDAuthenticationPackage.dll` with `OpenAccessEIDPackage.dll` (covers `$INSTDIR\`, `$SYSDIR\` and `..\x64\Release\` forms), every `EIDAuthentication.admx` with `OpenAccessEID.admx`, and every `EIDAuthentication.adml` with `OpenAccessEID.adml`.

- [ ] **Step 3: Update registry locations**

Replace `Software\EIDAuthentication` with `Software\OpenAccessEID`, `Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication` with `...\Uninstall\OpenAccessEID`, and the `EIDAuthentication\LsaProtectionBackup` path with `OpenAccessEID\LsaProtectionBackup`.

Set the uninstall display name explicitly:

```nsis
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "DisplayName" "OpenAccess EID"
```

- [ ] **Step 4: Verify no legacy token remains**

```bash
grep -n "EIDAuthentication" Installer/Installerx64.nsi
```

Expected: no output. (Task 7 reintroduces the token deliberately, inside clearly-marked migration blocks.)

- [ ] **Step 5: Commit**

```bash
git add Installer/Installerx64.nsi
git commit -m "refactor(rename): installer product name, paths and registry

OpenAccess EID display name, \$PROGRAMFILES64\\OpenAccess EID, Start Menu
folder, OpenAccessEIDPackage.dll, OpenAccessEID.admx/.adml and the Software,
Uninstall and LsaProtectionBackup keys."
```

---

## Task 7: Upgrade migration from v1.2.00 and earlier

The highest-risk task. A machine that has v1.2.00 installed has: the legacy package name in two LSA multi-sz values, `EIDAuthenticationPackage.dll` in System32, config and logs under the old ProgramData path, and settings under the old registry keys. All must be dealt with in one pass, and a reboot is mandatory because LSA only re-reads its package list at boot.

**Files:**
- Modify: `Installer/Installerx64.nsi` (migration block in the install section, plus reboot flag)

**Interfaces:**
- Consumes: `LEGACY_AUTHENTICATIONPACKAGENAME*` behaviour from Task 2 (the DLL itself strips the stale entries when `DllUnRegister` runs); this task handles the case where the old uninstaller never runs.
- Produces: a clean upgrade path. Task 11 validates it on the VM.

- [ ] **Step 1: Add the migration block**

In `Installer/Installerx64.nsi`, inside the main install section **before** the new package is registered, insert:

```nsis
  ;--------------------------------------------------------------------
  ; Migration from EID Authentication (v1.2.00 and earlier).
  ;
  ; Ordering matters. The stale LSA entry must go before the old DLL is
  ; deleted: LSA loads Authentication Packages by name from System32 at
  ; boot, so a name with no file behind it can leave the machine unable
  ; to authenticate. A reboot is mandatory either way - LSA reads that
  ; list only at boot.
  ;--------------------------------------------------------------------
  DetailPrint "Checking for a previous EID Authentication installation..."

  SetRegView 64
  ClearErrors
  ReadRegStr $R0 HKLM "Software\EIDAuthentication" "InstallPath"
  ${IfNot} ${Errors}
    DetailPrint "Found previous installation at $R0 - migrating."

    ; 1. Deregister the legacy LSA package while its DLL is still present.
    ${If} ${FileExists} "$SYSDIR\EIDAuthenticationPackage.dll"
      DetailPrint "Deregistering legacy authentication package..."
      ExecWait 'rundll32.exe "$SYSDIR\EIDAuthenticationPackage.dll",DllUnRegister'
    ${EndIf}

    ; 2. Carry settings across before the old keys are removed.
    DetailPrint "Migrating configuration..."
    ReadRegDWORD $R1 HKLM "SOFTWARE\EIDAuthentication\LogManager" "CSVEnabled"
    ${IfNot} ${Errors}
      WriteRegDWORD HKLM "SOFTWARE\OpenAccessEID\LogManager" "CSVEnabled" $R1
    ${EndIf}
    ClearErrors
    ReadRegDWORD $R1 HKLM "SOFTWARE\EIDAuthentication\LogManager" "CSVMaxFileSize"
    ${IfNot} ${Errors}
      WriteRegDWORD HKLM "SOFTWARE\OpenAccessEID\LogManager" "CSVMaxFileSize" $R1
    ${EndIf}
    ClearErrors
    ReadRegDWORD $R1 HKLM "SOFTWARE\EIDAuthentication\LogManager" "CSVFileCount"
    ${IfNot} ${Errors}
      WriteRegDWORD HKLM "SOFTWARE\OpenAccessEID\LogManager" "CSVFileCount" $R1
    ${EndIf}
    ClearErrors

    ; 3. Move logs and config. CopyFiles then RMDir: a failed move must not
    ;    destroy an administrator's audit trail.
    ${If} ${FileExists} "$APPDATA\..\..\ProgramData\EIDAuthentication\*.*"
      CreateDirectory "C:\ProgramData\OpenAccessEID"
      CopyFiles /SILENT "C:\ProgramData\EIDAuthentication\*.*" "C:\ProgramData\OpenAccessEID"
      RMDir /r "C:\ProgramData\EIDAuthentication"
      DetailPrint "Moved logs and configuration to C:\ProgramData\OpenAccessEID."
    ${EndIf}

    ; 4. Remove the legacy binary and registry footprint.
    Delete "$SYSDIR\EIDAuthenticationPackage.dll"
    Delete "$WINDIR\PolicyDefinitions\EIDAuthentication.admx"
    Delete "$WINDIR\PolicyDefinitions\en-US\EIDAuthentication.adml"
    DeleteRegKey HKLM "Software\EIDAuthentication"
    DeleteRegKey HKLM "SOFTWARE\EIDAuthentication\LogManager"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"
    RMDir /r "$SMPROGRAMS\EID Authentication"

    SetRebootFlag true
    DetailPrint "Migration complete. A reboot is required."
  ${EndIf}
```

- [ ] **Step 2: Warn about orphaned Group Policy**

Immediately after the migration block, add:

```nsis
  ${If} ${RebootFlag}
    MessageBox MB_OK|MB_ICONEXCLAMATION "Upgrading from EID Authentication.$\n$\n\
Group Policy settings under the old EIDAuthentication namespace are NOT carried over. \
After rebooting, re-import the OpenAccess EID administrative template and re-apply any \
logging policies.$\n$\n\
Smart-card enrollments are preserved - users do not need to re-enrol."
  ${EndIf}
```

The reassurance about enrollments is accurate precisely because `CREDENTIAL_LSAPREFIX` is unchanged. If a future change ever alters that prefix, this message becomes a lie and must be revisited.

- [ ] **Step 3: Confirm the token appears only inside migration code**

```bash
grep -n "EIDAuthentication" Installer/Installerx64.nsi
```

Expected: hits only within the migration block and the warning message. Every one must be a *legacy* reference — reading or deleting old state — never writing new state.

- [ ] **Step 4: Commit**

```bash
git add Installer/Installerx64.nsi
git commit -m "feat(rename): migrate installs from EID Authentication v1.2.00

Deregisters the legacy LSA package before deleting its DLL (a registered
name with no file can leave a machine unable to authenticate), carries
LogManager settings across, moves ProgramData with copy-then-delete, clears
the old registry footprint and forces a reboot.

Warns that GPO under the old namespace is orphaned. Enrollments survive
because CREDENTIAL_LSAPREFIX is deliberately unchanged."
```

---

## Task 8: Solution, build script and CI

**Files:**
- Rename: `EIDCredentialProvider.sln` → `OpenAccessEID.sln`
- Modify: `build.ps1`
- Modify: `.github/workflows/windows-ci.yaml`, `codeql.yml`, `scan-artifacts.yml`, `pr-report.yml`, `release-vt-scan.yml`, `aikido-badges.yml`

**Interfaces:**
- Consumes: `OpenAccessEIDPackage.dll` from Task 3.
- Produces: a green CI build under the new names.

- [ ] **Step 1: Rename the solution**

```bash
git mv EIDCredentialProvider.sln OpenAccessEID.sln
```

- [ ] **Step 2: Update build.ps1**

```bash
grep -n "EIDCredentialProvider.sln\|EIDAuthenticationPackage" build.ps1
```

Replace `EIDCredentialProvider.sln` with `OpenAccessEID.sln` and `EIDAuthenticationPackage.dll` with `OpenAccessEIDPackage.dll` (the latter appears in the output listing and the SHA-256 manifest target list).

- [ ] **Step 3: Update the workflows**

```bash
git grep -n "EIDCredentialProvider.sln\|EIDAuthenticationPackage\|DangerDawgAU_EIDAuthentication\|DangerDawgAU/EIDAuthentication" -- .github/
```

Replace per the mapping table. Note `scan-artifacts.yml` enumerates binary names explicitly — `EIDAuthenticationPackage.dll` must become `OpenAccessEIDPackage.dll` there or the scan silently misses the file.

- [ ] **Step 4: Build**

Run: `.\build.ps1 Debug x64`

Expected: `Rebuild All: 10 succeeded, 0 failed` with `OpenAccessEIDPackage.dll` listed.

- [ ] **Step 5: Validate every workflow still parses**

```bash
python - <<'PY'
import yaml, io, glob
for f in sorted(glob.glob('.github/workflows/*.y*ml')):
    yaml.safe_load(io.open(f, encoding='utf-8'))
    print('OK', f)
PY
```

Expected: `OK` for each file.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "build(rename): OpenAccessEID.sln, build.ps1 and CI workflows

Includes the explicit binary list in scan-artifacts.yml, which would
silently skip the renamed DLL otherwise, and the SonarCloud project key."
```

---

## Task 9: Documentation

**Files:**
- Modify: `README.md`, `SECURITY_REVIEW.md`, `docs/VM_TEST_PLAN.md`, `docs/BETA_RELEASE_NOTES.md`, and every other tracked `.md`

**Interfaces:**
- Consumes: the final names from Tasks 2-8.
- Produces: documentation matching shipped behaviour.

- [ ] **Step 1: Enumerate**

```bash
git grep -ln "EIDAuthentication\|EID Authentication" -- '*.md'
```

- [ ] **Step 2: Replace throughout**

Apply the mapping table. Take care with:

- GitHub URLs — `github.com/DangerDawgAU/EIDAuthentication` → `.../OpenAccessEID`
- Badge image and target URLs, including the `badges` branch JSON paths
- The component table listing `EIDAuthenticationPackage.dll`
- Registry and path tables in the Group Policy section
- The Code Signing section, which names the LSA-loaded binaries

- [ ] **Step 3: Add an upgrade section to README.md**

Insert after the Components section:

```markdown
## Upgrading from EID Authentication (v1.2.00 and earlier)

This project was renamed to **OpenAccess EID** at v2.0.00. The installer migrates an
existing installation automatically and **requires a reboot** — the Windows LSA reads
its authentication-package list only at boot.

**Smart-card enrollments are preserved.** Stored credentials are untouched by the
rename, so users do not re-enrol.

Three things do not carry over and need administrator action:

| Item | Action |
|---|---|
| Group Policy | Re-import the `OpenAccessEID.admx` template and re-apply logging policies. Settings under the old `EIDAuthentication.Policies` namespace are orphaned. |
| Log and config location | Moved to `C:\ProgramData\OpenAccessEID`. Anything reading the old path — a SIEM collector, a scheduled task — must be re-pointed. |
| Scripts referencing binaries | `EIDAuthenticationPackage.dll` is now `OpenAccessEIDPackage.dll`. |
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(rename): OpenAccess EID throughout, plus an upgrade guide

Documents the three things migration cannot carry: Group Policy under the
old namespace, the ProgramData location, and the renamed package DLL."
```

---

## Task 10: Final sweep and verification

**Files:**
- Modify: `tools/Verify-Rename.ps1` (allow-list the two legacy constants)

- [ ] **Step 1: Find whatever remains**

```bash
git grep -n "EIDAuthentication"
```

Expected remaining hits, and nothing else:
1. `EIDCardLibrary/EIDCardLibrary.h` — the two `LEGACY_AUTHENTICATIONPACKAGENAME*` constants
2. `EIDCardLibrary/Registration.cpp` — comments referring to the legacy name
3. `Installer/Installerx64.nsi` — the migration block and its warning
4. `README.md` — the upgrade section
5. `docs/superpowers/plans/2026-07-25-openaccess-eid-rename.md` — this plan

Anything else is an omission. Fix it before proceeding.

- [ ] **Step 2: Allow-list the legitimate survivors**

In `tools/Verify-Rename.ps1`, replace the `git grep` on line ~35 with:

```powershell
# Legacy references are legitimate in exactly four places: the constants used to
# clean up a pre-v2.0.00 install, the installer's migration block, the upgrade
# documentation, and this rename plan. Everything else is an omission.
$allowed = @(
    ':!tools/Verify-Rename.ps1',
    ':!EIDCardLibrary/EIDCardLibrary.h',
    ':!EIDCardLibrary/Registration.cpp',
    ':!Installer/Installerx64.nsi',
    ':!README.md',
    ':!docs/superpowers/plans/*'
)
$hits = @(git grep -n --fixed-strings $ForbiddenToken -- $allowed 2>$null)
```

Use `$allowed`, not `@allowed`. Splatting syntax applies to cmdlet parameters; for a native executable like `git`, a plain array variable is expanded into separate arguments, which is what is wanted here.

- [ ] **Step 3: Run the harness**

Run: `pwsh -File tools/Verify-Rename.ps1`

Expected: `VERIFICATION PASSED`, exit 0, with all three guard-rail PASS lines — in particular `CREDENTIAL_LSAPREFIX intact`.

- [ ] **Step 4: Full clean build**

Run: `.\build.ps1 Debug x64`

Expected: `Rebuild All: 10 succeeded, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore(rename): final sweep; harness passes

Allow-lists the four places a legacy reference is correct: the cleanup
constants, the installer migration, the upgrade guide and the plan."
```

---

## Task 11: Runtime validation on the VM

**No code changes.** The rename touches the LSA authentication package, which gates every logon on the machine. A build that compiles proves nothing here.

- [ ] **Step 1: Release build**

Run: `.\build.ps1 Release x64`

Expected: build succeeds, `Installer\EIDInstallx64.exe` produced, `SHA256SUMS.txt` regenerated listing `OpenAccessEIDPackage.dll`.

- [ ] **Step 2: Upgrade test — the critical path**

On a VM with **v1.2.00 already installed and an enrolled YubiKey**:

1. Run the new installer.
2. Confirm the migration prompt appears and mentions Group Policy.
3. Reboot when prompted.
4. **Log on with the YubiKey.**

Expected: logon succeeds without re-enrolment. This proves `CREDENTIAL_LSAPREFIX` was genuinely left alone and that the LSA package swap completed.

If logon fails, check in this order:

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages"
Test-Path "$env:SystemRoot\System32\OpenAccessEIDPackage.dll"
Test-Path "$env:SystemRoot\System32\EIDAuthenticationPackage.dll"
```

The lists must contain `OpenAccessEIDPackage` and **not** `EIDAuthenticationPackage`, and only the new DLL should exist. A stale name with no file behind it is the predicted failure mode.

- [ ] **Step 3: Clean install test**

On a clean VM: install, reboot, enrol a card, log on. Confirm logs appear under `C:\ProgramData\OpenAccessEID\logs\events.csv`.

- [ ] **Step 4: Group Policy test**

Copy `OpenAccessEID.admx` / `.adml` into `%WINDIR%\PolicyDefinitions`, open `gpedit.msc`, confirm the **OpenAccess EID** category appears with all logging policies, set one, and confirm it is written under `HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager`.

- [ ] **Step 5: Uninstall test**

Uninstall, reboot, confirm both LSA lists are clean and the machine still logs on with a password.

- [ ] **Step 6: Record results**

Append outcomes to `docs/VM_TEST_PLAN.md` and commit.

```bash
git add docs/VM_TEST_PLAN.md
git commit -m "test(rename): record VM validation results for the OpenAccess EID rename"
```

---

## Task 12: Repository rename and external integrations

**Do this last.** Renaming the repo mid-flight breaks CI badges and integrations while work is in progress.

**Stars, watchers, issues, PRs, releases and history are all preserved** by a GitHub rename, and redirects are created automatically. The only way to lose them is creating a new repository — never do that.

- [ ] **Step 1: Merge to main first**

Open a PR from `rename/openaccess-eid`, confirm all checks pass, and merge. The rename must land on `main` before the repository is renamed.

- [ ] **Step 2: Rename the repository**

```bash
gh repo rename OpenAccessEID --repo DangerDawgAU/EIDAuthentication
```

Then confirm nothing was lost:

```bash
gh repo view DangerDawgAU/OpenAccessEID --json nameWithOwner,stargazerCount,forkCount --jq '{name:.nameWithOwner,stars:.stargazerCount,forks:.forkCount}'
```

Expected: `stars: 5` (or higher). If stars are 0, stop — a new repo was created instead of a rename.

**Never re-create a repository named `EIDAuthentication` under this account.** Doing so silently breaks every redirect from the old URL.

- [ ] **Step 3: Update the local remote**

```bash
git remote set-url origin https://github.com/DangerDawgAU/OpenAccessEID.git
git remote -v
```

- [ ] **Step 4: Re-point external services**

- **SonarCloud:** create/rename the project to key `DangerDawgAU_OpenAccessEID`; confirm `sonar.projectKey` in CI matches.
- **Aikido:** confirm the repository still resolves; refresh the `AIKIDO_CODE_REPO_ID` repository variable if its ID changed.
- **Badges branch:** confirm the JSON on the `badges` branch is still written and read at the new URLs.

- [ ] **Step 5: Verify CI end-to-end**

Push a trivial commit to `main` and confirm every check passes: `build`, `CodeQL`, `Aikido Security`, `SonarCloud`.

- [ ] **Step 6: Release v2.0.00**

Tag and publish as a **prerelease** first, exactly as v1.2.00 was handled, and promote only after the upgrade test in Task 11 has been repeated against the published artifacts.

Write the notes to a file first — they must lead with the rename, the mandatory reboot, the preserved enrollments and the orphaned Group Policy:

```bash
cat > /tmp/v2-notes.md <<'EOF'
> **Prerelease.** Build-verified and code-reviewed; promote only after the upgrade
> test on a machine with v1.2.00 and an enrolled card has passed.

**This project has been renamed from EID Authentication to OpenAccess EID.**

### Upgrading

The installer migrates an existing v1.2.00 installation and **requires a reboot** —
Windows reads its LSA authentication-package list only at boot.

**Smart-card enrollments are preserved.** Stored credentials are untouched by the
rename, so users do not need to re-enrol.

Three things need administrator action after upgrading:

| Item | Action |
|---|---|
| Group Policy | Re-import the `OpenAccessEID.admx` template and re-apply logging policies. Settings under the old `EIDAuthentication.Policies` namespace are orphaned. |
| Logs and config | Moved to `C:\ProgramData\OpenAccessEID`. Re-point any SIEM collector or scheduled task reading the old path. |
| Scripts | `EIDAuthenticationPackage.dll` is now `OpenAccessEIDPackage.dll`. |

### Unchanged

Component names keep the `EID` prefix, all GUIDs are unchanged, and the credential
storage format is identical to v1.2.00.
EOF

gh release create v2.0.00 --target main --title "REL_2.0.00_Win_x64" --prerelease --notes-file /tmp/v2-notes.md
```

- [ ] **Step 7: Commit any final URL fixes**

```bash
git add -A
git commit -m "chore(rename): repository renamed to OpenAccessEID; integrations re-pointed"
```

---

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| LSA lists a package name whose DLL was deleted | **Critical** — machine may not authenticate | Task 7 deregisters before deleting, and Task 2 strips the legacy name on both register and deregister. Task 11 Step 2 verifies the registry directly. |
| `CREDENTIAL_LSAPREFIX` changed by a careless global replace | **Critical** — every enrollment orphaned | Explicit global constraint; guard rail in `Verify-Rename.ps1`; verified by a real YubiKey logon in Task 11. |
| Deployed Group Policy orphaned by the namespace change | High — logging silently reverts to defaults | Documented in README, warned about by the installer, tested in Task 11 Step 4. |
| SIEM collectors still reading the old ProgramData path | Medium — audit gap | Documented in the upgrade table; old directory is moved, not left as a decoy. |
| Repository stars lost | Medium — irrecoverable | Rename only, never re-create; verified in Task 12 Step 2. |
| `scan-artifacts.yml` still scanning the old DLL name | Low — silent coverage gap | Called out explicitly in Task 8 Step 3. |

---

## Out of scope

- Renaming `EIDCardLibrary`, `EIDCredentialProvider`, `EIDMigrate`, `EIDMigrateUI`, `EIDManageUsers`, `EIDTraceConsumer`, `EIDConfigurationWizard`, `EIDConfigurationWizardElevated`, `EIDPasswordChangeNotification` — the bare `EID` prefix is retained by explicit decision.
- Changing `CREDENTIAL_LSAPREFIX` or any GUID.
- The `EIDTraceConsumer` Windows service name — it contains no forbidden token; renaming it would need its own service migration.
- Code signing, and the VirusTotal detection work — tracked separately.
