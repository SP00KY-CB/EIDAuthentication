<#
.SYNOPSIS
  Acceptance test for the OpenAccess EID rename.
.DESCRIPTION
  Asserts that the legacy token "EIDAuthentication" appears in git-tracked file
  contents or filenames only where it is deliberate:

    - the legacy LSA package name kept to clean up pre-v2.0.00 installs
      (EIDCardLibrary.h, Registration.cpp);
    - the installer's migration code (Installerx64.nsi);
    - upgrade documentation, test plans, release notes and dated historical
      plans/specs;
    - the SonarCloud project key, an external identifier configured in
      SonarCloud.

  The bare token "EID" is ALLOWED and must not be flagged - EIDCardLibrary,
  EIDCredentialProvider, the L$_EID_ LSA secret prefix and friends are all
  retained by design.

  Exit code 0 = clean, 1 = an unexpected occurrence or a guard rail failed.
#>
[CmdletBinding()]
param(
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
$allowedFiles = @(
    ':!tools/Verify-Rename.ps1',
    ':!EIDCardLibrary/EIDCardLibrary.h',
    ':!EIDCardLibrary/Registration.cpp',
    ':!Installer/Installerx64.nsi',
    ':!README.md',
    ':!docs/VM_TEST_PLAN.md',
    ':!docs/RELEASE_NOTES_v2.0.00.md',
    ':!docs/BETA_RELEASE_NOTES.md',
    ':!docs/superpowers/*'
)
# The SonarCloud project key is an external identifier set in SonarCloud itself;
# it keeps its original value unless the project key is changed there first.
$allowedLine = 'DangerDawgAU_EIDAuthentication'

$hits = @(git grep -n --fixed-strings $ForbiddenToken -- $allowedFiles 2>$null |
          Where-Object { ($_ -replace $allowedLine, '') -match [regex]::Escape($ForbiddenToken) })
if ($hits.Count -gt 0) {
    $failed = $true
    Write-Host "FAIL: $($hits.Count) unexpected occurrence(s) of '$ForbiddenToken':" -ForegroundColor Red
    $hits | Select-Object -First 40 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
} else {
    Write-Host "PASS: '$ForbiddenToken' appears only where it is deliberate." -ForegroundColor Green
}

# --- 3. Guard rails: things that MUST still be present -----------------------
# A careless global search-and-replace could destroy these. Their absence is a
# worse failure than the rename being incomplete.
$mustExist = @{
    'EIDCardLibrary project'        = 'EIDCardLibrary/EIDCardLibrary.vcxproj'
    'EIDCredentialProvider project' = 'EIDCredentialProvider/EIDCredentialProvider.vcxproj'
    'OpenAccessEIDPackage project'  = 'OpenAccessEIDPackage/OpenAccessEIDPackage.vcxproj'
}
foreach ($entry in $mustExist.GetEnumerator()) {
    if (-not (Test-Path $entry.Value)) {
        $failed = $true
        Write-Host "FAIL: expected to exist, but missing: $($entry.Key) ($($entry.Value))" -ForegroundColor Red
    }
}
$checks = @(
    @{ Name = 'CREDENTIAL_LSAPREFIX L"L$_EID_" (changing it orphans every enrollment)'
       Pattern = 'L"L$_EID_"'; Path = 'EIDCardLibrary/StoredCredentialManagement.cpp' },
    @{ Name = 'LSA package name constant is OpenAccessEIDPackage'
       Pattern = 'AUTHENTICATIONPACKAGENAME = "OpenAccessEIDPackage"'; Path = 'EIDCardLibrary/EIDCardLibrary.h' },
    @{ Name = 'SSP package name matches the LSA package name'
       Pattern = 'TEXT("OpenAccessEIDPackage")'; Path = 'OpenAccessEIDPackage/EIDSecuritySupportProvider.cpp' },
    @{ Name = 'original author attribution retained (issue #63)'
       Pattern = 'Copyright (C) 2009 Vincent Le Toux'; Path = 'EIDCardLibrary/Package.cpp' }
)
foreach ($c in $checks) {
    $hit = @(git grep -c --fixed-strings $c.Pattern -- $c.Path 2>$null)
    if ($hit.Count -eq 0) {
        $failed = $true
        Write-Host "FAIL: $($c.Name)" -ForegroundColor Red
    } else {
        Write-Host "PASS: $($c.Name)" -ForegroundColor Green
    }
}

if ($failed) { Write-Host "`nVERIFICATION FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`nVERIFICATION PASSED" -ForegroundColor Green
exit 0
