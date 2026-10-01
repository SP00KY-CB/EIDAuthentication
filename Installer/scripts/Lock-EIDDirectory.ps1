# Lock-EIDDirectory.ps1 - run by the OpenAccess EID installer
# (Installerx64.nsi, LockEIDDirectory); not meant to be run by hand.
#
# Gives the directory -Path owner Administrators and a protected DACL that
# replaces every ACE it had: Full control for SYSTEM and Administrators and
# read/execute for Users, inherited by everything below (the DACL the runtime
# applies to the log directory, EID_LOG_DIR_SDDL). Owner and DACL are written
# in a single call, so there is no moment with a half-applied DACL. Refuses a
# junction, symbolic link or other reparse point: changing its ACL would
# change the ACL of whatever it points to.
#
# Exit codes, read by the installer:
#   10 = done
#   11 = refused or failed
#   12 = cannot run here (PowerShell not in FullLanguage mode)
#   anything else = PowerShell did not run the script
# On anything but 10 the installer falls back to icacls.

param(
    [Parameter(Mandatory = $true)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output "Cannot secure ${Path}: PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode."
    exit 12
}

$sddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'

try {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        Write-Output "Not secured: $Path is not a directory."
        exit 11
    }
    if ((([int] $item.Attributes) -band 0x400) -ne 0) {
        Write-Output "Not secured: $Path is a junction, symbolic link or other reparse point."
        exit 11
    }
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    # Owner and DACL only: leave the group and the SACL as they are.
    $security.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections] 'Owner, Access')
    $item.SetAccessControl($security)
    Write-Output "Secured $Path (owner Administrators; SYSTEM and Administrators Full, Users read)."
    exit 10
} catch {
    Write-Output "Not secured: ${Path}: $($_.Exception.Message)"
    exit 11
}
