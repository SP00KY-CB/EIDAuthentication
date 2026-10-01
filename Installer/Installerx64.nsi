;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"
  !include "nsDialogs.nsh"
  !include "X64.nsh"
  !include "WinVer.nsh"
  !include "FileFunc.nsh"

;--------------------------------
;General

  ;Name and file
  Name "OpenAccess EID"
  OutFile "EIDInstallx64.exe"

  ;Installer icon (optional - copied by build.ps1 if exists)
  Icon "installer.ico"
  UninstallIcon "installer.ico"

  ;Default installation folder
  InstallDir "$PROGRAMFILES64\OpenAccess EID"

  ;Get installation folder from registry if available
  InstallDirRegKey HKLM "Software\OpenAccessEID" "InstallPath"

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_LICENSE "License.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  Page custom ShowSecurityOptions LeaveSecurityOptions
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH

  ; Custom uninstall page for certificate/cleanup options
  UninstPage custom un.ShowUninstallOptions un.LeaveUninstallOptions

  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_UNPAGE_FINISH
;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"
  !insertmacro MUI_LANGUAGE "French"

;--------------------------------
;Install types
;
;  1 = Core     - application only (existing behaviour)
;  2 = Complete - application + bundled smart-card minidrivers
;                 (MyEID / YubiKey / Idemia IDOne PIV). All minidriver
;                 packages are embedded in the installer at build time -
;                 no internet access is required at install time.

  InstType "Core"
  InstType "Complete"

;--------------------------------
;Variables for size calculation

  Var /GLOBAL InstallSize

;--------------------------------
;Security option (install-time question)

  Var /GLOBAL RequireCardBound
  Var /GLOBAL RequireCardBoundCheckbox
  ; 1 once the Security Options page has actually been presented, so an explicit
  ; operator choice can be told apart from the silent (/S) default.
  Var /GLOBAL SecurityPageShown

;--------------------------------
;Upgrade state

  ; 1 when .onInit found and removed an installation made under the product's
  ; former name, EID Authentication (v1.3.00 and earlier). The Core section
  ; then finishes the migration and warns about orphaned Group Policy.
  Var /GLOBAL MigratedFromLegacy

  ; 1 when the uninstaller of the version being replaced deleted every user's
  ; stored credential (v2.0.00 and earlier, when its unregistration step could
  ; not be swapped for this version's - see NeutraliseOldUnregister). The Core
  ; section then tells the operator that users must re-enrol.
  Var /GLOBAL EnrolmentsWiped

;--------------------------------
;Uninstaller Variables

  Var /GLOBAL Uninstall_RemoveMappings
  Var /GLOBAL Uninstall_RemoveCertificates

;--------------------------------
;Installer Sections

Section "Core" SecCore
  SectionIn RO 1 2

  ; Initialize install size counter
  StrCpy $InstallSize 0

  ;--------------------------------------------------------------------
  ; Migration from EID Authentication (v1.3.00 and earlier), part 2.
  ; Part 1 in .onInit has already copied the LogManager settings across and
  ; run the old uninstaller, which deregistered the legacy LSA package
  ; (EIDAuthenticationPackage), scheduled its DLL for deletion and removed
  ; the old registry keys. What is left is state the old uninstaller does not
  ; own.
  ;--------------------------------------------------------------------
  ${If} $MigratedFromLegacy == 1
    DetailPrint "Completing migration from EID Authentication..."

    ; Logs, logging.json and the LSA-protection backup. A rename (not a copy)
    ; keeps the directory's protected DACL and cannot lose an audit trail
    ; half-way. If it fails - a file still held open, or the new directory
    ; already exists - the old directory is left untouched.
    ; Any user can create C:\ProgramData\EIDAuthentication, so it is only moved
    ; when it and everything in it is owned by SYSTEM/Administrators and holds
    ; no junction or symlink; renaming a planted tree into the new location
    ; would hand the SYSTEM logger the attacker's directory.
    ${If} ${FileExists} "C:\ProgramData\EIDAuthentication\*.*"
      ${IfNot} ${FileExists} "C:\ProgramData\OpenAccessEID\*.*"
        Push "C:\ProgramData\EIDAuthentication"
        Call IsEIDDataTreeTrusted
        Pop $R0
        ${If} $R0 != 1
          DetailPrint "WARNING: C:\ProgramData\EIDAuthentication is a junction, or it or something in it is not owned by SYSTEM/Administrators or can be modified by other users, or it could not be checked; not moved. Existing logs remain there."
        ${Else}
          ClearErrors
          Rename "C:\ProgramData\EIDAuthentication" "C:\ProgramData\OpenAccessEID"
          ${If} ${Errors}
            DetailPrint "WARNING: could not move C:\ProgramData\EIDAuthentication; existing logs remain there."
          ${Else}
            DetailPrint "Moved logs and configuration to C:\ProgramData\OpenAccessEID."
          ${EndIf}
        ${EndIf}
      ${Else}
        DetailPrint "C:\ProgramData\OpenAccessEID already exists; existing logs remain in C:\ProgramData\EIDAuthentication."
      ${EndIf}
    ${EndIf}

    ; Belt and braces: remove anything an interrupted old uninstaller may
    ; have left behind under the old name.
    nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /F /TN "EID Authentication\Apply Trace Config"'
    Delete "$WINDIR\PolicyDefinitions\EIDAuthentication.admx"
    Delete "$WINDIR\PolicyDefinitions\en-US\EIDAuthentication.adml"
    RMDir /r "$SMPROGRAMS\EID Authentication"
    Delete "$DESKTOP\EID Authentication Configuration.lnk"
  ${EndIf}

  ; Create and lock down C:\ProgramData\OpenAccessEID (logs and logging.json)
  ; before anything runs as SYSTEM against it. Also covers a directory just
  ; renamed from the legacy location above.
  DetailPrint "Securing C:\ProgramData\OpenAccessEID..."
  Call SecureEIDDataDir

  ; Create installation directory and lock it down before anything is put in it.
  ; EIDTraceConsumer.exe runs from here as SYSTEM and the System32 DLLs are
  ; copied from here, and /D= can point $INSTDIR anywhere - including a folder a
  ; standard user can write to. So whatever the path, give it the Program Files
  ; treatment: owner Administrators, inheritance removed, Full control for
  ; SYSTEM and Administrators, read/execute for Users. A junction, or a folder
  ; that already holds something a standard user owns or can modify, is refused.
  CreateDirectory "$INSTDIR"
  Push "$INSTDIR"
  Call IsReparsePoint
  Pop $R0
  ${If} $R0 == 1
    Push "ERROR: the installation folder $INSTDIR is a junction or symbolic link. Installation stopped; choose another folder."
    Call InstallLog
    MessageBox MB_OK|MB_ICONSTOP "The installation folder$\n$INSTDIR$\nis a junction or symbolic link. OpenAccess EID runs a SYSTEM service from this folder, so it will not install there.$\n$\nChoose another folder." /SD IDOK
    Abort
  ${EndIf}
  Push "$INSTDIR"
  Call LockEIDDirectory
  Pop $R0
  ${If} $R0 != 1
    Push "ERROR: could not restrict the permissions of $INSTDIR. Installation stopped."
    Call InstallLog
    MessageBox MB_OK|MB_ICONSTOP "The permissions of the installation folder$\n$INSTDIR$\ncould not be restricted to SYSTEM and Administrators. OpenAccess EID runs a SYSTEM service from this folder, so it will not install there." /SD IDOK
    Abort
  ${EndIf}
  Push "$INSTDIR"
  Call IsEIDDataTreeTrusted
  Pop $R0
  ${If} $R0 == 0
    Push "ERROR: $INSTDIR already contains files or folders that a standard user owns or can modify, or a junction. Installation stopped."
    Call InstallLog
    MessageBox MB_OK|MB_ICONSTOP "The installation folder$\n$INSTDIR$\nalready contains files or folders that are not owned by SYSTEM/Administrators, that other users can modify, or a junction. OpenAccess EID runs a SYSTEM service from this folder, so it will not install there.$\n$\nChoose an empty folder, or remove those items first." /SD IDOK
    Abort
  ${ElseIf} $R0 == 2
    Push "WARNING: could not check the contents of $INSTDIR (PowerShell did not run, or runs in constrained language mode); its permissions have been restricted."
    Call InstallLog
  ${EndIf}
  SetOutPath "$INSTDIR"

  ; Install DLL files to Program Files
  FILE "..\x64\Release\OpenAccessEIDPackage.dll"
  Push "$INSTDIR\OpenAccessEIDPackage.dll"
  Call AddFileSize

  FILE "..\x64\Release\EIDCredentialProvider.dll"
  Push "$INSTDIR\EIDCredentialProvider.dll"
  Call AddFileSize

  FILE "..\x64\Release\EIDPasswordChangeNotification.dll"
  Push "$INSTDIR\EIDPasswordChangeNotification.dll"
  Call AddFileSize

  ; Install all executable files
  FILE "..\x64\Release\EIDConfigurationWizard.exe"
  Push "$INSTDIR\EIDConfigurationWizard.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDConfigurationWizardElevated.exe"
  Push "$INSTDIR\EIDConfigurationWizardElevated.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDMigrate.exe"
  Push "$INSTDIR\EIDMigrate.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDMigrateUI.exe"
  Push "$INSTDIR\EIDMigrateUI.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDManageUsers.exe"
  Push "$INSTDIR\EIDManageUsers.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDTraceConsumer.exe"
  Push "$INSTDIR\EIDTraceConsumer.exe"
  Call AddFileSize

  ; Install icon for DisplayIcon (installed programs list)
  FILE "cred_provider.ico"

  ; Install Group Policy administrative templates (ADMX/ADML) so the
  ; custom OpenAccess EID policies appear in gpedit.msc.
  ; Destination: %WINDIR%\PolicyDefinitions (picked up by Group Policy
  ; Editor automatically on next launch).
  DetailPrint "Installing Group Policy templates..."
  SetOutPath "$WINDIR\PolicyDefinitions"
  File "PolicyDefinitions\OpenAccessEID.admx"
  SetOutPath "$WINDIR\PolicyDefinitions\en-US"
  File "PolicyDefinitions\en-US\OpenAccessEID.adml"
  SetOutPath "$INSTDIR"

  ; Install manual-run administrator tools. Disable-LsaProtection.ps1 must
  ; NOT be executed by the installer - the sysadmin has to read the warning
  ; page and type a confirmation phrase. Ship it under $INSTDIR\tools\ so
  ; it is always available locally after install.
  DetailPrint "Installing administrator tools..."
  SetOutPath "$INSTDIR\tools"
  File "tools\Disable-LsaProtection.ps1"
  SetOutPath "$INSTDIR"

  ; Copy DLLs to System32 (required for LSA and Credential Provider).
  ; LSASS and LogonUI keep these mapped, and the uninstaller that just ran has
  ; usually queued their deletion for the next reboot - InstallSystemDll makes
  ; sure the new copy is what is left after that reboot.
  ${DisableX64FSRedirection}
  Push "OpenAccessEIDPackage.dll"
  Call InstallSystemDll
  Push "EIDCredentialProvider.dll"
  Call InstallSystemDll
  Push "EIDPasswordChangeNotification.dll"
  Call InstallSystemDll

  ; Create Start Menu folder and shortcuts for all executables
  CreateDirectory "$SMPROGRAMS\OpenAccess EID"
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Configuration Wizard.lnk" "$INSTDIR\EIDConfigurationWizard.exe" "" "$INSTDIR\EIDConfigurationWizard.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Credential Migration (CLI).lnk" "$INSTDIR\EIDMigrate.exe" "" "$INSTDIR\EIDMigrate.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Credential Migration (GUI).lnk" "$INSTDIR\EIDMigrateUI.exe" "" "$INSTDIR\EIDMigrateUI.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Manage Users.lnk" "$INSTDIR\EIDManageUsers.exe" "" "$INSTDIR\EIDManageUsers.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Trace Consumer.lnk" "$INSTDIR\EIDTraceConsumer.exe" "" "$INSTDIR\EIDTraceConsumer.exe" 0
  ; Elevated PowerShell shortcut for the LSA Protection toggle script.
  ; Uses -NoExit so the warning page and outcome remain visible after the
  ; script returns; ExecutionPolicy Bypass scoped to this process only.
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Disable LSA Protection (manual).lnk" \
    "powershell.exe" \
    '-NoProfile -NoExit -ExecutionPolicy Bypass -File "$INSTDIR\tools\Disable-LsaProtection.ps1"' \
    "$INSTDIR\cred_provider.ico" 0 SW_SHOWNORMAL "" \
    "Manually disable Windows LSA Protection so unsigned EID DLLs can load. Reads a warning page and requires confirmation."
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Uninstall.lnk" "$INSTDIR\EIDUninstall.exe" "" "$INSTDIR\EIDUninstall.exe" 0

  ; Create desktop shortcut pointing to Program Files
  CreateShortcut "$DESKTOP\OpenAccess EID Configuration.lnk" "$INSTDIR\EIDConfigurationWizard.exe"

  ; Create uninstaller in installation directory
  WriteUninstaller "$INSTDIR\EIDUninstall.exe"

  ; Write installation path to registry
  SetRegView 64
  WriteRegStr HKLM "Software\OpenAccessEID" "InstallPath" "$INSTDIR"

  ; Security policy: RequireCardBoundCredentials (from the install-time question).
  ; 1 = only card-wrapped (crypted) credentials may be created / used at logon / imported;
  ; the Windows password can then never be recovered without the smart card.
  ; Write the value when the operator actually saw the Security Options page and made a
  ; choice there (including on upgrade/repair - otherwise ticking the box would silently
  ; do nothing). For silent (/S) installs the page never runs, so fall back to writing
  ; only when the policy has never been configured: that preserves an admin's prior
  ; choice and never re-locks an existing non-card-bound enrollment out of logon.
  ClearErrors
  ReadRegDWORD $0 HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "RequireCardBoundCredentials"
  ${If} ${Errors}
  ${OrIf} $SecurityPageShown == 1
    WriteRegDWORD HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "RequireCardBoundCredentials" $RequireCardBound
  ${EndIf}

  ; Uninstall info
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "DisplayName" "OpenAccess EID"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "UninstallString" "$INSTDIR\EIDUninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "Publisher" "OpenAccess EID"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "DisplayIcon" "$INSTDIR\cred_provider.ico"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "NoRepair" 1
  ; Tells a future installer that this version's uninstaller keeps stored
  ; credentials (only the opt-in cleanup checkbox removes them). Uninstallers of
  ; v2.0.00 and earlier deleted them during unregistration.
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "KeepsEnrolmentsOnUninstall" 1

  ; Convert total install size from bytes to KB and write to registry
  IntOp $InstallSize $InstallSize / 1024
  ; Add ~100 KB for uninstaller and directory structures
  IntOp $InstallSize $InstallSize + 100
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "EstimatedSize" $InstallSize

  ; Register authentication package (from System32)
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllRegister'

  ; Configure Smart Card services to start automatically on boot. The
  ; default state on Windows is "Manual (Trigger Start)" which only
  ; starts the services when a reader is already attached - if the user
  ; plugs the reader in after logon, or sign-in needs the service before
  ; any trigger has fired, the Credential Provider will not see any
  ; readers. Forcing start= auto ensures SCardSvr and its device
  ; enumerator are running before the logon UI appears.
  DetailPrint "Configuring Smart Card services for automatic startup..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config SCardSvr start= auto'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScDeviceEnum start= auto'
  nsExec::ExecToLog '"$SYSDIR\net.exe" start SCardSvr'
  nsExec::ExecToLog '"$SYSDIR\net.exe" start ScDeviceEnum'

  ; Install and start the ETW trace consumer service. Without this the CSV
  ; logging (configured via Group Policy / the LogManager registry key) has no
  ; consumer and never produces files. The executable self-registers as an
  ; auto-start service via -install.
  DetailPrint "Installing EID Trace Consumer service..."
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -install'
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -start'

  ; Apply the (Group Policy-aware) ETW trace-session config to the WMI autologger now, and create a
  ; boot-time scheduled task that re-applies it each boot so Group Policy changes to the logging/ETW
  ; settings take effect without EIDLogManager. Runs as SYSTEM (needs HKLM autologger write).
  ; $SYSDIR resolves to the real System32 here (x64 FS redirection is disabled above).
  DetailPrint "Applying trace configuration and scheduling the GPO-apply task..."
  nsExec::ExecToLog '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllApplyTraceConfigW'
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Create /F /RU SYSTEM /RL HIGHEST /SC ONSTART /TN "OpenAccess EID\Apply Trace Config" /TR "$SYSDIR\rundll32.exe $SYSDIR\OpenAccessEIDPackage.dll,DllApplyTraceConfigW"'

  SetPluginUnload manual
  SetRebootFlag true

  ${If} $MigratedFromLegacy == 1
    MessageBox MB_OK|MB_ICONEXCLAMATION "EID Authentication has been upgraded to OpenAccess EID.$\n$\nGroup Policy set through the old EIDAuthentication administrative template is NOT carried over. After rebooting, apply the OpenAccess EID template and re-apply any logging policies.$\n$\nA reboot is required before smart-card logon uses the new version." /SD IDOK
  ${EndIf}

  ; Always recorded, and shown unless silent: after this, every enrolled user is
  ; locked out of smart-card logon until they enrol again.
  ${If} $EnrolmentsWiped == 1
    Push "NOTICE: the uninstaller of the previous version deleted every user's stored smart-card credential. Users must re-enrol their cards before they can log on with them."
    Call InstallLog
    MessageBox MB_OK|MB_ICONEXCLAMATION "The uninstaller of the previous version deleted every user's stored smart-card credential.$\n$\nUsers must re-enrol their cards before they can log on with them." /SD IDOK
  ${EndIf}

SectionEnd

;--------------------------------
;Smart Card Minidrivers  (Complete install type)
;
;  These sections install vendor smart-card minidrivers that are
;  BUNDLED INTO THE INSTALLER at build time. No network access is
;  required at install time - suitable for isolated / air-gapped
;  deployments.
;
;  Each vendor package is extracted into $PLUGINSDIR (auto-cleaned
;  on installer exit) and installed with the appropriate tool:
;    - MyEID  (ZIP containing INF+DLL+CAT)  -> Expand-Archive + pnputil -i -a
;    - YubiKey (signed MSI)                  -> msiexec /i /qn /norestart
;    - IDOne PIV (CAB from Windows Update)   -> expand.exe + pnputil -i -a
;
;  Failures are logged as warnings and do not abort the Core install.
;
;  The bundled files live in Installer\drivers\ and are staged by
;  build.ps1 (download + SHA-256 verification). See the README.md
;  in that directory.

SectionGroup /e "Smart Card Minidrivers" SecMinidrivers

Section /o "MyEID Minidriver (Aventra)" SecMyEIDMinidriver
  SectionIn 2

  InitPluginsDir
  SetOutPath "$PLUGINSDIR\MyEID"
  File "drivers\MyEID_Minidriver.zip"

  DetailPrint "Extracting MyEID Minidriver..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command ' \
    'try { Expand-Archive -LiteralPath "$PLUGINSDIR\MyEID\MyEID_Minidriver.zip" -DestinationPath "$PLUGINSDIR\MyEID\x" -Force; exit 0 } ' \
    'catch { Write-Error $_.Exception.Message; exit 1 }' \
    ''
  Pop $0
  ${If} $0 != 0
    DetailPrint "WARNING: MyEID extraction failed (code $0) - skipping"
    Goto MyEIDDone
  ${EndIf}

  DetailPrint "Installing MyEID Minidriver (pnputil)..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command ' \
    '$inf = Get-ChildItem -Path "$PLUGINSDIR\MyEID\x" -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -First 1; ' \
    'if (-not $inf) { Write-Error "No INF found in MyEID archive"; exit 2 }; ' \
    '& pnputil.exe -i -a $inf.FullName | Out-Host; ' \
    'exit $LASTEXITCODE' \
    ''
  Pop $0
  ${If} $0 = 0
    DetailPrint "MyEID Minidriver installed successfully"
  ${Else}
    DetailPrint "WARNING: MyEID Minidriver install returned code $0"
  ${EndIf}

MyEIDDone:
SectionEnd

Section /o "YubiKey Minidriver (Yubico)" SecYubiKeyMinidriver
  SectionIn 2

  InitPluginsDir
  SetOutPath "$PLUGINSDIR\YubiKey"
  File "drivers\YubiKey-Minidriver-5.0.4.273-x64.msi"

  DetailPrint "Installing YubiKey Minidriver (msiexec)..."
  nsExec::ExecToLog '"$SYSDIR\msiexec.exe" /i "$PLUGINSDIR\YubiKey\YubiKey-Minidriver-5.0.4.273-x64.msi" /qn /norestart'
  Pop $0
  ${If} $0 = 0
    DetailPrint "YubiKey Minidriver installed successfully"
  ${ElseIf} $0 = 3010
    DetailPrint "YubiKey Minidriver installed successfully (reboot required)"
    SetRebootFlag true
  ${Else}
    DetailPrint "WARNING: YubiKey Minidriver install returned code $0"
  ${EndIf}
SectionEnd

Section /o "IDOne PIV Minidriver (Idemia / Windows Update)" SecWUMinidriver
  SectionIn 2

  InitPluginsDir
  SetOutPath "$PLUGINSDIR\WU"
  File "drivers\WindowsUpdate_Minidriver.cab"
  CreateDirectory "$PLUGINSDIR\WU\x"

  DetailPrint "Extracting CAB contents..."
  nsExec::ExecToLog '"$SYSDIR\expand.exe" -F:* "$PLUGINSDIR\WU\WindowsUpdate_Minidriver.cab" "$PLUGINSDIR\WU\x"'
  Pop $0
  ${If} $0 != 0
    DetailPrint "WARNING: CAB extraction failed (code $0) - skipping"
    Goto WUDone
  ${EndIf}

  DetailPrint "Adding INF driver(s) to the driver store..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command ' \
    '$infs = Get-ChildItem -Path "$PLUGINSDIR\WU\x" -Recurse -Filter *.inf -ErrorAction SilentlyContinue; ' \
    'if (-not $infs) { Write-Error "No INF found in CAB"; exit 2 }; ' \
    'foreach ($inf in $infs) { Write-Host ("Installing: " + $inf.FullName); & pnputil.exe -i -a $inf.FullName | Out-Host }; ' \
    'exit 0' \
    ''
  Pop $0
  ${If} $0 = 0
    DetailPrint "IDOne PIV Minidriver installed successfully"
  ${Else}
    DetailPrint "WARNING: IDOne PIV Minidriver install returned code $0"
  ${EndIf}

WUDone:
SectionEnd

SectionGroupEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecCore ${LANG_ENGLISH} "Core OpenAccess EID components: LSA Authentication Package, Credential Provider, Configuration Wizard, Log Manager, Migrate CLI/UI, and Manage Users tool. Always installed."
  LangString DESC_SecCore ${LANG_FRENCH}  "Composants principaux OpenAccess EID: LSA, Credential Provider, assistant de configuration et outils associes. Toujours installes."

  LangString DESC_SecMinidrivers ${LANG_ENGLISH} "Smart card minidrivers bundled with the installer. No internet access required at install time. Auto-selected for the Complete install type."
  LangString DESC_SecMinidrivers ${LANG_FRENCH}  "Minidrivers de carte a puce fournis avec l'installateur. Aucun acces Internet requis. Selectionnes automatiquement pour l'installation Complete."

  LangString DESC_SecMyEID ${LANG_ENGLISH} "Aventra MyEID minidriver v3.0.1.2 (Certified). Bundled in the installer; extracts and installs via pnputil."
  LangString DESC_SecMyEID ${LANG_FRENCH}  "Minidriver Aventra MyEID v3.0.1.2 (Certifie). Inclus dans l'installateur; extrait et installe via pnputil."

  LangString DESC_SecYubiKey ${LANG_ENGLISH} "YubiKey Smart Card Minidriver 5.0.4.273 (x64). Bundled signed MSI installed silently via msiexec."
  LangString DESC_SecYubiKey ${LANG_FRENCH}  "Minidriver YubiKey 5.0.4.273 (x64). MSI signe inclus, installe silencieusement via msiexec."

  LangString DESC_SecWU ${LANG_ENGLISH} "IDOne PIV minidriver from the Microsoft Update catalog. Bundled signed CAB; extracted and added to the driver store via pnputil."
  LangString DESC_SecWU ${LANG_FRENCH}  "Minidriver IDOne PIV du catalogue Microsoft Update. CAB signe inclus; extrait et ajoute au magasin de pilotes via pnputil."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}              $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMinidrivers}       $(DESC_SecMinidrivers)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMyEIDMinidriver}   $(DESC_SecMyEID)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecYubiKeyMinidriver} $(DESC_SecYubiKey)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecWUMinidriver}      $(DESC_SecWU)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Install-time Security Options page

Function ShowSecurityOptions
  !insertmacro MUI_HEADER_TEXT "Security Options" "Choose how OpenAccess EID protects stored credentials."

  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 60u "When 'Require card-bound credentials' is enabled, each user's Windows password is only ever stored sealed to their smart card, so it cannot be recovered from this machine without the card (and PIN).$\n$\nRecommended for decrypt-capable cards such as MyEID (Aventra) and YubiKey (PIV). Leave it OFF if you use signature-only cards, which cannot use card-bound storage and would otherwise fail to enrol / log on."
  Pop $0

  ${NSD_CreateCheckbox} 10u 68u 100% 12u "Require card-bound credentials (RequireCardBoundCredentials policy)"
  Pop $RequireCardBoundCheckbox
  ${If} $RequireCardBound == 1
    ${NSD_Check} $RequireCardBoundCheckbox
  ${EndIf}

  nsDialogs::Show
FunctionEnd

Function LeaveSecurityOptions
  ${NSD_GetState} $RequireCardBoundCheckbox $RequireCardBound
  StrCpy $SecurityPageShown 1
FunctionEnd

;--------------------------------
;Helper Functions for Certificate Cleanup

Function un.ShowUninstallOptions
  ; Create custom page with checkboxes for uninstall options
  !insertmacro MUI_HEADER_TEXT "Cleanup Options" "Choose what to remove besides the program files."

  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 40u "Select additional cleanup options. Both are off by default so that reinstalling keeps existing enrollments working."
  Pop $0

  ; Checkbox for removing EID certificate mappings from users (LSA credentials)
  ; Default UNCHECKED: destructive cleanup is opt-in (a temporary uninstall/upgrade
  ; must not destroy enrollments)
  ${NSD_CreateCheckbox} 10u 50u 100% 12u "Remove EID certificate mappings from users"
  Pop $Uninstall_RemoveMappings

  ; Checkbox for removing EID root CA + issued certificates
  ${NSD_CreateCheckbox} 10u 70u 100% 24u "Remove EID Root Certificate Authority and all EID-issued user certificates from this machine, including the CA private key (irreversible)"
  Pop $Uninstall_RemoveCertificates

  nsDialogs::Show
FunctionEnd

Function un.LeaveUninstallOptions
  ; Get the state of checkboxes when leaving the page
  ${NSD_GetState} $Uninstall_RemoveMappings $Uninstall_RemoveMappings
  ${NSD_GetState} $Uninstall_RemoveCertificates $Uninstall_RemoveCertificates
FunctionEnd

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  ; Opt-in removal of stored credentials (if the checkbox was selected) comes
  ; first: it asks the package loaded in LSASS to delete them, so it has to run
  ; while the package is still registered.
  ${If} $Uninstall_RemoveMappings = 1
    ; This requires calling into the DLL since NSIS cannot directly manipulate LSA
    DetailPrint "Removing EID credential mappings from LSA..."
    ${DisableX64FSRedirection}
    ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",CleanupLsaCredentials' $1
    ${If} $1 != 0
      DetailPrint "Note: LSA cleanup returned code $1 (may be expected if not installed)"
    ${EndIf}
    ${EnableX64FSRedirection}
  ${Else}
    DetailPrint "Skipping LSA credential mapping removal (not selected)"
  ${EndIf}

  ; Unregister all components (from System32)
  ${DisableX64FSRedirection}
  DetailPrint "Unregistering components..."
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllUnRegister' $0
  ${If} $0 != 0
    DetailPrint "Warning: DllUnRegister returned error code $0 - continuing with manual cleanup"
  ${EndIf}

  ; rundll32 exits 0 whether or not DllUnRegister worked, so check the LSA
  ; package lists themselves and take out any of our names still there. Left
  ; in, they point LSASS at DLLs that are deleted at the reboot.
  InitPluginsDir
  File "/oname=$PLUGINSDIR\Remove-EIDLsaRegistration.ps1" "scripts\Remove-EIDLsaRegistration.ps1"
  Push "$PLUGINSDIR\Remove-EIDLsaRegistration.ps1"
  System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_SCRIPT", t s)'
  nsExec::ExecToLog /TIMEOUT=120000 `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText($$env:OAEID_SCRIPT))); exit $$LASTEXITCODE"`
  Pop $0
  ${If} $0 == 10
    DetailPrint "LSA package lists checked: no OpenAccess EID entries left."
  ${ElseIf} $0 == 13
    DetailPrint "DllUnRegister had left OpenAccess EID entries in the LSA package lists; removed them."
  ${Else}
    DetailPrint "WARNING: could not confirm that the LSA package lists are clean (result $0)."
    MessageBox MB_OK|MB_ICONEXCLAMATION "Could not confirm that Windows no longer loads the OpenAccess EID LSA packages (result $0).$\n$\nBefore rebooting, check these values under$\nHKLM\SYSTEM\CurrentControlSet\Control\Lsa$\n  Security Packages, Authentication Packages, Notification Packages$\nand remove OpenAccessEIDPackage, EIDAuthenticationPackage and EIDPasswordChangeNotification if listed." /SD IDOK
  ${EndIf}

  ${EnableX64FSRedirection}

  ; Conditionally remove certificates created by the software (if checkbox was selected).
  ; Native cleanup inside the package DLL (still present - deleted later in this
  ; section): sweeps machine stores and every user profile, deletes the CA key.
  ${If} $Uninstall_RemoveCertificates = 1
    DetailPrint "Removing EID certificates (machine stores and all user profiles)..."
    ${DisableX64FSRedirection}
    ; rundll32 discards the entry point's HRESULT and exits 0 unless it fails to launch,
    ; so $2 only catches a launch failure - per-certificate results go to the ETW trace.
    ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",CleanupEIDCertificates' $2
    ${If} $2 != 0
      DetailPrint "Warning: could not run certificate cleanup (code $2) - certificates remain"
    ${EndIf}
    ${EnableX64FSRedirection}
  ${Else}
    DetailPrint "Skipping certificate removal (not selected)"
  ${EndIf}

  ; Delete Start Menu shortcuts and folder
  Delete "$SMPROGRAMS\OpenAccess EID\Configuration Wizard.lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Credential Migration (CLI).lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Credential Migration (GUI).lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Manage Users.lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Trace Consumer.lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Disable LSA Protection (manual).lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Uninstall.lnk"
  RMDir "$SMPROGRAMS\OpenAccess EID"

  ; Delete desktop shortcut
  Delete "$DESKTOP\OpenAccess EID Configuration.lnk"

  ; Delete System32 files (LSA-locked, require reboot)
  ${DisableX64FSRedirection}
  Delete /REBOOTOK "$SYSDIR\OpenAccessEIDPackage.dll"
  Delete /REBOOTOK "$SYSDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$SYSDIR\EIDPasswordChangeNotification.dll"

  ; Delete ETW log files
  Delete /REBOOTOK "$SYSDIR\LogFiles\WMI\EIDCredentialProvider.etl"

  ${EnableX64FSRedirection}

  ; Remove Group Policy administrative templates
  Delete "$WINDIR\PolicyDefinitions\OpenAccessEID.admx"
  Delete "$WINDIR\PolicyDefinitions\en-US\OpenAccessEID.adml"

  ; Delete Program Files installation - DLLs
  Delete "$INSTDIR\OpenAccessEIDPackage.dll"
  Delete "$INSTDIR\EIDCredentialProvider.dll"
  Delete "$INSTDIR\EIDPasswordChangeNotification.dll"

  ; Delete Program Files installation - Executables
  Delete "$INSTDIR\EIDConfigurationWizard.exe"
  Delete "$INSTDIR\EIDConfigurationWizardElevated.exe"
  Delete "$INSTDIR\EIDMigrate.exe"
  Delete "$INSTDIR\EIDMigrateUI.exe"
  Delete "$INSTDIR\EIDManageUsers.exe"

  ; Stop and remove the ETW trace consumer service before deleting its binary,
  ; otherwise the running service holds the file open and leaves a stale service.
  ; Remove the trace-config GPO-apply scheduled task
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /F /TN "OpenAccess EID\Apply Trace Config"'
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -stop'
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -uninstall'
  Delete "$INSTDIR\EIDTraceConsumer.exe"
  Delete "$INSTDIR\cred_provider.ico"

  ; Disable-LsaProtection.ps1 keeps its backup of the original RunAsPPL values
  ; until -Restore has put them back. If the backup is still there, LSA
  ; protection is most likely still off: keep a copy of the script next to the
  ; backup (C:\ProgramData\OpenAccessEID is writable only by SYSTEM and
  ; Administrators) and tell the administrator how to restore it.
  ${If} ${FileExists} "C:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt"
    ClearErrors
    CopyFiles /SILENT "$INSTDIR\tools\Disable-LsaProtection.ps1" "C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1"
    ${If} ${Errors}
      DetailPrint "WARNING: LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and not restored, and the script could not be kept. Restore the values recorded in C:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt by hand, then reboot."
      MessageBox MB_OK|MB_ICONEXCLAMATION "LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and has not been restored.$\n$\nRestore the values recorded in$\nC:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt$\nunder HKLM\SYSTEM\CurrentControlSet\Control\Lsa, then reboot." /SD IDOK
    ${Else}
      DetailPrint "WARNING: LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and not restored. The script was kept at C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1; run it with -Restore as administrator, then reboot."
      MessageBox MB_OK|MB_ICONEXCLAMATION "LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and has not been restored. It stays off after this uninstall.$\n$\nThe script has been kept. To turn LSA protection back on, run as administrator:$\n$\npowershell -NoProfile -ExecutionPolicy Bypass -File $\"C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1$\" -Restore$\n$\nthen reboot." /SD IDOK
    ${EndIf}
  ${EndIf}

  ; Delete administrator tools
  Delete "$INSTDIR\tools\Disable-LsaProtection.ps1"
  RMDir "$INSTDIR\tools"

  ; Delete uninstaller
  Delete "$INSTDIR\EIDUninstall.exe"

  ; Remove installation directory
  RMDir "$INSTDIR"

  ; Remove registry keys
  SetRegView 64

  ; Remove installation path registry
  DeleteRegKey HKLM "Software\OpenAccessEID"

  ; Remove Credential Provider registry keys
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{B4866A0A-DB08-4835-A26F-414B46F3244C}"
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B4866A0A-DB08-4835-A26F-414B46F3244C}"
  DeleteRegKey HKCR "CLSID\{B4866A0A-DB08-4835-A26F-414B46F3244C}"

  ; Remove Configuration Wizard registry keys
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{F5D846B4-14B0-11DE-B23C-27A355D89593}"
  DeleteRegKey HKCR "CLSID\{F5D846B4-14B0-11DE-B23C-27A355D89593}"

  ; Remove WMI Autologger for EIDCredentialProvider
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Control\WMI\Autologger\EIDCredentialProvider"

  ; Remove crash dump configuration for lsass.exe
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe"

  ; Remove GPO policy values set by the Configuration Wizard
  DeleteRegKey HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider"
  DeleteRegValue HKLM "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "scremoveoption"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Policies\System" "scforceoption"

  ; Reset ScPolicySvc service to demand-start (installer may have set it to auto-start)
  DetailPrint "Resetting Smart Card Removal Policy service..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScPolicySvc start= demand'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ScPolicySvc'

  ; Restore Smart Card services to their Windows default (demand / trigger
  ; start). The installer forced these to auto-start; leave them stopped
  ; and revert to demand so Windows' trigger-start behaviour takes over.
  DetailPrint "Restoring Smart Card services to default startup..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config SCardSvr start= demand'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScDeviceEnum start= demand'

  ; Remove uninstall information
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID"

  SetPluginUnload manual
  SetRebootFlag true

  MessageBox MB_OK "OpenAccess EID has been uninstalled. Please reboot your computer to complete the removal."

SectionEnd

;--------------------------------
;Helper function to calculate file size and add to total

Function AddFileSize
  ; This function receives a file path on the stack
  ; Adds the file size to the $InstallSize variable

  Pop $0  ; File path

  ; Get file size by opening and seeking to end
  FileOpen $1 $0 "r"

  ${If} $1 != ""
    FileSeek $1 0 END $2  ; Seek to end, get position (file size in bytes)
    FileClose $1

    ; Add file size to running total
    IntOp $InstallSize $InstallSize + $2
  ${EndIf}
FunctionEnd

;--------------------------------
;Install log

; Push <text> / Call InstallLog: DetailPrint <text> and append it to
; %TEMP%\OpenAccessEID-install.log, so an unattended (/S) install keeps a
; record of every warning it could not show. Also usable from .onInit, where
; DetailPrint has nowhere to print.
Function InstallLog
  Exch $R0
  Push $R1
  DetailPrint "$R0"
  ClearErrors
  FileOpen $R1 "$TEMP\OpenAccessEID-install.log" a
  ${IfNot} ${Errors}
    FileSeek $R1 0 END
    FileWrite $R1 "$R0$\r$\n"
    FileClose $R1
  ${EndIf}
  Pop $R1
  Pop $R0
FunctionEnd

;--------------------------------
;System32 DLL installation

; Push <file name> / Call InstallSystemDll
; Installs $INSTDIR\<file name> as $SYSDIR\<file name> (call with x64 file
; system redirection disabled) so that the new file is what is there after the
; next reboot. LSASS (and LogonUI) keep the current copy mapped, so it cannot be
; overwritten in place, and the uninstaller that ran before this install has
; usually queued "delete $SYSDIR\<file name>" for that reboot. So:
;   1. stage the new file next to it as <file name>.oaeid-new;
;   2. rename the current copy aside (Windows allows renaming a mapped DLL) and
;      queue the renamed file for deletion;
;   3. copy the staged file into place now, so this session (DllRegister, the
;      trace config) already uses the new version;
;   4. queue a reboot-time rename of the staged file over <file name>.
;      PendingFileRenameOperations is processed in the order the entries were
;      queued, so this runs after any delete of <file name> queued earlier and
;      leaves the new file in place.
; Stops the installation if the new file cannot even be staged: registering
; packages whose DLL is missing would leave LSA pointing at nothing.
Function InstallSystemDll
  Exch $R9
  Push $R8
  Push $R7
  StrCpy $R8 "$SYSDIR\$R9.oaeid-new"

  Push "$INSTDIR\$R9"
  System::Call 'kernel32::CopyFile(t s, t R8, i 0) i .R7'
  ${If} $R7 = 0
    Push "ERROR: could not write $R8. Installation stopped; nothing has been registered with LSA."
    Call InstallLog
    MessageBox MB_OK|MB_ICONSTOP "Could not write$\n$R8$\n$\nThe installation has been stopped before anything was registered with Windows. Free some disk space or check that no security product blocks writes to System32, then run the installer again." /SD IDOK
    Abort
  ${EndIf}

  ${If} ${FileExists} "$SYSDIR\$R9"
    System::Call 'ole32::CoCreateGuid(g .s)'
    Pop $R7
    StrCpy $R7 "$SYSDIR\$R9.oaeid-old-$R7"
    ClearErrors
    Rename "$SYSDIR\$R9" "$R7"
    ${IfNot} ${Errors}
      Delete /REBOOTOK "$R7"
    ${EndIf}
  ${EndIf}

  System::Call 'kernel32::CopyFile(t R8, t "$SYSDIR\$R9", i 0) i .R7'
  ${If} $R7 = 0
    Push "WARNING: $SYSDIR\$R9 is in use and could not be replaced now; the new version takes its place at the next reboot."
    Call InstallLog
  ${EndIf}

  ; MOVEFILE_REPLACE_EXISTING (1) | MOVEFILE_DELAY_UNTIL_REBOOT (4). Queued
  ; whatever happened above, so a delete queued earlier cannot win.
  System::Call 'kernel32::MoveFileEx(t R8, t "$SYSDIR\$R9", i 5) i .R7'
  ${If} $R7 = 0
    Push "ERROR: could not schedule $R8 to replace $SYSDIR\$R9 at the next reboot. If $SYSDIR\$R9 is missing after rebooting, run this installer again before rebooting a second time."
    Call InstallLog
    MessageBox MB_OK|MB_ICONEXCLAMATION "Could not schedule the new $R9 to be put in place at the next reboot.$\n$\nAfter rebooting, check that $SYSDIR\$R9 exists. If it does not, run this installer again." /SD IDOK
  ${EndIf}
  SetRebootFlag true

  Pop $R7
  Pop $R8
  Pop $R9
FunctionEnd

;--------------------------------
;Upgrade from uninstallers that delete enrolments

; Call NeutraliseOldUnregister / Pop <"1" | "0">
; Uninstallers of v2.0.00 and earlier run
;   rundll32 <System32>\<package DLL>,DllUnRegister
; and that DllUnRegister deletes every user's stored credential. This puts this
; version's package DLL - whose DllUnRegister only removes registrations - at
; that path first, so the old uninstaller runs it instead and the enrolments
; survive the upgrade. The DLL LSASS has loaded is renamed aside (Windows allows
; renaming a mapped DLL) and deleted at the next reboot; the old uninstaller then
; deletes the substitute, which nothing has mapped, at once. v1.3.00 and earlier
; use EIDAuthenticationPackage.dll; this version's DllUnRegister also removes
; registrations made under that name. Only the cleanup actions the operator
; ticks in the old uninstaller (none in a silent run) remove anything.
; "1" when the substitute is in place, "0" otherwise (the old DLL is then left
; exactly as it was).
Function NeutraliseOldUnregister
  Push $R9
  Push $R8
  Push $R7
  ${If} $MigratedFromLegacy == 1
    StrCpy $R9 "$SYSDIR\EIDAuthenticationPackage.dll"
  ${Else}
    StrCpy $R9 "$SYSDIR\OpenAccessEIDPackage.dll"
  ${EndIf}
  StrCpy $R8 0

  InitPluginsDir
  ClearErrors
  File "/oname=$PLUGINSDIR\OpenAccessEIDPackage.dll" "..\x64\Release\OpenAccessEIDPackage.dll"
  ${If} ${Errors}
    Push "Could not extract the substitute package DLL to $PLUGINSDIR."
    Call InstallLog
  ${Else}
    ${DisableX64FSRedirection}
    StrCpy $R7 ""
    ${If} ${FileExists} "$R9"
      System::Call 'ole32::CoCreateGuid(g .s)'
      Pop $R7
      StrCpy $R7 "$R9.oaeid-old-$R7"
      ClearErrors
      Rename "$R9" "$R7"
      ${If} ${Errors}
        Push "Could not rename $R9 aside."
        Call InstallLog
        StrCpy $R7 "failed"
      ${EndIf}
    ${EndIf}
    ${If} $R7 != "failed"
      ; bFailIfExists: the path has just been vacated.
      Push "$PLUGINSDIR\OpenAccessEIDPackage.dll"
      System::Call 'kernel32::CopyFile(t s, t R9, i 1) i .R8'
      ${If} $R8 = 0
        StrCpy $R8 0
        Push "Could not copy the substitute package DLL to $R9."
        Call InstallLog
        ; Put the original back so the old uninstaller still has its DLL.
        ${If} $R7 != ""
          Rename "$R7" "$R9"
        ${EndIf}
      ${Else}
        StrCpy $R8 1
        ${If} $R7 != ""
          Delete /REBOOTOK "$R7"
        ${EndIf}
        Push "Substituted this version's unregistration step for the old uninstaller's ($R9), so stored credentials are kept."
        Call InstallLog
      ${EndIf}
    ${EndIf}
    ${EnableX64FSRedirection}
  ${EndIf}

  StrCpy $R9 $R8
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

;--------------------------------
;ProgramData hardening
;
; Any user can create a subdirectory of C:\ProgramData, so the product directory
; (or the legacy C:\ProgramData\EIDAuthentication) may already exist owned by an
; unprivileged user, be a junction, or hold a planted logging.json or junction.
; LSASS and the trace consumer write and rotate logs there as SYSTEM, so the
; installer keeps only a tree that is entirely owned by SYSTEM/Administrators,
; writable by nobody else and free of reparse points, and locks the directory
; down itself. The checks and the lock-down are PowerShell scripts from
; Installer\scripts, extracted to $PLUGINSDIR.

; Extracts the installer's PowerShell helpers to $PLUGINSDIR.
Function ExtractEIDScripts
  InitPluginsDir
  File "/oname=$PLUGINSDIR\Test-EIDDirectoryTree.ps1" "scripts\Test-EIDDirectoryTree.ps1"
  File "/oname=$PLUGINSDIR\Lock-EIDDirectory.ps1" "scripts\Lock-EIDDirectory.ps1"
FunctionEnd

; Push <script file name> / Push <path> / Call RunEIDScript / Pop <result>
; Runs $PLUGINSDIR\<script> -Path <path> and returns its exit code, or nsExec's
; "error"/"timeout". The script is read and run as a script block, so a
; machine-wide PowerShell execution policy cannot block it, and the two strings
; travel in environment variables, so no quoting in a path can break the
; command line.
Function RunEIDScript
  Exch $R0
  Exch
  Exch $R1
  Push $R2
  Call ExtractEIDScripts
  Push "$PLUGINSDIR\$R1"
  System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_SCRIPT", t s)'
  System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_PATH", t R0)'
  nsExec::ExecToLog /TIMEOUT=120000 `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText($$env:OAEID_SCRIPT))) -Path $$env:OAEID_PATH; exit $$LASTEXITCODE"`
  Pop $R2
  StrCpy $R0 $R2
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

; Push <path> / Call IsReparsePoint / Pop <"1" | "0">: "1" when <path> itself
; is a junction, symbolic link or other reparse point. Does not follow it.
Function IsReparsePoint
  Exch $R9
  Push $R8
  System::Call 'kernel32::GetFileAttributes(t R9) i .R8'
  ${If} $R8 = -1
    StrCpy $R9 0
  ${Else}
    IntOp $R8 $R8 & 0x400
    ${If} $R8 <> 0
      StrCpy $R9 1
    ${Else}
      StrCpy $R9 0
    ${EndIf}
  ${EndIf}
  Pop $R8
  Exch $R9
FunctionEnd

; Push <path> / Call IsEIDDataTreeTrusted / Pop <result>:
;   "1" <path> and everything below it is owned by SYSTEM (S-1-5-18) or
;       Administrators (S-1-5-32-544), nothing is a reparse point, and no ACE
;       lets anyone but SYSTEM, Administrators or CREATOR OWNER write, create,
;       delete, change permissions or take ownership;
;   "0" not trusted (including an ACL that cannot be read);
;   "2" the check could not run: PowerShell missing, blocked, timed out or in
;       constrained language mode. That is neither answer - callers must not
;       move anything aside on it.
; The check stops at the first reparse point, so it never walks into a
; junction's target. See Installer\scripts\Test-EIDDirectoryTree.ps1.
Function IsEIDDataTreeTrusted
  Exch $R9
  Push "Test-EIDDirectoryTree.ps1"
  Push $R9
  Call RunEIDScript
  Pop $R9
  ${If} $R9 == 10
    StrCpy $R9 1
  ${ElseIf} $R9 == 11
    StrCpy $R9 0
  ${Else}
    StrCpy $R9 2
  ${EndIf}
  Exch $R9
FunctionEnd

; Push <directory> / Call LockEIDDirectory / Pop <"1" | "0">
; Owner Administrators and a protected DACL that replaces every other ACE: Full
; control for SYSTEM and Administrators, read/execute for Users, inherited by
; everything below (the runtime's EID_LOG_DIR_SDDL). PowerShell writes owner and
; DACL in one call; when that fails or cannot run, icacls does it in two (which
; leaves any extra explicit ACE in place - the trust check afterwards catches
; that). Never touches a reparse point.
Function LockEIDDirectory
  Exch $R9
  Push $R8
  Push $R9
  Call IsReparsePoint
  Pop $R8
  ${If} $R8 == 1
    Push "WARNING: not changing the permissions of $R9: it is a junction or symbolic link."
    Call InstallLog
    StrCpy $R9 0
  ${Else}
    Push "Lock-EIDDirectory.ps1"
    Push $R9
    Call RunEIDScript
    Pop $R8
    ${If} $R8 == 10
      StrCpy $R9 1
    ${Else}
      Push "Could not set the permissions of $R9 with PowerShell (result $R8); using icacls."
      Call InstallLog
      nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$R9" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX'
      Pop $R8
      ${If} $R8 == 0
        nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$R9" /setowner *S-1-5-32-544'
        Pop $R8
      ${EndIf}
      ${If} $R8 == 0
        StrCpy $R9 1
      ${Else}
        Push "WARNING: icacls could not secure $R9 (code $R8)."
        Call InstallLog
        StrCpy $R9 0
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Pop $R8
  Exch $R9
FunctionEnd

; Push <path> / Push <destination prefix> / Call MoveAside / Pop <new path, or "">
; Renames <path> to <destination prefix>.untrusted-<random GUID>. The suffix is
; random, so a standard user cannot pre-create the destination to block the
; move; a failed rename (typically a handle held open) is retried for about ten
; seconds. "" when it never succeeded.
Function MoveAside
  Exch $R8
  Exch
  Exch $R9
  Push $R7
  Push $R6
  StrCpy $R6 0
  ${Do}
    IntOp $R6 $R6 + 1
    System::Call 'ole32::CoCreateGuid(g .s)'
    Pop $R7
    StrCpy $R7 "$R8.untrusted-$R7"
    ClearErrors
    Rename "$R9" "$R7"
    ${IfNot} ${Errors}
      ${ExitDo}
    ${EndIf}
    StrCpy $R7 ""
    ${If} $R6 >= 5
      ${ExitDo}
    ${EndIf}
    Sleep 2000
  ${Loop}
  StrCpy $R9 $R7
  Pop $R6
  Pop $R7
  Exch
  Pop $R8
  Exch $R9
FunctionEnd

; Shown and recorded when an untrusted folder cannot be moved out of the way:
; until an administrator deals with it, OpenAccess EID writes no log files.
; Push <path> / Call WarnNotMovedAside
Function WarnNotMovedAside
  Exch $R9
  Push "WARNING: $R9 is a junction, is not owned by SYSTEM/Administrators or can be modified by other users, and could not be moved aside. OpenAccess EID will NOT write log files until an administrator deletes or renames it and runs this installer again."
  Call InstallLog
  MessageBox MB_OK|MB_ICONEXCLAMATION "$R9$\n$\nis a junction, is not owned by SYSTEM/Administrators, or can be modified by other users, and could not be moved aside (something may be holding it open).$\n$\nOpenAccess EID will NOT write log files until an administrator deletes or renames it and runs this installer again. Smart-card logon is not affected." /SD IDOK
  Pop $R9
FunctionEnd

; Create C:\ProgramData\OpenAccessEID and its logs directory, owned by
; Administrators, with inheritance from ProgramData removed: Full control to
; SYSTEM and Administrators, read-only to Users (the same DACL the runtime
; applies, EID_LOG_DIR_SDDL). An existing directory that fails
; IsEIDDataTreeTrusted is moved aside, never adopted: taking ownership of it
; would launder whatever was planted inside. Only the base directory is created
; before the lock-down; logs is created afterwards, so it inherits the protected
; DACL and is owned by whoever runs the installer (Administrators or SYSTEM) -
; it is never handed over with /setowner, which would give Administrators'
; ownership to something a standard user created in the meantime.
Function SecureEIDDataDir
  StrCpy $R9 "C:\ProgramData\OpenAccessEID"

  ${If} ${FileExists} "$R9"
    Push $R9
    Call IsEIDDataTreeTrusted
    Pop $R0
    ${If} $R0 == 0
      Push $R9
      Push $R9
      Call MoveAside
      Pop $R8
      ${If} $R8 == ""
        Push $R9
        Call WarnNotMovedAside
        Return
      ${EndIf}
      Push "WARNING: $R9 was a junction, not owned by SYSTEM/Administrators, or modifiable by other users; moved aside to $R8 for review."
      Call InstallLog
    ${ElseIf} $R0 == 2
      Push "WARNING: could not check $R9 (PowerShell did not run, or runs in constrained language mode); securing it in place instead of moving it aside."
      Call InstallLog
    ${EndIf}
  ${EndIf}

  ; Base directory only, then lock it before anything is created inside it.
  CreateDirectory "$R9"
  Push $R9
  Call IsReparsePoint
  Pop $R0
  ${If} $R0 == 1
    Push $R9
    Call WarnNotMovedAside
    Return
  ${EndIf}
  Push $R9
  Call LockEIDDirectory
  Pop $R0
  ${If} $R0 != 1
    Push "WARNING: could not secure $R9; OpenAccess EID will refuse to write logs there."
    Call InstallLog
    Return
  ${EndIf}

  ; Until the lock-down above, a standard user could create logs (or a junction
  ; called logs) in a directory this installer had just created. Now that nobody
  ; else can add anything, check it and move an untrusted one out of the tree.
  ${If} ${FileExists} "$R9\logs"
    Push "$R9\logs"
    Call IsReparsePoint
    Pop $R0
    ${If} $R0 == 1
      StrCpy $R0 0
    ${Else}
      Push "$R9\logs"
      Call IsEIDDataTreeTrusted
      Pop $R0
    ${EndIf}
    ${If} $R0 == 0
      Push "$R9\logs"
      Push "$R9-logs"
      Call MoveAside
      Pop $R8
      ${If} $R8 == ""
        Push "$R9\logs"
        Call WarnNotMovedAside
        Return
      ${EndIf}
      Push "WARNING: $R9\logs was a junction, not owned by SYSTEM/Administrators, or modifiable by other users; moved aside to $R8 for review."
      Call InstallLog
    ${EndIf}
  ${EndIf}

  CreateDirectory "$R9\logs"

  ; Final check of the whole tree, including anything else planted before the
  ; lock-down (the runtime also ignores a logging.json it does not trust).
  Push $R9
  Call IsEIDDataTreeTrusted
  Pop $R0
  ${If} $R0 == 0
    Push "WARNING: $R9 still contains items that are not owned by SYSTEM/Administrators or that other users can modify. Review and remove them; OpenAccess EID ignores an untrusted logging.json and log folder."
    Call InstallLog
    MessageBox MB_OK|MB_ICONEXCLAMATION "$R9 still contains items that are not owned by SYSTEM/Administrators or that other users can modify.$\n$\nReview and remove them. Until then OpenAccess EID may not write log files there." /SD IDOK
  ${ElseIf} $R0 == 2
    Push "WARNING: could not verify $R9 after securing it (PowerShell did not run, or runs in constrained language mode)."
    Call InstallLog
  ${EndIf}
FunctionEnd

;--------------------------------
;Initializer function

Function .onInit
  ${If} ${RunningX64}
  ${Else}
    MessageBox MB_OK "This installer is designed for 64bits only"
    Abort
  ${EndIf}

  ; Default for the security option.
  ;
  ; SECURITY: with this policy OFF, a credential may be sealed via the DPAPI
  ; path - CryptProtectData with CRYPTPROTECT_LOCAL_MACHINE and NO entropy - so
  ; the stored Windows password is recoverable by any administrator with no card
  ; and no PIN. The product's central claim only holds when this is ON.
  ;
  ; So: default ON for a genuinely FRESH install, and leave existing deployments
  ; alone. Defaulting ON unconditionally would silently re-lock existing
  ; non-card-bound (signature-only) enrollments out of logon on upgrade/repair,
  ; because silent (/S) installs never show the Security Options page.
  SetRegView 64
  StrCpy $MigratedFromLegacy 0
  StrCpy $EnrolmentsWiped 0
  ; Current install location, else one made under the former product name.
  ReadRegStr $9 HKLM "Software\OpenAccessEID" "InstallPath"
  ${If} $9 == ""
    ReadRegStr $9 HKLM "Software\EIDAuthentication" "InstallPath"
  ${EndIf}
  ${If} $9 == ""
    ; No prior installation - nothing can be re-locked, so be secure by default.
    StrCpy $RequireCardBound 1
  ${Else}
    ; Upgrade or repair: preserve today's behaviour and let the value already in
    ; force (read below) decide.
    StrCpy $RequireCardBound 0
  ${EndIf}
  StrCpy $SecurityPageShown 0

  ; On upgrade/repair, seed the checkbox from the policy value already in force so the
  ; page reflects reality instead of always rendering unchecked. This also means an
  ; admin who deliberately set 0 keeps 0.
  ClearErrors
  ReadRegDWORD $0 HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "RequireCardBoundCredentials"
  ${IfNot} ${Errors}
    StrCpy $RequireCardBound $0
  ${EndIf}

  ; Check for an existing installation - current name first, then the former
  ; EID Authentication name (v1.3.00 and earlier).
  SetRegView 64
  StrCpy $5 "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID"
  StrCpy $6 "OpenAccess EID"
  ReadRegStr $0 HKLM "Software\OpenAccessEID" "InstallPath"
  ${If} $0 == ""
    ReadRegStr $0 HKLM "Software\EIDAuthentication" "InstallPath"
    ${If} $0 != ""
      StrCpy $5 "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"
      StrCpy $6 "EID Authentication (the former name of OpenAccess EID)"
      StrCpy $MigratedFromLegacy 1
    ${EndIf}
  ${EndIf}
  StrCmp $0 "" CheckInstallEnd 0

  ; Uninstallers of v2.0.00 and earlier delete every user's stored credential
  ; while unregistering, whatever the cleanup checkboxes say. Newer ones keep
  ; them and record that with this marker (written by the Core section). For the
  ; older ones, NeutraliseOldUnregister (below) swaps in this version's
  ; unregistration step before running them.
  ClearErrors
  ReadRegDWORD $4 HKLM "$5" "KeepsEnrolmentsOnUninstall"
  ${If} $4 == 1
    StrCpy $3 "Smart-card enrollments and stored credentials are kept."
  ${Else}
    StrCpy $3 "The uninstaller of this older version deletes every user's stored smart-card credential. The installer replaces that step so that enrollments are kept; if it cannot, you will be asked before anything is removed."
  ${EndIf}

  ; Installation found - ask user to uninstall first
  MessageBox MB_YESNO "$6 is already installed at:$\n$0$\n$\nIt must be uninstalled first. $3$\n$\nUninstall it now?" /SD IDYES IDYES DoUninstall IDNO AbortInstall

  DoUninstall:
    InitPluginsDir

    ; The uninstaller deletes the whole smart-card policy key, which holds
    ; RequireCardBoundCredentials, RequireRevocationCheck and the other
    ; policies an administrator chose. Keep a copy and put it back afterwards
    ; so an upgrade does not silently reset them.
    ClearErrors
    nsExec::ExecToLog '"$SYSDIR\reg.exe" export "HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "$PLUGINSDIR\sccp-policy.reg" /y /reg:64'
    Pop $7

    ; Logging settings live under the install key, which the uninstaller also
    ; deletes. Migrating from the former name, copy them to the new key (which
    ; the old uninstaller never touches); otherwise keep a copy to put back.
    ${If} $MigratedFromLegacy == 1
      nsExec::ExecToLog '"$SYSDIR\reg.exe" copy "HKLM\SOFTWARE\EIDAuthentication\LogManager" "HKLM\SOFTWARE\OpenAccessEID\LogManager" /s /f /reg:64'
      Pop $8
      StrCpy $8 1
    ${Else}
      nsExec::ExecToLog '"$SYSDIR\reg.exe" export "HKLM\SOFTWARE\OpenAccessEID\LogManager" "$PLUGINSDIR\logmanager.reg" /y /reg:64'
      Pop $8
    ${EndIf}

    ; _?= makes ExecWait genuinely wait. Without it an NSIS uninstaller
    ; re-launches itself from a temporary copy and returns at once, so it
    ; would run concurrently with this install - and delete keys the new
    ; version has just written (credential provider CLSID, policies).
    ReadRegStr $1 HKLM "$5" "UninstallString"
    ${If} ${FileExists} "$1"
      ; An uninstaller that wipes enrolments: run it with this version's
      ; DllUnRegister in place of its own. If that cannot be arranged, an
      ; interactive upgrade asks; a silent one stops unless /WIPEENROLMENTS=1
      ; says that losing every enrolment is accepted.
      ${If} $4 != 1
        Call NeutraliseOldUnregister
        Pop $R0
        ${If} $R0 != 1
          ${If} ${Silent}
            ${GetParameters} $R1
            ClearErrors
            ${GetOptions} $R1 "/WIPEENROLMENTS=" $R2
            ${If} ${Errors}
            ${OrIf} $R2 != 1
              Push "ERROR: upgrade refused. The uninstaller of the installed version ($6) deletes every user's stored smart-card credential, and this installer could not replace that step (details above). The installed version has not been touched. Upgrade interactively, or run again with /WIPEENROLMENTS=1 to accept that every user must re-enrol."
              Call InstallLog
              Abort
            ${EndIf}
          ${Else}
            MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "The installer could not stop the uninstaller of the installed version from deleting every user's stored smart-card credential.$\n$\nIf you continue, every enrolled user must re-enrol their card after the upgrade.$\n$\nContinue anyway?" IDYES WipeAccepted
            Push "Upgrade cancelled: the old uninstaller would have deleted every stored smart-card credential."
            Call InstallLog
            Abort
            WipeAccepted:
          ${EndIf}
          StrCpy $EnrolmentsWiped 1
          Push "WARNING: running the old uninstaller unchanged; it deletes every user's stored smart-card credential."
          Call InstallLog
        ${EndIf}
      ${EndIf}

      ${If} ${Silent}
        ExecWait '"$1" /S _?=$0'
      ${Else}
        ExecWait '"$1" _?=$0'
      ${EndIf}
      ; Run in place, the uninstaller cannot delete itself or its directory.
      Delete "$1"
      RMDir "$0"
    ${EndIf}

    ${If} $7 == 0
      nsExec::ExecToLog '"$SYSDIR\reg.exe" import "$PLUGINSDIR\sccp-policy.reg" /reg:64'
      Pop $7
    ${EndIf}
    ${If} $8 == 0
      nsExec::ExecToLog '"$SYSDIR\reg.exe" import "$PLUGINSDIR\logmanager.reg" /reg:64'
      Pop $8
    ${EndIf}
    Goto CheckInstallEnd

  AbortInstall:
    Abort

  CheckInstallEnd:
FunctionEnd
