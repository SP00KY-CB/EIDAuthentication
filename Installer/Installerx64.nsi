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
          DetailPrint "WARNING: C:\ProgramData\EIDAuthentication is a junction, or it or something in it is not owned by SYSTEM/Administrators; not moved. Existing logs remain there."
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

  ; Create installation directory
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

  ; Copy DLLs to System32 (required for LSA and Credential Provider)
  ${DisableX64FSRedirection}
  ; Use /REBOOTOK to handle locked files (LSA loads DLLs at boot only)
  Delete /REBOOTOK "$SYSDIR\OpenAccessEIDPackage.dll"
  Delete /REBOOTOK "$SYSDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$SYSDIR\EIDPasswordChangeNotification.dll"

  CopyFiles /SILENT "$INSTDIR\OpenAccessEIDPackage.dll" "$SYSDIR\OpenAccessEIDPackage.dll"
  CopyFiles /SILENT "$INSTDIR\EIDCredentialProvider.dll" "$SYSDIR\EIDCredentialProvider.dll"
  CopyFiles /SILENT "$INSTDIR\EIDPasswordChangeNotification.dll" "$SYSDIR\EIDPasswordChangeNotification.dll"

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
    MessageBox MB_OK|MB_ICONEXCLAMATION "EID Authentication has been upgraded to OpenAccess EID.$\n$\nGroup Policy set through the old EIDAuthentication administrative template is NOT carried over. After rebooting, apply the OpenAccess EID template and re-apply any logging policies.$\n$\nThe EID Authentication uninstaller removed the stored smart-card credentials while unregistering: users must re-enrol their cards.$\n$\nA reboot is required before smart-card logon uses the new version." /SD IDOK
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

  ; Unregister all components first (from System32)
  ${DisableX64FSRedirection}
  DetailPrint "Unregistering components..."
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllUnRegister' $0
  ${If} $0 != 0
    DetailPrint "Warning: DllUnRegister returned error code $0 - continuing with manual cleanup"
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

  ; Conditionally remove EID credential mappings from LSA Private Data (if checkbox was selected)
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
;ProgramData hardening
;
; Any user can create a subdirectory of C:\ProgramData, so the product directory
; (or the legacy C:\ProgramData\EIDAuthentication) may already exist owned by an
; unprivileged user, be a junction, or hold a planted logging.json or junction.
; LSASS and the trace consumer write and rotate logs there as SYSTEM, so the
; installer keeps only a tree that is entirely owned by SYSTEM/Administrators and
; free of reparse points, and locks the directory down itself.

; Push <path> / Call IsEIDDataTreeTrusted / Pop <result>: "1" when <path> and
; everything below it is owned by SYSTEM (S-1-5-18) or Administrators
; (S-1-5-32-544) and nothing is a reparse point (attribute 1024); "0" otherwise,
; including when the check itself fails. Stops at the first reparse point, so it
; never walks into a junction's target.
Function IsEIDDataTreeTrusted
  Exch $R9
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference='Stop'; try { $$ok='S-1-5-18','S-1-5-32-544'; function T($$i) { if (($$i.Attributes -band 1024) -or ($$ok -notcontains (Get-Acl -LiteralPath $$i.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value)) { exit 1 } }; T (Get-Item -LiteralPath '$R9' -Force); Get-ChildItem -LiteralPath '$R9' -Recurse -Force | ForEach-Object { T $$_ }; exit 0 } catch { exit 1 }"`
  Pop $R9
  ${If} $R9 == 0
    StrCpy $R9 1
  ${Else}
    StrCpy $R9 0
  ${EndIf}
  Exch $R9
FunctionEnd

; Create C:\ProgramData\OpenAccessEID and its logs directory, owned by
; Administrators, with inheritance from ProgramData removed: Full control to
; SYSTEM and Administrators, read-only to Users (the same DACL the runtime
; applies, EID_LOG_DIR_SDDL). An existing directory that fails
; IsEIDDataTreeTrusted is moved aside, never adopted: taking ownership of it
; would launder whatever was planted inside.
Function SecureEIDDataDir
  ${If} ${FileExists} "C:\ProgramData\OpenAccessEID"
    Push "C:\ProgramData\OpenAccessEID"
    Call IsEIDDataTreeTrusted
    Pop $R0
    ${If} $R0 != 1
      ${GetTime} "" "L" $R1 $R2 $R3 $R4 $R5 $R6 $R7
      StrCpy $R8 "C:\ProgramData\OpenAccessEID.untrusted-$R3$R2$R1-$R5$R6$R7"
      ClearErrors
      Rename "C:\ProgramData\OpenAccessEID" "$R8"
      ${If} ${Errors}
        DetailPrint "WARNING: C:\ProgramData\OpenAccessEID is a junction or not owned by SYSTEM/Administrators and could not be moved aside. OpenAccess EID will not write logs there until an administrator removes it."
        Return
      ${EndIf}
      DetailPrint "WARNING: C:\ProgramData\OpenAccessEID was a junction or not owned by SYSTEM/Administrators; moved aside to $R8 for review."
    ${EndIf}
  ${EndIf}

  ; Base directory first, so logs is created under the locked-down DACL.
  CreateDirectory "C:\ProgramData\OpenAccessEID"
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "C:\ProgramData\OpenAccessEID" /setowner *S-1-5-32-544'
  Pop $R0
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "C:\ProgramData\OpenAccessEID" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX'
  Pop $R1
  CreateDirectory "C:\ProgramData\OpenAccessEID\logs"
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "C:\ProgramData\OpenAccessEID\logs" /setowner *S-1-5-32-544'
  Pop $R2
  ${If} $R0 != 0
  ${OrIf} $R1 != 0
  ${OrIf} $R2 != 0
    DetailPrint "WARNING: could not fully secure C:\ProgramData\OpenAccessEID (icacls codes $R0/$R1/$R2); OpenAccess EID may refuse to log there."
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
  ; them and record that with this marker (written by the Core section).
  ClearErrors
  ReadRegDWORD $4 HKLM "$5" "KeepsEnrolmentsOnUninstall"
  ${If} $4 == 1
    StrCpy $3 "Smart-card enrollments and stored credentials are kept."
  ${Else}
    StrCpy $3 "WARNING: the uninstaller of this older version deletes every user's stored smart-card credential. Users will have to re-enrol their cards afterwards."
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
