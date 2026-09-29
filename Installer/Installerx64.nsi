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
  Name "EID Authentication"
  OutFile "EIDInstallx64.exe"

  ;Installer icon (optional - copied by build.ps1 if exists)
  Icon "installer.ico"
  UninstallIcon "installer.ico"

  ;Default installation folder
  InstallDir "$PROGRAMFILES64\EID Authentication"

  ;Get installation folder from registry if available
  InstallDirRegKey HKLM "Software\EIDAuthentication" "InstallPath"

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
;Uninstaller Variables

  Var /GLOBAL Uninstall_RemoveMappings
  Var /GLOBAL Uninstall_RemoveCertificates

;--------------------------------
;Installer Sections

Section "Core" SecCore
  SectionIn RO 1 2

  ; Initialize install size counter
  StrCpy $InstallSize 0

  ; Create installation directory
  SetOutPath "$INSTDIR"

  ; Install DLL files to Program Files
  FILE "..\x64\Release\EIDAuthenticationPackage.dll"
  Push "$INSTDIR\EIDAuthenticationPackage.dll"
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
  ; custom EID Authentication policies appear in gpedit.msc.
  ; Destination: %WINDIR%\PolicyDefinitions (picked up by Group Policy
  ; Editor automatically on next launch).
  DetailPrint "Installing Group Policy templates..."
  SetOutPath "$WINDIR\PolicyDefinitions"
  File "PolicyDefinitions\EIDAuthentication.admx"
  SetOutPath "$WINDIR\PolicyDefinitions\en-US"
  File "PolicyDefinitions\en-US\EIDAuthentication.adml"
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
  Delete /REBOOTOK "$SYSDIR\EIDAuthenticationPackage.dll"
  Delete /REBOOTOK "$SYSDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$SYSDIR\EIDPasswordChangeNotification.dll"

  CopyFiles /SILENT "$INSTDIR\EIDAuthenticationPackage.dll" "$SYSDIR\EIDAuthenticationPackage.dll"
  CopyFiles /SILENT "$INSTDIR\EIDCredentialProvider.dll" "$SYSDIR\EIDCredentialProvider.dll"
  CopyFiles /SILENT "$INSTDIR\EIDPasswordChangeNotification.dll" "$SYSDIR\EIDPasswordChangeNotification.dll"

  ; Create Start Menu folder and shortcuts for all executables
  CreateDirectory "$SMPROGRAMS\EID Authentication"
  CreateShortcut "$SMPROGRAMS\EID Authentication\Configuration Wizard.lnk" "$INSTDIR\EIDConfigurationWizard.exe" "" "$INSTDIR\EIDConfigurationWizard.exe" 0
  CreateShortcut "$SMPROGRAMS\EID Authentication\Credential Migration (CLI).lnk" "$INSTDIR\EIDMigrate.exe" "" "$INSTDIR\EIDMigrate.exe" 0
  CreateShortcut "$SMPROGRAMS\EID Authentication\Credential Migration (GUI).lnk" "$INSTDIR\EIDMigrateUI.exe" "" "$INSTDIR\EIDMigrateUI.exe" 0
  CreateShortcut "$SMPROGRAMS\EID Authentication\Manage Users.lnk" "$INSTDIR\EIDManageUsers.exe" "" "$INSTDIR\EIDManageUsers.exe" 0
  CreateShortcut "$SMPROGRAMS\EID Authentication\Trace Consumer.lnk" "$INSTDIR\EIDTraceConsumer.exe" "" "$INSTDIR\EIDTraceConsumer.exe" 0
  ; Elevated PowerShell shortcut for the LSA Protection toggle script.
  ; Uses -NoExit so the warning page and outcome remain visible after the
  ; script returns; ExecutionPolicy Bypass scoped to this process only.
  CreateShortcut "$SMPROGRAMS\EID Authentication\Disable LSA Protection (manual).lnk" \
    "powershell.exe" \
    '-NoProfile -NoExit -ExecutionPolicy Bypass -File "$INSTDIR\tools\Disable-LsaProtection.ps1"' \
    "$INSTDIR\cred_provider.ico" 0 SW_SHOWNORMAL "" \
    "Manually disable Windows LSA Protection so unsigned EID DLLs can load. Reads a warning page and requires confirmation."
  CreateShortcut "$SMPROGRAMS\EID Authentication\Uninstall.lnk" "$INSTDIR\EIDUninstall.exe" "" "$INSTDIR\EIDUninstall.exe" 0

  ; Create desktop shortcut pointing to Program Files
  CreateShortcut "$DESKTOP\EID Authentication Configuration.lnk" "$INSTDIR\EIDConfigurationWizard.exe"

  ; Create uninstaller in installation directory
  WriteUninstaller "$INSTDIR\EIDUninstall.exe"

  ; Write installation path to registry
  SetRegView 64
  WriteRegStr HKLM "Software\EIDAuthentication" "InstallPath" "$INSTDIR"

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
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "DisplayName" "EID Authentication"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "UninstallString" "$INSTDIR\EIDUninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "Publisher" "EID Authentication"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "DisplayIcon" "$INSTDIR\cred_provider.ico"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "NoRepair" 1

  ; Convert total install size from bytes to KB and write to registry
  IntOp $InstallSize $InstallSize / 1024
  ; Add ~100 KB for uninstaller and directory structures
  IntOp $InstallSize $InstallSize + 100
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "EstimatedSize" $InstallSize

  ; Register authentication package (from System32)
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\EIDAuthenticationPackage.dll",DllRegister'

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
  nsExec::ExecToLog '"$SYSDIR\rundll32.exe" "$SYSDIR\EIDAuthenticationPackage.dll",DllApplyTraceConfigW'
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Create /F /RU SYSTEM /RL HIGHEST /SC ONSTART /TN "EID Authentication\Apply Trace Config" /TR "$SYSDIR\rundll32.exe $SYSDIR\EIDAuthenticationPackage.dll,DllApplyTraceConfigW"'

  SetPluginUnload manual
  SetRebootFlag true

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
  LangString DESC_SecCore ${LANG_ENGLISH} "Core EID Authentication components: LSA Authentication Package, Credential Provider, Configuration Wizard, Log Manager, Migrate CLI/UI, and Manage Users tool. Always installed."
  LangString DESC_SecCore ${LANG_FRENCH}  "Composants principaux EID Authentication: LSA, Credential Provider, assistant de configuration et outils associes. Toujours installes."

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
  !insertmacro MUI_HEADER_TEXT "Security Options" "Choose how EID Authentication protects stored credentials."

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
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\EIDAuthenticationPackage.dll",DllUnRegister' $0
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
    ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\EIDAuthenticationPackage.dll",CleanupEIDCertificates' $2
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
    ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\EIDAuthenticationPackage.dll",CleanupLsaCredentials' $1
    ${If} $1 != 0
      DetailPrint "Note: LSA cleanup returned code $1 (may be expected if not installed)"
    ${EndIf}
    ${EnableX64FSRedirection}
  ${Else}
    DetailPrint "Skipping LSA credential mapping removal (not selected)"
  ${EndIf}

  ; Delete Start Menu shortcuts and folder
  Delete "$SMPROGRAMS\EID Authentication\Configuration Wizard.lnk"
  Delete "$SMPROGRAMS\EID Authentication\Credential Migration (CLI).lnk"
  Delete "$SMPROGRAMS\EID Authentication\Credential Migration (GUI).lnk"
  Delete "$SMPROGRAMS\EID Authentication\Manage Users.lnk"
  Delete "$SMPROGRAMS\EID Authentication\Trace Consumer.lnk"
  Delete "$SMPROGRAMS\EID Authentication\Disable LSA Protection (manual).lnk"
  Delete "$SMPROGRAMS\EID Authentication\Uninstall.lnk"
  RMDir "$SMPROGRAMS\EID Authentication"

  ; Delete desktop shortcut
  Delete "$DESKTOP\EID Authentication Configuration.lnk"

  ; Delete System32 files (LSA-locked, require reboot)
  ${DisableX64FSRedirection}
  Delete /REBOOTOK "$SYSDIR\EIDAuthenticationPackage.dll"
  Delete /REBOOTOK "$SYSDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$SYSDIR\EIDPasswordChangeNotification.dll"

  ; Delete ETW log files
  Delete /REBOOTOK "$SYSDIR\LogFiles\WMI\EIDCredentialProvider.etl"

  ${EnableX64FSRedirection}

  ; Remove Group Policy administrative templates
  Delete "$WINDIR\PolicyDefinitions\EIDAuthentication.admx"
  Delete "$WINDIR\PolicyDefinitions\en-US\EIDAuthentication.adml"

  ; Delete Program Files installation - DLLs
  Delete "$INSTDIR\EIDAuthenticationPackage.dll"
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
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /F /TN "EID Authentication\Apply Trace Config"'
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
  DeleteRegKey HKLM "Software\EIDAuthentication"

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
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"

  SetPluginUnload manual
  SetRebootFlag true

  MessageBox MB_OK "EID Authentication has been uninstalled. Please reboot your computer to complete the removal."

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
  ClearErrors
  ReadRegStr $9 HKLM "Software\EIDAuthentication" "InstallPath"
  ${If} ${Errors}
  ${OrIf} $9 == ""
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

  ; Check if already installed via registry
  SetRegView 64
  ReadRegStr $0 HKLM "Software\EIDAuthentication" "InstallPath"
  StrCmp $0 "" CheckInstallEnd 0

  ; Installation found - ask user to uninstall first
  MessageBox MB_YESNO "EID Authentication is already installed at:$\n$0$\n$\nDo you want to uninstall it first?" IDYES DoUninstall IDNO AbortInstall

  DoUninstall:
    ; Read uninstaller path
    ReadRegStr $1 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "UninstallString"
    ExecWait '"$1"'
    Goto CheckInstallEnd

  AbortInstall:
    Abort

  CheckInstallEnd:
FunctionEnd
