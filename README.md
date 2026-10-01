# OpenAccess EID for Windows

[![CI](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/windows-ci.yaml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/windows-ci.yaml)
[![CodeQL](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/codeql.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/codeql.yml)
[![VirusTotal Scan](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/scan-artifacts.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/scan-artifacts.yml)
[![Release Scan](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/release-vt-scan.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/release-vt-scan.yml)
[![Gitleaks](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-gitleaks.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-gitleaks.yml)
[![TruffleHog](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-trufflehog.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-trufflehog.yml)
[![Kingfisher](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-kingfisher.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-kingfisher.yml)
[![2MS](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-2ms.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-2ms.yml)
[![detect-secrets](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-detect-secrets.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-detect-secrets.yml)
[![GitGuardian](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-gitguardian.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/secret-gitguardian.yml)
[![Xygeni](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/xygeni.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/xygeni.yml)
[![Kusari Inspector](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/kusari.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/kusari.yml)
[![MegaLinter](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/megalinter.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/megalinter.yml)
[![KICS](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/kics.yml/badge.svg)](https://github.com/SP00KY-CB/OpenAccessEID/actions/workflows/kics.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=DangerDawgAU_EIDAuthentication&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=DangerDawgAU_EIDAuthentication)
[![Coverity Scan](https://img.shields.io/coverity/scan/33308.svg)](https://scan.coverity.com/projects/sp00ky-cb-openaccesseid)
[![Aikido Security](https://img.shields.io/badge/Aikido-security-1f6feb)](https://app.aikido.dev/repositories/2594845)
[![Aikido Code Quality](https://img.shields.io/badge/Aikido-code%20quality-1f6feb)](https://app.aikido.dev/repositories/2594845)
[![Snyk Security](https://snyk.io/test/github/SP00KY-CB/OpenAccessEID/badge.svg)](https://app.snyk.io/org/sp00ky-cb/project/936e041e-19b8-47c5-a278-2a090b81a88c)
[![Arnica](https://img.shields.io/badge/Arnica-monitored-1f6feb)](https://www.arnica.io/)
[![Corgea](https://img.shields.io/badge/Corgea-PR%20scanning-1f6feb)](https://corgea.com/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SP00KY-CB/OpenAccessEID/badge)](https://scorecard.dev/viewer/?uri=github.com/SP00KY-CB/OpenAccessEID)
[![License: LGPL-2.1](https://img.shields.io/github/license/SP00KY-CB/OpenAccessEID)](LICENSE)

**Certificate-based smart card logon for local Windows accounts, built for environments where Active Directory cannot be used.**

> Formerly released as **EID Authentication** (v1.3.00 and earlier); see [Upgrading from EID Authentication](#upgrading-from-eid-authentication-v1300-and-earlier).
>
> This project is a fork of **EIDAuthenticate Community Edition**, originally written by **Vincent Le Toux** ([My Smart Logon](https://www.mysmartlogon.com)). It is maintained independently and is not affiliated with or endorsed by My Smart Logon. For the commercially supported product, see My Smart Logon's EIDAuthenticate. See [Credits and license](#credits-and-license).

Supports any smart card with a Windows minidriver. The installer bundles minidrivers for Aventra MyEID, YubiKey, and Idemia IDOne PIV cards; the OpenSC minidriver extends coverage to many additional cards.

---

## Concept of Operations

OpenAccess EID provides certificate-based smart card logon for local Windows accounts. It registers an authentication package with the Windows Local Security Authority (LSA) and a credential provider with the logon UI, replacing password entry with card-and-PIN authentication on hosts that are not domain-joined. Enrollment, certificate validation, and authentication are performed entirely on the local machine; no Active Directory, domain controller, or network connectivity is required. This design targets standalone, isolated, and air-gapped systems where domain infrastructure is unavailable or prohibited by policy.

**Authentication Flow:**
1. User inserts smart card at Windows logon screen
2. Credential Provider displays PIN entry field
3. LSA Authentication Package validates PIN against smart card
4. Certificate extracted from card and verified against trust chain
5. User logged on with token generated from certificate-mapped local account

**Password Backup (Optional):** During enrollment, the Windows password can be encrypted with the smart card's public key and stored in LSA private data. This enables passwordless operation while maintaining DPAPI compatibility.

---

## Security Configuration

### Blank Password Accounts

**Warning:** By default, Windows allows local accounts with blank passwords to log on at the physical console without credentials. This bypasses smart card authentication.

**Default Windows Behavior:**

| Logon Type | Blank Password Account |
|------------|------------------------|
| Physical console | Allowed - can log in without credentials |
| Remote Desktop | Blocked |
| Network access (SMB) | Blocked |

**Required Group Policy:**

To enforce smart-card-only logon with passwordless accounts:

```
Computer Configuration > Windows Settings > Security Settings >
Local Policies > Security Options
```

**Policy:** `Accounts: Limit local account use of blank passwords to console logon only`

**Setting:** `Disabled` (blocks ALL blank password logons)

**Registry:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\limitblankpassworduse = 0
```

### Deployment Strategies

**Option 1: Smart-Card-Only (Recommended)**

1. Disable blank password logon via Group Policy (above)
2. Remove Windows passwords: `net user <username> ""`
3. Enroll with blank password in Configuration Wizard
4. Result: Smart card required for all logons

**Option 2: Smart Card + Password Backup**

1. Keep strong Windows passwords on accounts
2. Enter real password during enrollment
3. Result: Smart card required; password enables DPAPI/network auth

### Password Validation Behavior

| Phase | Password Validation |
|-------|-------------------|
| Enrollment | YES - wizard validates against Windows password |
| Authentication | NO - token created from certificate only |
| Post-Logon | Stored password used for DPAPI, network auth |

---

## Components

| Executable | Purpose |
|------------|---------|
| **EIDConfigurationWizard.exe** | Enrollment wizard for certificate creation, validation, and credential storage |
| **EIDConfigurationWizardElevated.exe** | UAC elevation helper for policy operations requiring admin rights |
| **EIDMigrate.exe** | Command-line tool for bulk credential export and import |
| **EIDMigrateUI.exe** | GUI wizard for credential backup and migration |
| **EIDTraceConsumer.exe** | Service that consumes ETW events and writes the structured CSV audit log |

| DLL | Purpose |
|-----|---------|
| **OpenAccessEIDPackage.dll** | LSA Authentication Package - core authentication logic running in LSASS |
| **EIDCredentialProvider.dll** | Credential Provider - integrates with the Windows logon screen |
| **EIDPasswordChangeNotification.dll** | Password Filter - synchronizes Windows password changes with stored credentials |

| Library | Purpose |
|---------|---------|
| **EIDCardLibrary.lib** | Static library providing smart card I/O, certificate management, and LSA IPC |

---

## Upgrading from EID Authentication (v1.3.00 and earlier)

This project was renamed to **OpenAccess EID** at v2.0.00. Running the new installer on a machine with EID Authentication installed removes the old version (keeping enrollments) and installs OpenAccess EID in its place. **A reboot is required**: Windows reads its LSA authentication-package list only at boot.

**Smart-card enrollments are preserved.** Stored credentials, certificates and the smart-card policies under `HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider` are carried over, so users do not re-enrol.

What changes, and what needs administrator action:

| Item | Old | New | Action |
|---|---|---|---|
| LSA package | `EIDAuthenticationPackage.dll` | `OpenAccessEIDPackage.dll` | None - the installer swaps the registration. Update any scripts that name the DLL. |
| Install folder | `C:\Program Files\EID Authentication` | `C:\Program Files\OpenAccess EID` | None. |
| Logs and `logging.json` | `C:\ProgramData\EIDAuthentication` | `C:\ProgramData\OpenAccessEID` | Re-point any SIEM collector or scheduled task. If the move fails (a file held open), existing logs stay in the old folder and the installer says so. |
| Logging settings | `HKLM\SOFTWARE\EIDAuthentication\LogManager` | `HKLM\SOFTWARE\OpenAccessEID\LogManager` | None - copied across. |
| Group Policy template | `EIDAuthentication.admx`, namespace `EIDAuthentication.Policies` | `OpenAccessEID.admx`, namespace `OpenAccessEID.Policies` | **Re-apply logging policies** using the new template, and copy it to any central PolicyDefinitions store. Settings made through the old template are not carried over. |
| Scheduled task | `EID Authentication\Apply Trace Config` | `OpenAccess EID\Apply Trace Config` | None. |

Component names keep the `EID` prefix (`EIDCredentialProvider.dll`, `EIDMigrate.exe`, and so on), all GUIDs are unchanged, and the stored-credential format is identical.

## Software Architecture

### Authentication Package (OpenAccessEIDPackage.dll)

Implements the Windows LSA Authentication Package interface (`SpLsaModeInitialize`).

**Key Functions:**
- `LsaApLogonUserEx2` - Primary authentication entry point
- `LsaApCallPackage` - Trusted IPC (challenge-response protocol)
- `LsaApCallPackageUntrusted` - Untrusted IPC (credential CRUD operations)

**IPC Message Types:**
| Message | Purpose |
|---------|---------|
| `EIDCMCreateStoredCredential` | Store encrypted password backup |
| `EIDCMUpdateStoredCredential` | Update stored password after Windows password change |
| `EIDCMRemoveStoredCredential` | Remove stored credential |
| `EIDCMHasStoredCredential` | Check if credential exists |
| `EIDCMGetStoredCredentialRid` | Lookup user RID from certificate hash |
| `EIDCMEIDGinaAuthenticationChallenge` | Initiate challenge-response |
| `EIDCMEIDGinaAuthenticationResponse` | Submit challenge response |

**LSA Private Data Keys:** Format `L$_EID__<RID_HEX>` with a double underscore (e.g., `L$_EID__000003E9` for RID 1001)

### Credential Provider (EIDCredentialProvider.dll)

Implements `ICredentialProvider` and `ICredentialProviderCredential` interfaces.

**COM Registration:**
- CLSID: `{B4866A0A-DB08-4835-A26F-414B46F3244C}`
- Usage Scenarios: `CPUS_LOGON`, `CPUS_UNLOCK_WORKSTATION`, `CPUS_CREDUI`

**Classes:**
| Class | Interface | Purpose |
|-------|-----------|---------|
| `CEIDProvider` | `ICredentialProvider` | Main provider, enumerates credentials |
| `CEIDCredential` | `ICredentialProviderCredential` | Smart card credential tile with PIN entry |
| `CMessageCredential` | `ICredentialProviderCredential` | Status message when no card present |
| `CEIDFilter` | `ICredentialProviderFilter` | Filters credential providers |

### Smart Card Library (EIDCardLibrary)

**Core API - SmartCardModule.h:**
```cpp
MgScCardAcquireContext()     // Connect to card via minidriver
MgScCardAuthenticatePin()    // Verify PIN
MgScCardReadFile()           // Read card file
MgScCardWriteFile()          // Write card file
MgScCardDeauthenticate()     // End authenticated session
MgScCardDeleteContext()      // Cleanup
```

**Core API - StoredCredentialManagement.h:**
```cpp
CStoredCredentialManager::CreateCredential()    // Store encrypted password
CStoredCredentialManager::GetPassword()         // Retrieve via certificate+PIN
CStoredCredentialManager::GetChallenge()        // Generate auth challenge
CStoredCredentialManager::GetPasswordFromChallengeResponse()  // Decrypt via challenge
CStoredCredentialManager::UpdateCredential()    // Re-encrypt after password change
CStoredCredentialManager::RemoveStoredCredential()
```

**Core API - CContainer.h:**
```cpp
CContainer::GetUserName()       // Extract username from certificate
CContainer::GetRid()            // Extract Relative ID from certificate
CContainer::GetCertificate()    // Return certificate context
CContainer::GetCSPInfo()        // Build CSP info for authentication
```

**Data Structures - EIDCardLibrary.h:**
```cpp
struct EID_INTERACTIVE_LOGON {
    EID_INTERACTIVE_LOGON_SUBMIT_TYPE MessageType;  // KerbCertificateLogon = 13
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
    ULONG Flags;
    ULONG CspDataLength;
    PUCHAR CspData;           // Smart card CSP data
};

struct EID_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer[...];
};
```

### Password Change Notification (EIDPasswordChangeNotification.dll)

Windows Password Filter API implementation:
- `InitializeChangeNotify()` - DLL initialization
- `PasswordFilter()` - Pre-change validation (accepts all)
- `PasswordChangeNotify()` - Post-change handler - calls `CStoredCredentialManager::UpdateCredential()`

---

## Registry Integration

### LSA
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` = `OpenAccessEIDPackage`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` = `EIDPasswordChangeNotification`

### Credential Provider
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{B4866A0A-DB08-4835-A26F-414B46F3244C}`
- `HKCR\CLSID\{B4866A0A-DB08-4835-A26F-414B46F3244C}`

### Configuration Wizard
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{F5D846B4-14B0-11DE-B23C-27A355D89593}`

### Group Policy
`HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider`

| Policy | Type | Default | Purpose |
|--------|------|---------|---------|
| `AllowSignatureOnlyKeys` | DWORD | 0 | Accept signature-only keys |
| `AllowCertificatesWithNoEKU` | DWORD | 0 | Accept certificates without Smart Card Logon EKU |
| `AllowTimeInvalidCertificates` | DWORD | 0 | Accept expired certificates |
| `EnforceCSPWhitelist` | DWORD | 0 | Block non-whitelisted CSP providers |
| `RequireCardBoundCredentials` | DWORD | 0 | Only card-wrapped credentials may be created, used at logon, or imported |
| `RequireRevocationCheck` | DWORD | 0 | Refuse a card whose revocation status cannot be confirmed offline |

**Note:** `0` = Disabled, `1` = Enabled. These policies are **disabled by default** for security. Only enable if specifically required for your environment.

Logging and ETW trace settings are managed under `HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager`
via the bundled ADMX template (`Installer\PolicyDefinitions`). Values set there override the local
configuration.

#### `RequireCardBoundCredentials`

When enabled, a user's Windows password is only ever stored sealed to their smart card, so it cannot
be recovered from the machine without the card and its PIN. This requires a **decrypt-capable** card
(MyEID/Aventra and YubiKey PIV qualify). Signature-only cards cannot use card-bound storage and will
fail to enrol or log on while this is set, which is why it is opt-in and why the installer never
changes an existing value during an upgrade. Enable it after a successful logon test.

#### `RequireRevocationCheck` and offline CRLs

Revocation checking in this project is **offline only** — the auth stack never reaches the network
(`CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL`), because target machines are air-gapped. Revocation data must
therefore be distributed to each machine explicitly:

```cmd
EIDMigrate.exe import-crl <path-to-crl>
```

The CRL's signature is verified against an already-trusted issuer before installation. The same
operation is available from EIDMigrateUI's "Manage certificate revocation" page, which also toggles
this policy.

> **Operational warning:** with `RequireRevocationCheck=1` the stack fails **closed**. If no CRL is
> installed — or the installed CRL's `nextUpdate` has passed — every card's revocation status is
> "unknown" and **every logon on that machine is refused**. On air-gapped hosts a CRL expires with no
> way to refresh itself automatically, so track CRL validity and re-import before `nextUpdate`, or
> leave this policy disabled.

---

## Smart Card Compatibility

OpenAccess EID uses the Windows smart card minidriver model rather than any single vendor stack. Any card with a working Windows minidriver can be used, including PIV-compliant cards; the minidriver mapped to the card by Windows is located and loaded at runtime.

**Bundled Minidrivers:**

The installer bundles three minidrivers (SHA-256 verified at build time, staged by `Installer\Stage-Minidrivers.ps1`) and installs them without internet access. Offline installation matters on isolated and air-gapped hosts. The "Smart Card Minidrivers" section is auto-selected for the Complete install type.

| Minidriver | Version | Cards |
|------------|---------|-------|
| Aventra MyEID | 3.0.1.2 (Certified) | Aventra MyEID (tested with MyEID 4.5) |
| Yubico YubiKey Smart Card Minidriver | 5.0.4.273 (x64) | YubiKey with PIV enabled |
| Idemia IDOne PIV | 2.4.3 (Microsoft Update catalog) | IDOne PIV cards |

**Wider Compatibility via OpenSC:**

The OpenSC project provides a Windows minidriver (installed by the OpenSC MSI) that covers a broad range of additional cards, including many national eID cards and other PKCS#15-capable tokens. Cards supported by the OpenSC minidriver work with OpenAccess EID the same way as cards using vendor minidrivers. OpenSC is not bundled; obtain it from https://github.com/OpenSC/OpenSC/releases.

**Other Compatible Cards:**
- PIVKey cards via PIVKey Minidriver
- Gemalto/eGem 4B cards
- Any PIV-compliant card with a Windows minidriver

**Minidriver Integration:**
- Uses `SCardGetCardTypeProviderName()` to locate the minidriver DLL
- Dynamically loads via `CardAcquireContext` (Card Module API)
- All cryptographic operations are performed on-card (private keys never leave the card)

**Important Notes for YubiKey Users:**
- **The YubiKey Smart Card Minidriver must be installed** before using the Configuration Wizard. The installer's "Smart Card Minidrivers" section installs it; it can also be downloaded from https://www.yubico.com/support/download/yubikey-minidriver/
- The YubiKey minidriver has known limitations with on-card key generation. If you encounter "smart card is read only" errors during certificate creation:
  - Generate keys/certificates externally using YubiKey Manager (`ykman`)
  - Then use the "Existing Certificate" option in the Configuration Wizard

---

## Security Properties

| Property | Implementation |
|----------|----------------|
| PIN Storage | Never stored - used once per auth, erased via `SecureZeroMemory()` |
| Private Keys | Never leave smart card - all crypto operations on-card |
| Credential Storage | Encrypted with certificate public key, stored in LSA private data |
| Certificate Validation | Full chain validation with CRL checking |
| Hash Algorithm | SHA-256 (32 bytes) |
| Encryption | Certificate-based or DPAPI fallback |
| Replay Protection | Challenge-response protocol |
| CSP Injection Protection | Whitelist enforcement via `EnforceCSPWhitelist` policy |

---

## System Requirements

- **OS:** Windows 7 SP1+ (x64 only)
- **Build:** Visual Studio 2022, Platform Toolset v143, C++23
- **Runtime:** Smart Card Resource Manager (SCardSvr), Smart Card Device Enumeration (ScDeviceEnum)

---

## Bulk User Import/Export

The EIDMigrate tools enable bulk backup and migration of smart card credentials between machines. Credentials are exported to an encrypted `.eid` file format and can be restored to the same or a different machine.

### Tools

| Tool | Purpose |
|------|---------|
| **EIDMigrate.exe** | Command-line interface for export/import operations |
| **EIDMigrateUI.exe** | GUI wizard for step-by-step migration |

### Command-Line Usage

```cmd
# Export all local credentials to encrypted file
EIDMigrate.exe export -local -output backup.eid -password "passphrase-16-chars-min" -v

# Import credentials from file
EIDMigrate.exe import -local -input backup.eid -password "passphrase-16-chars-min" -v

# List all stored credentials
EIDMigrate.exe list -local -v

# Validate exported file
EIDMigrate.exe validate -input backup.eid -password "passphrase-16-chars-min" -v
```

### GUI Wizard

The EIDMigrateUI wizard provides four migration flows:

1. **Export** - Select credentials, confirm, and export to encrypted file
2. **Import** - Select file, preview credentials, and import to local machine
3. **List** - View all stored credentials (local machine or from file)
4. **Validate** - Verify file integrity and credential count

### File Format

Export files use the `.eid` extension with the following security:

- **Encryption:** AES-256-GCM (PBKDF2-HMAC-SHA256 key derivation)
- **Password:** Minimum 16 characters required
- **Integrity:** HMAC-SHA256 signature
- **Content:** Credentials, groups, and metadata in JSON format

### Important Notes

- **Password Requirement:** Export/import passwords must be at least 16 characters
- **Certificate Installation:** Imported certificates are automatically installed to the user's MY store
- **LSA Secret Format:** Uses double underscore format: `L$_EID__<HEX_RID>`
- **Cross-Machine:** Exported files can be imported to different machines

---

## Code Signing

The beta releases of OpenAccess EID are **unsigned**. Windows "LSA
Protection" (also known as `RunAsPPL` or Protected Process Light) will refuse to
load unsigned plug-ins into LSASS, which blocks the authentication package
and password-change notification DLL. To test the unsigned beta, LSA
Protection must be disabled on the target machine.

### Prefer a signed build

If you would rather not weaken LSA Protection, request a code-signed
release by opening an issue at:
<https://github.com/SP00KY-CB/OpenAccessEID/issues>

### Disable LSA Protection (manual, admin-only)

The installer ships a PowerShell helper that prints a warning page,
probes the current state, backs up the prior values, and toggles
`RunAsPPL`:

```
%ProgramFiles%\OpenAccess EID\tools\Disable-LsaProtection.ps1
```

A Start Menu shortcut is also created: **OpenAccess EID >
Disable LSA Protection (manual)**. The script requires Administrator
rights and will self-elevate. It must never be run on production
workstations, domain controllers, or any host holding cached credentials
of value: disabling LSA Protection allows tools such as Mimikatz to
read LSASS memory.

### Registry values involved

| Path | Value | Type | Meaning |
|------|-------|------|---------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL` | DWORD | `0` = off, `1` = on (UEFI lock), `2` = on (no UEFI lock, Win11 22H2+) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPLBoot` | DWORD | Win11 24H2+ boot-time equivalent |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe` | `AuditLevel` | DWORD | `8` = audit (log, don't block) for CodeIntegrity events 3033/3063/3065/3066 |

If LSA Protection was enabled with UEFI lock on a Secure Boot host, a
registry change alone is not sufficient; the UEFI variable must be
cleared with Microsoft's `LsaPplConfig.efi` opt-out tool
(<https://www.microsoft.com/download/details.aspx?id=40897>). The
PowerShell helper detects this case and prints a warning.

Authoritative reference:
<https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>

### Production deployment (signed builds)

For production deployments, all three LSA-loaded binaries must be
code-signed:

- `OpenAccessEIDPackage.dll` (LSA Authentication Package)
- `EIDPasswordChangeNotification.dll` (Password Change Notification)
- `EIDCredentialProvider.dll` (Credential Provider; loaded by LogonUI rather than LSASS, signed as a matter of policy)

Signing the first two requires enrolment in Microsoft's [LSA file-signing
service](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-manage)
(not a regular Authenticode certificate; Microsoft-countersigned binaries
only). Until a signed release is cut, beta users must disable LSA
Protection.

---

## Building

**Requirements:**
- Visual Studio 2022 with C++23 support (Platform Toolset v143)
- NSIS (Nullsoft Scriptable Install System) for installer creation

**Build Commands:**

```powershell
# Release build (default)
.\build.ps1

# Debug build
.\build.ps1 Debug x64
```

**What Gets Built:**

| Component | Description |
|-----------|-------------|
| `OpenAccessEIDPackage.dll` | LSA Authentication Package |
| `EIDCredentialProvider.dll` | Credential Provider |
| `EIDPasswordChangeNotification.dll` | Password Filter |
| `EIDConfigurationWizard.exe` | Enrollment wizard |
| `EIDTraceConsumer.exe` | ETW-to-CSV audit log service |
| `EIDMigrate.exe` | Migration CLI tool (x64 only) |
| `EIDMigrateUI.exe` | Migration GUI wizard (x64 only) |
| `EIDInstallx64.exe` | NSIS installer (Release x64 only) |

**Output Location:**
- Built binaries: `x64\Release\` or `x64\Debug\`
- Installer: `Installer\EIDInstallx64.exe`

---

## Credits and license

OpenAccess EID is derived from **EIDAuthenticate Community Edition** by **Vincent Le Toux**, Copyright (C) 2009 Vincent Le Toux / Copyright (C) 2009-2011 My Smart Logon, originally published at <https://sourceforge.net/projects/eidauthenticate/>. The authentication package, credential provider, card library and configuration wizard in this repository are built on his original work, and his copyright notices are retained in the source files derived from it. Later modifications are copyright their respective contributors (see the git history).

This fork is maintained independently. It is not affiliated with, reviewed by or endorsed by Vincent Le Toux or My Smart Logon,. Problems with this fork should be reported here, not to the original author.

Licensed under the GNU Lesser General Public License version 2.1, the same license as the original work. See [LICENSE](LICENSE).
