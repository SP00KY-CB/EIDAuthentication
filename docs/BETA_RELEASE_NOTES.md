# EID Authentication - Beta Release Notes

**Status:** Beta (v1.0.0-beta.1)
**Audience:** System administrators and security testers evaluating EID Authentication in non-production lab environments.

This document discloses known limitations, risks, and verification steps for the beta.
**Do not deploy this build to production endpoints.**

---

## 1. Unsigned installer and binaries

The installer and all shipped DLLs/EXEs are **not Authenticode-signed**. As a result:

- **SmartScreen / Defender**: Windows will warn on launch ("Windows protected your PC"). Click **More info** -> **Run anyway** to proceed.
- **LSA Protection (RunAsPPL)**: If LSA Protection is enabled on the target machine, LSASS will refuse to load `EIDAuthenticationPackage.dll`. CodeIntegrity event **3033** or **3065/3066** will be logged to the System event log.
  - Option A (recommended for evaluation): temporarily disable LSA Protection with the bundled helper
    `C:\Program Files\EID Authentication\tools\Disable-LsaProtection.ps1`
    (Start Menu -> EID Authentication -> **Disable LSA Protection (manual)**). The script self-elevates, shows a warning page, requires a typed confirmation, and backs up the prior state.
  - Option B: request a signed build by opening an issue at
    https://github.com/SP00KY-CB/OpenAccessEID/issues

> **Security trade-off:** Disabling LSA Protection removes a major defence against credential theft from LSASS (e.g., Mimikatz-class attacks). Only do this on a test machine that is not used for day-to-day work and does not hold real credentials. Re-enable it (`-Restore`) when testing is complete.

## 2. Integrity verification (SHA-256)

Every release publishes `SHA256SUMS.txt` alongside the installer. Before running `EIDInstallx64.exe`, verify its hash:

```powershell
certutil -hashfile EIDInstallx64.exe SHA256
```

Compare the output to the line for `Installer\EIDInstallx64.exe` in `SHA256SUMS.txt`. The manifest also covers every `.dll`/`.exe` the installer lays down, the three bundled smart-card minidrivers, and the ADMX/ADML policy files.

If available, a CycloneDX/SPDX SBOM is attached to the release as `EIDAuthentication-sbom.zip`.

## 3. No automated test coverage

The project currently ships **zero automated tests** (unit, integration, or end-to-end). All validation to date has been manual. Areas that have **not** been exercised by a test harness:

- LSA authentication package code paths (logon / unlock / change-password)
- Credential Provider tile state machine
- Migration export/import round-trip
- Certificate chain validation edge cases (revocation, name constraints, expiry)
- Concurrent smart-card removal during logon

Treat observed stability as anecdotal. File issues for any unexpected behaviour.

## 4. Air-gap / offline revocation policy

In this build, `EIDCardLibrary\CertificateValidation.cpp` treats the following chain-trust bits as **soft failures** (warn, do not hard-fail):

- `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`  (CRL/OCSP unreachable)
- `CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT`
- `CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT`

This lets the product work on air-gapped machines where CRL/OCSP endpoints are unreachable. The following bits are now **hard failures** (fixed in beta):

- `CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT`
- `CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT`
- Expiry / not-yet-valid / signature-invalid / untrusted-root / usage-invalid

If your environment requires strict revocation checking, do not use this beta until a configurable revocation-policy setting lands (tracked in `roadmap.md`).

## 5. LSASS risk reminder

`EIDAuthenticationPackage.dll` runs **inside LSASS**. A bug in that DLL can:

- Crash LSASS -> bugcheck and reboot
- Leak or corrupt credential material
- Bypass authentication

Beta-fixed LSASS issues:

- PIN length is now clamped against the `UNLEN` buffer bound before `memcpy_s` in `LsaApLogonUserEx2` (previously a caller-supplied `UNICODE_STRING.Length` could overflow the stack buffer in LSASS).

Unresolved risk: the LSA package has not been fuzzed. Do not run this build on a machine that authenticates real users.

## 6. View Log

The migration wizard's "View Log" button now launches **EIDLogManager.exe** (installed alongside the wizard). EIDLogManager surfaces ETW events from the product's providers. Direct CSV log export is not yet implemented.

## 7. Scope: local accounts only

This beta supports **local Windows accounts only**. The following are out of scope for v1.0.0-beta.1:

- Domain / Active Directory accounts
- Azure AD / Entra ID joined machines
- Microsoft Account (MSA) logins
- Remote Desktop / Terminal Services (RDS/RDP)
- Windows Hello for Business coexistence

Attempting to use the credential provider for a domain or cloud account will either fail silently or fall back to the default provider.

## 8. Known gaps (non-exhaustive)

- No code signing (see section 1).
- No automated tests (see section 3).
- EnforceCSPWhitelist policy is honoured, but the bundled whitelist is hard-coded; administrators should review `EIDCardLibrary\CertificateValidation.cpp` for the current entries before relying on it.
- Uninstaller removes certificates it installed, but does not restore the prior LSA-package list if the user manually edited `Authentication Packages` in the registry.

## 9. Reporting issues

Please file beta feedback (crashes, unexpected authentication outcomes, policy conflicts, installer failures) at:

> https://github.com/SP00KY-CB/OpenAccessEID/issues

When reporting, include:

- Output of `certutil -hashfile EIDInstallx64.exe SHA256` so we can confirm which build you ran
- Relevant System / Application event-log entries (CodeIntegrity 3033/3063/3065/3066 especially)
- Whether LSA Protection was enabled or disabled at the time
- Windows version (`winver`)
