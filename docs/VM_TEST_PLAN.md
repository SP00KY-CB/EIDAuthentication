# EIDAuthentication — VM Test Plan

> ## Part Z — additional gate for `security-fuzzing-hardening` (PR #54)
>
> This branch changes code on the interactive logon path, inside LSASS, in the
> installer, and in the credential export format. The rows below are **in
> addition to** everything already in this document, and each one exists because
> a specific defect was fixed there. Run them on a build from this branch.
>
> | # | Step | Expected | ✓ | Notes |
> |---|------|----------|---|-------|
> | Z1 | Smart-card logon, correct PIN. | Logon succeeds. **The whole branch is void if this fails** — it touches the CSP-info validator, the submit-buffer bounds check, the minidriver load path and the challenge length rule. | ☐ | |
> | Z2 | Smart-card logon, **wrong** PIN, then correct PIN. | Wrong PIN is refused with the usual message and the retry succeeds. Exercises the rewritten `__try/__finally` that now wipes the PIN on all eighteen exits. | ☐ | |
> | Z3 | Enrol a user with a **57–63 character** password, then log on with the card. | Both succeed. Before this branch, enrolment reported success and every later logon failed with `NTE_BAD_LEN` — the stored ciphertext landed exactly on the block boundary. | ☐ | |
> | Z4 | Enrol a user with a **64 character** password, then log on. | Both succeed. This length previously stored a truncated (effectively empty) password. | ☐ | |
> | Z5 | Enrol with an ordinary 8–20 character password and log on. | Succeeds — confirms the block-length change did not disturb the common case. | ☐ | |
> | Z6 | On a machine with an existing enrolment from **v1.3.00**, upgrade to this build and log on. | Succeeds. The stored-blob format is unchanged; only exact-multiple lengths behave differently. | ☐ | |
> | Z7 | Fresh install on a clean VM, then check `HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider\RequireCardBoundCredentials`. | Value is **1**. New installs are card-bound by default now. | ☐ | |
> | Z8 | Upgrade an existing install that has the policy at 0 (or absent). | Value is **unchanged**. An upgrade must never silently re-lock an existing signature-only enrolment. | ☐ | |
> | Z9 | With `RequireCardBoundCredentials=1`, attempt to enrol a **signature-only** card. | Enrolment is refused with a clear error. This is the intended trade for Z7. | ☐ | |
> | Z10 | Full install → uninstall → reinstall cycle. | All succeed. Seventeen helper launches in the installer moved from bare names to `$SYSDIR` absolute paths; a typo would surface here. | ☐ | |
> | Z11 | Silent install `EIDInstallx64.exe /S`, then silent uninstall. | Both complete without a prompt. | ☐ | |
> | Z12 | Confirm the scheduled task `EID Authentication\Apply Trace Config` exists after install and runs at boot. | Task present; trace config applied. Its `/TR` payload also changed to an absolute path. | ☐ | |
> | Z13 | `EIDMigrate` export to `.eidm` with a **17–32 character** passphrase, then import it on another VM. | Round-trips. That passphrase length previously overflowed a 32-byte stack buffer in the HMAC key path. | ☐ | |
> | Z14 | Import an `.eidm` produced by **v1.3.00**. | Imports successfully — the iteration count is now read from the file header rather than assumed. | ☐ | |
> | Z15 | Run the configuration wizard's **debug report** feature end to end. | Report is produced. The named pipe is now single-instance with `SECURITY_IDENTIFICATION`, and the path it receives is validated. | ☐ | |
> | Z16 | Corrupt `C:\ProgramData\EIDAuthentication\logging.json` (invalid JSON), then log on. | Logon succeeds, LSASS does not crash, and an ETW `[CONFIG_REJECT]` event is recorded. | ☐ | |
> | Z17 | Set `logPath` in `logging.json` to a path outside `C:\ProgramData\EIDAuthentication`. | Rejected; the default log path is retained. | ☐ | |
>
> **Rollback trigger:** any ❌ on Z1, Z2, Z5, Z6, Z8 or Z10. Those are the rows
> where a failure means existing users are locked out or cannot install.

---

## Original plan (security-uplift)

**Purpose:** Verify the `security-uplift` branch on a clean VM before merging to
`quality-fixes`. This is the explicit gate from `SECURITY_REVIEW.md`: every High/Medium
finding is code-complete, but nothing has been exercised end-to-end on a real machine.

**Branch under test:** `security-uplift` @ `43721a5`
**Installer:** `Installer\EIDInstallx64.exe` (rebuilt from this branch — confirm timestamp is
newer than commit `43721a5`, i.e. after 2026-07-15 22:20)
**Cards on hand:** MyEID Aventra (decrypt-capable), YubiKey PIV (decrypt-capable)

Work top to bottom. Tick each box; record the observed result in the Notes column when it
differs from Expected. A single ❌ on any **Core regression** or **must-block** row is a
merge blocker.

---

## Part A — Environment setup

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| A1 | Fresh Windows 11 VM (matching target build), **local account** only, not domain-joined. | Clean baseline. | ☐ | |
| A2 | Take a VM snapshot named `baseline-preinstall`. | Restore point exists. | ☐ | |
| A3 | Install the smart-card minidriver(s) for your card(s) if not already present (the installer bundles them under the Complete install type). | Card visible in `certutil -scinfo`. | ☐ | |
| A4 | Copy `EIDInstallx64.exe` to the VM. Verify its SHA-256 against `Installer\SHA256SUMS.txt`. | Hash matches. | ☐ | |
| A5 | Run the installer elevated → Complete. Reboot. | Installs with no errors; reboots clean. | ☐ | |
| A6 | Confirm files: `EIDAuthenticationPackage.dll`, `EIDCredentialProvider.dll` registered; `EIDConfigurationWizard.exe`, `EIDMigrate.exe`, `EIDMigrateUI.exe`, `EIDManageUsers.exe`, `EIDTraceConsumer.exe` present. **`EIDLogManager.exe` must be absent** (removed on this branch). | All present except EIDLogManager. | ☐ | |
| A7 | Take snapshot `installed-clean`. | Restore point exists. | ☐ | |

---

## Part B — Core regression (must still work)

These prove the security hardening didn't break the product. Any ❌ blocks merge.

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| B1 | Launch **EIDConfigurationWizard**, enroll the local account with the card (Option 2: real Windows password as backup). | Enrollment completes; cert bound to account. | ☐ | |
| B2 | Sign out. At the logon screen, select the smart-card tile, enter PIN. | Logs on from certificate only (no password typed). | ☐ | |
| B3 | Lock the workstation (Win+L), unlock with card + PIN. | Unlocks. | ☐ | |
| B4 | Wrong PIN at logon. | Rejected gracefully, no crash, retry allowed. | ☐ | |
| B5 | Remove card / no card present at logon. | Message tile shown; cannot log on with card. No secure-desktop wizard/reset dialog appears (M4). | ☐ | |
| B6 | Post-logon, confirm DPAPI-protected resource opens (proves stored password backup works). | Accessible. | ☐ | |
| B7 | Enroll a **second** account using the YubiKey (Option 1: blank password + blank-password GPO set). Log on with it. | Smart-card-only logon works. | ☐ | |
| B8 | Reboot; LSASS stable across several logon/lock cycles. | No LSASS crash, no event-log faults. | ☐ | |

---

## Part C — Security fix verification

Each row cites the finding. "must-block" rows are attacks the fix should now **prevent** —
a ❌ (i.e. the attack succeeds) is a merge blocker.

### H1 / H2 / M7 / M8 — LSASS memory safety

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-H1 | From an **unprivileged** user, exercise the credential-management IPC path (create/has/remove stored credential) via the normal UI flows, and with any available fuzz/malformed submit-buffer harness. | LSASS validates buffer; malformed input rejected with clean error, **no LSASS crash/read** (must-block). | ☐ | |
| C-H2 | Attempt enrollment / credential store with an over-length key blob (>32 bytes) if a test path allows. | Bounded copy; rejected, no overflow (must-block). | ☐ | |
| C-M7 | `EIDMigrate validate -i <crafted.eidm>` with an oversized/Forged `PayloadLength`. | Rejected with bounds error, no OOB/DoS (must-block). | ☐ | |
| C-M8 | Import a file with malformed `EID_PRIVATE_DATA` sizes. | Parse rejects; no underflow. | ☐ | |

### H3 — Card-bound stored credentials (`RequireCardBoundCredentials`)

Policy key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider`,
DWORD `RequireCardBoundCredentials` (default 0/off).

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-H3a | With policy **off** (default), confirm existing behavior unchanged (B1–B6 already cover this). | Baseline works. | ☐ | |
| C-H3b | Set `RequireCardBoundCredentials=1`. Re-enroll / log on with the decrypt-capable card. | Only card-wrapped (eidpdtCrypted) creds created & used; logon succeeds. | ☐ | |
| C-H3c | With policy **on**, attempt to create/import a DPAPI/ClearText (non-card-bound) credential. | Refused (must-block). | ☐ | |
| C-H3d | With policy **on**, confirm a previously stored DPAPI/ClearText cred is **not** usable at logon. | Rejected. | ☐ | |

### M1 — Offline certificate revocation

Policy key: same subkey, DWORD `RequireRevocationCheck` (default 0/off, fail-closed when 1).

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M1a | `EIDMigrate import-crl -i <valid-signed.crl>` (CLI). | CRL installed; signature verified. | ☐ | |
| C-M1b | `EIDMigrate import-crl -i <tampered-or-wrong-signer.crl>`. | Rejected — signature check fails (must-block). | ☐ | |
| C-M1c | **EIDMigrateUI → "Manage certificate revocation"** page: install a signed CRL + toggle `RequireRevocationCheck`. | GUI installs CRL and sets policy; no CLI needed. | ☐ | |
| C-M1d | With `RequireRevocationCheck=1` and a CRL that **revokes** the card's cert installed, attempt logon. | Logon denied — revoked cert rejected (must-block). | ☐ | |
| C-M1e | With `RequireRevocationCheck=1` but **no** CRL available (revocation "unknown"). | Fail-closed: logon denied. | ☐ | |
| C-M1f | Confirm the auth stack does **cache-only** checking — pull the network / stay air-gapped; a valid non-revoked cert with a cached CRL still logs on, and no outbound network attempt occurs. | Logon works offline; no network calls (Wireshark/loopback check optional). | ☐ | |

### M2 — Elevated trust-anchor install requires confirmation

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M2a | Run `EIDConfigurationWizardElevated.exe TRUST <cert>` (or via the wizard's elevated path). | Per-cert confirmation dialog shows **subject / issuer / SHA-1**, defaults to **No**; declining aborts install (must-block: no silent machine-wide root install). | ☐ | |
| C-M2b | Run `EIDConfigurationWizardElevated.exe ENABLESIGNATUREONLY` (and `ENABLENOEKU`, `ENABLETIMEINVALID`). | Each prompts for confirmation before weakening the GPO; declining aborts. | ☐ | |
| C-M2c | Confirm the policy keys are admin-write only (unprivileged user cannot set them). | Access denied for standard user. | ☐ | |

### M3 — Import validates the certificate

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M3a | `EIDMigrate import` (with `-force`) of a file whose cert is **self-signed / untrusted / wrong-EKU / revoked**, in production mode. | Import rejects the credential (chain + EKU + offline revocation reused via `IsTrustedCertificate`) (must-block). | ☐ | |
| C-M3b | Import of a file with a **valid, trusted, correct-EKU** cert. | Import succeeds. | ☐ | |

### H4 — Migration file provenance

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-H4a | `EIDMigrate export` on the issuing machine, then `EIDMigrate import`/`validate` on the VM. | CLI surfaces the provenance stamp (source **machine / operator / time**) held inside the AES-GCM+HMAC payload. | ☐ | |
| C-H4b | `EIDMigrate import -i <file> -expect-source <correct-machine>`. | Proceeds. | ☐ | |
| C-H4c | `EIDMigrate import -i <file> -expect-source <wrong-machine>`. | Refused before any account/password/group change (must-block). | ☐ | |
| C-H4d | Tamper with the `.eidm` bytes, then import with the correct passphrase. | AES-GCM/HMAC integrity fails; import aborts. | ☐ | |

### M5 / M6 — Install / service hardening

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M5 | Inspect ACLs on SYSTEM-written log dirs (CSV logger / trace consumer output). Attempt a junction/reparse redirect as a lower-priv writer. | Explicit DACL present; reparse redirect refused (must-block). | ☐ | |
| C-M6 | `sc qc <EID trace/consumer service>` — inspect `BINARY_PATH_NAME`. | Path is quoted (no unquoted-service-path CWE-428). | ☐ | |

### Audit / SIEM (supporting)

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-AUD1 | After exercising H1/H2/H3 paths and a migration, inspect the structured audit output (events CSV) and the event pipeline. | Security-control events emitted; migration audit routed to pipeline; CSV is SIEM-parseable (header + rows). | ☐ | |

---

## Part D — Group Policy / logging via GPO (EIDLogManager removed)

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| D1 | Load the ADMX/ADML (`Installer\PolicyDefinitions`) into the VM's local policy store; confirm the EID Authentication policy nodes appear (incl. ETW trace-session settings). | Policies visible in `gpedit.msc`. | ☐ | |
| D2 | Set trace/logging via GPO; confirm `EIDTraceConsumer` honors it (no EIDLogManager app needed). | Tracing controlled by policy. | ☐ | |
| D3 | Confirm no leftover EIDLogManager registration/shortcuts. | None. | ☐ | |

---

## Part E — Teardown

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| E1 | Uninstall via the installer's uninstaller (includes certificate cleanup). | Clean removal; account reverts to password logon. | ☐ | |
| E2 | Reboot; confirm normal password logon restored. | Logs on. | ☐ | |
| E3 | Restore `baseline-preinstall` snapshot to release the VM. | Clean. | ☐ | |

---

## Sign-off

- [ ] All **Core regression** (Part B) passed.
- [ ] All **must-block** attack rows in Part C blocked as expected.
- [ ] No LSASS crash observed at any point.
- [ ] Result recorded → clear to merge `security-uplift` → `quality-fixes`.

**Tester:** ____________  **Date:** ____________  **VM build:** ____________

## Uninstaller certificate cleanup (PR #53)

1. Install the build, enrol a user (creates root CA `CN=EID:<machine>` in
   LocalMachine Root and a user certificate issued by it).
2. Verify presence: `certutil -store root | findstr EID:` shows the CA;
   the enrolled user's My store contains the issued certificate.
3. Uninstall with "Remove EID Root Certificate Authority..." TICKED.
4. Verify: `certutil -store root | findstr EID:` -> nothing;
   `certutil -store ca | findstr EID:` -> nothing; enrolled user's My store
   has no cert issued by `EID:<machine>` (log on as that user or load the
   hive); `certutil -key | findstr /i <CA container>` -> gone.
5. Reinstall, uninstall again with the box UNTICKED -> CA cert, user certs
   and key container all survive.
