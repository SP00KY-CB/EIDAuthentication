# OpenAccessEID — Security Review

**Scope:** full source audit of the OpenAccessEID smart-card logon stack (~44k LOC, C++/Win32).
**Method:** eight parallel domain reviewers (auth core, PKI/cert trust, stored-cred crypto, credential
provider, migration import, config/GPO/priv-esc, DLL/service/install, IPC/LSA-call/memory), followed by
manual verification of the highest-severity findings against the code.
**Threat model:** an attacker who wants to **bypass authentication, escalate privilege, steal
credentials, or abuse the system when in use.** Attacker positions considered: unprivileged local user,
local administrator, physical/console access to a locked machine, a malicious CSP/smart card, a
malicious migration file, and a hostile SSPI/`LsaCallAuthenticationPackage` caller.
**Branch:** `security-uplift`.  **Date:** 2026-07-11.

---

## 1. Executive summary

**The core of the product is sound.** Two independent reviewers confirmed there is **no
unauthenticated smart-card-logon bypass**: the logon path builds and verifies the certificate chain to
a trusted root, enforces the smart-card-logon EKU, binds the certificate to the account by an **exact
byte-for-byte match** (not a spoofable UPN/name), and — critically — **proves possession of the card
private key** via a real challenge/response (`CryptDecrypt`/`CryptSignHash` under the PIN) before any
token is minted. Presenting a public certificate alone does **not** authenticate. The untrusted IPC
surface also correctly authorizes callers (own-RID / admin) before acting.

**The real risk is concentrated in memory safety inside LSASS and in trust-injection / credential-theft
paths that require elevated or social-engineering preconditions.** No finding is a clean remote or
unprivileged **auth bypass**, so nothing is rated Critical — but two High findings are memory-corruption
defects in the SYSTEM-resident LSASS package that deserve top priority, and several trust-management
gaps (revocation not checked, one-click root-CA install, unvalidated import) could each degrade the
smart-card guarantee to "any attacker cert works" under the right conditions.

### Severity tally (post-triage)

| Severity | Count | Themes |
|---|---|---|
| Critical | 0 | (no unauth/unprivileged auth bypass found) |
| **High** | **4** | LSASS memory corruption ×2; stored-password recovery without card; malicious-import backdoor |
| **Medium** | **8** | revocation gap, root-CA/GPO trust injection, lock-screen wizard, SYSTEM log-ACL redirection, unquoted service path, import parsing OOB/DoS |
| **Low** | **11** | crypto hygiene, PIN residue, DLL-planting, pipe/filter/leak hardening |
| Info / verified-secure | many | see §5 |

### Top 5 to fix first
1. **H1** — validate the untrusted `LsaApCallPackage` submit buffer (arbitrary LSASS read / crash from an unprivileged user).
2. **H2** — bound the `memcpy` into the 32-byte `KEY_BLOB.Data` (LSASS stack overflow).
3. **H3** — stop storing passwords recoverable without the card (DPAPI/ClearText variants).
4. **M1** — actually check certificate **revocation** at logon.
5. **M2** — stop installing an `argv`-supplied root CA behind one UAC prompt.

---

## 2. Findings at a glance

| # | Sev | Title | Location |
|---|-----|-------|----------|
| H1 | High | Unvalidated client pointers in `LsaApCallPackageUntrusted` → arbitrary read / OOB write / crash in LSASS | `OpenAccessEIDPackage.cpp:322,328,340-344,425-427` |
| H2 | High | Unbounded `memcpy` into fixed 32-byte `KEY_BLOB.Data` → LSASS stack overflow | `StoredCredentialManagement.cpp:1596-1597` |
| H3 | High | DPAPI/ClearText stored credentials are recoverable without the card | `StoredCredentialManagement.cpp:142-170, 1785-1793, 1927-1946` |
| H4 | High | Migration import provisions users/passwords/admin-group with no file authenticity | `Import.cpp:373-559`; `LsaClient.cpp:595-698` |
| M1 | Med | Certificate revocation never enforced (revoked card still logs on) | `CertificateValidation.cpp:110-113,168-174,482-483` |
| M2 | Med | Elevated `TRUST`/`ENABLE*` verbs install argv-supplied root CA / flip auth GPOs on one UAC prompt | `EIDConfigurationWizard.cpp:91-124`; `CertificateValidation.cpp:597-641` |
| M3 | Med | Import enrolls an unvalidated (self-signed) cert as a logon credential | `Import.cpp:561-610` |
| M4 | Med | Lock-screen tile launches keymgr Forgotten-Password wizard + admin dialog on secure desktop | `helpers.cpp:232-348`; `CMessageCredential.cpp:285-306` |
| M5 | Med | Log dirs created with inherited ACLs → SYSTEM writer redirectable (junction) + audit disclosure | `CSVLogger.cpp:249`; `CSVConfig.cpp:170`; `EIDTraceConsumer.cpp:187` |
| M6 | Med | Unquoted LocalSystem service ImagePath (CWE-428) | `EIDTraceConsumer.cpp:684` |
| M7 | Med | Import `PayloadLength` unbounded (OOB read/DoS) + USHORT-truncated sizes feed LSASS secret | `FileCrypto.cpp:742-758`; `LsaClient.cpp:622-682` |
| M8 | Med | `EID_PRIVATE_DATA` parse integer underflow | `LsaClient.cpp:271,291,385-397` |
| L1–L11 | Low | crypto hygiene, PIN residue, filter no-op, DLL-planting, pipe DACL, JSON depth, etc. | see §4 |

---

## 3. High-severity findings

### H1 — Arbitrary read / OOB in LSASS via `LsaApCallPackageUntrusted` (unprivileged local)
**Location:** `OpenAccessEIDPackage/OpenAccessEIDPackage.cpp:322, 328, 340-344, 425-427`
**Category:** memory-safety / info-disclosure (LSASS, SYSTEM) · **Confidence:** high (verified in code)

Any local process can `LsaConnectUntrusted` + `LsaCallAuthenticationPackage` into this handler, which
runs in LSASS. It **discards `SubmitBufferLength`** (`UNREFERENCED_PARAMETER(SubmitBufferLength)`, line
322) and immediately writes `pBuffer->dwError = 0` (line 328) before any size or authorization check — an
out-of-bounds write if the caller submits a buffer shorter than `EID_CALLPACKAGE_BUFFER`. Worse, for
`EIDCMCreateStoredCredential` (reachable by a **non-admin** targeting their own RID, which passes
`MatchUserOrIsAdmin`), it rebases caller-authored pointer fields with no bounds check:

```c
pPointer = (PBYTE)pBuffer->wszPassword - (ULONG_PTR)ClientBufferBase + (ULONG_PTR)pBuffer;  // line 340
pBuffer->wszPassword = (PWSTR)pPointer;
pPointer = pBuffer->pbCertificate - (ULONG_PTR)ClientBufferBase + (ULONG_PTR)pBuffer;        // line 342
pBuffer->pbCertificate = pPointer;
pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pBuffer->pbCertificate,
                                            pBuffer->dwCertificateSize);                      // line 344
```

Since the caller allocated the client buffer it knows `ClientBufferBase` exactly, so
`server_addr = pBuffer + (chosen_ptr − ClientBufferBase)` is an **attacker-chosen absolute address in
LSASS**. `CertCreateCertificateContext` then reads up to `dwCertificateSize` bytes from it, and
`CreateCredential` reads `wszPassword` as a wide string from a second arbitrary address.

**Exploit:** (a) point `pbCertificate` at an unmapped address → reliable **LSASS access violation →
machine reboot (DoS)**; (b) point `wszPassword` at target LSASS memory → `CreateCredential` copies those
bytes into the caller's own stored credential, which the caller then reads back via the EIDMigrate export
path → **read of arbitrary LSASS memory = theft of other users' secrets.** The DoS + OOB-read primitive
alone justify High; if the read-back chain is fully practical this is Critical.
**This is the #1 fix.** Every other IPC path (`RemapPointer`/`SafeCheckBufferOverflow` on logon, the GINA
handlers) validates offsets against the buffer length — only this path omits it.

**Fix:** reject `SubmitBufferLength < sizeof(EID_CALLPACKAGE_BUFFER)` at entry; treat `wszPassword` /
`pbCertificate` as *offsets+lengths* and require `offset + size <= SubmitBufferLength` with overflow-safe
math (reuse `SafeCheckBufferOverflow`) **before** rebasing; cap `dwCertificateSize` against the remaining
buffer.

---

### H2 — LSASS stack buffer overflow: unbounded `memcpy` into 32-byte `KEY_BLOB.Data`
**Location:** `EIDCardLibrary/StoredCredentialManagement.cpp:1596-1597` (struct at 1363-1370)
**Category:** memory-safety (stack overflow in LSASS/SYSTEM) · **Confidence:** high (verified in code)

```c
struct KEY_BLOB { ... BYTE Data[CREDENTIALKEYLENGTH/8]; };   // 256/8 = 32 bytes
...
bKey.cb = dwResponseSize;
memcpy(bKey.Data, pResponse, dwResponseSize);               // no check dwResponseSize <= 32
```

`bKey` is a stack local; `Data` is 32 bytes. The only nearby guard (line 1585) checks the **challenge**
size, never the **response** size. `dwResponseSize`/`pResponse` are the plaintext output of the card
CSP's `CryptDecrypt` (or the caller's `dwResponseSize` on the GINA response path,
`OpenAccessEIDPackage.cpp:588-603`) — an oversized response smashes the LSASS stack → potential
**SYSTEM code execution**.

**Exploit preconditions:** a malicious/emulated CSP or physical card presenting an enrolled cert
(CSP substitution is only *audited*, not blocked, unless `EnforceCSPWhitelist` is on — see L-series), or a
TCB caller on the GINA response path. Elevated preconditions, but a clear memory-corruption defect on an
LSASS-resident path.

**Fix:** `if (dwResponseSize > sizeof(bKey.Data)) { fail; }` before the `memcpy`; also bound
`dwResponseSize` in `PerformGinaAuthenticationResponse` and `dwChallengeSize` in
`GetResponseFromCryptedChallenge` (line ~1202).

---

### H3 — Stored password recoverable **without the card** for DPAPI and ClearText credential variants
**Location:** `StoredCredentialManagement.cpp:142-170` (DPAPI seal), `1927-1946` (DPAPI unseal),
`1785-1793` (ClearText) · **Category:** crypto / credential-theft · **Confidence:** high

Stored credentials come in three variants selected by the *stored blob's own* `dwType`:
- **`eidpdtCrypted` — sound.** Random AES-256 key, RSA-wrapped to the cert public key; recovery needs the
  card private key + PIN. An attacker with the blob but no card cannot decrypt. (Verified good.)
- **`eidpdtDPAPI` — recoverable without the card.** The password is sealed with
  `CryptProtectData(..., CRYPTPROTECT_LOCAL_MACHINE)` and **no entropy** (line 151); recovery verifies the
  card signature but then unseals with `CryptUnprotectData(..., CRYPTPROTECT_LOCAL_MACHINE, ...)` (line
  1931) using only the machine DPAPI key. The card key plays **no role in confidentiality** — the
  signature gates the code path, not the ciphertext.
- **`eidpdtClearText` — plaintext at rest.** Read path returns the password verbatim after only a
  signature check (line 1792).

**Exploit:** any local Administrator/SYSTEM reads the `L$_EID_<rid>` LSA secret and, for a DPAPI blob,
calls `CryptUnprotectData(CRYPTPROTECT_LOCAL_MACHINE)` on that machine to recover the **cleartext Windows
password** — no card, no PIN, signature check skipped. This defeats the premise that the card protects the
stored secret; the recovered password is the user's real (often reused) domain/local password. ClearText
blobs are read directly. `CreateCredential` doesn't write these types today, but the read paths are live
and the EIDMigrate import path can persist them (see H4/M3).

**Fix:** encrypt every stored password under a key only the private key can recover (as `eidpdtCrypted`
already does); retire the DPAPI and ClearText variants, or refuse to load/import any credential with
`dwType != eidpdtCrypted`. A static entropy string is **not** a fix (recoverable from the binary).

---

### H4 — Malicious migration file provisions users / passwords / admin-group with no authenticity check
**Status: CLOSED (194be73)** for the single-issuer / trusted-operator deployment. Re-assessment narrowed the practical risk: M3 (938dbda) now requires the import cert to chain to a trusted root + SC-logon EKU + pass offline revocation (cert-injection closed); the password sink is operator-supplied at import, not read from the file. The remaining concern was provenance/authenticity — and the `.eidm` already stamps machine/operator/time *inside* the AES-GCM+HMAC authenticated payload (tamper-proof without the passphrase). H4 fix (#1): the CLI import now shows that stamp before applying anything and supports `-expect-source <machine>` to refuse a file not from the expected issuer; the GUI already surfaces machine+date. A machine signature (unforgeable even to a passphrase holder) was considered and **declined** as beyond this deployment's threat model (one trusted issuing system, air-gapped).
**Location:** `EIDMigrate/Import.cpp:373-559`; sink `EIDMigrate/LsaClient.cpp:595-698`
**Category:** logic / auth-bypass · **Confidence:** high (behavior explicit); severity bounded by `-force` + social engineering

The import file's integrity/authenticity rests **entirely on a shared passphrase** (PBKDF2 → AES-256-GCM
+ HMAC). There is **no signature and no origin proof** — and in a migration workflow the passphrase travels
with the file. Once decrypted, every field is trusted: `ImportSingleCredential` will **create arbitrary
local accounts** (`CreateLocalUserAccount`, line 396), **set their passwords** (line 533), **add them to
groups including `Administrators`** (`SynchronizeGroupMemberships`, line 298), install a certificate, and
write the LSA secret. `ValidateJsonSchema` is never called (see L-series), so there isn't even a shape
check.

**Exploit:** attacker crafts a `.eidm` that creates `svc_backup`, sets a known password, adds it to
`Administrators`, and installs their cert; an admin runs `EIDMigrate import -force <file>` with the
supplied passphrase → **persistent backdoor admin account.** (Default mode is dry-run; `-force` required.)

**Fix:** sign export files with the exporting host/operator key and verify against an allow-list before
applying anything; enforce a strict schema; require explicit per-account / per-group-membership
confirmation; never auto-add to privileged groups from file data.

---

## 4. Medium & Low findings

### Medium

- **M1 — Certificate revocation is never checked.** `CertificateValidation.cpp:482-483` builds the chain
  with **no** `CERT_CHAIN_REVOCATION_CHECK_*` flag, and `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` /
  `CRYPT_E_NO_REVOCATION_CHECK` / `CRYPT_E_REVOCATION_OFFLINE` are treated as soft (ignored) failures
  (lines 110-113, 168-174). A **revoked** card (lost/stolen/deprovisioned) still authenticates; an attacker
  can also force "revocation unknown" by blocking OCSP/CRL. *Fix:* pass
  `CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`; make `REVOCATION_STATUS_UNKNOWN` a hard failure for
  CA-issued chains via a policy that defaults fail-closed.

- **M2 — One-click root-CA install / GPO downgrade across the elevation boundary.**
  `EIDConfigurationWizard.cpp:91-124` re-launches its own image elevated (`runas`) and, for the `TRUST`
  verb, installs an **`argv[1]` base64 certificate** into the machine `Root`/`CA` store
  (`MakeTrustedCertifcate` → `CertificateValidation.cpp:597-641`) with no confirmation of which cert or
  store; `ENABLESIGNATUREONLY`/`ENABLENOEKU`/`ENABLETIMEINVALID` flip auth-weakening GPOs the same way.
  A single, under-described UAC prompt (attributed to the trusted-publisher wizard) installs an attacker
  **machine-wide trust anchor** → every cert the attacker issues then chains to trusted → smart-card logon
  bypass. *Fix:* have the elevated instance re-derive the cert from the card/thumbprint and re-validate it,
  and show an explicit "install `<subject>` as a trusted root for ALL users?" confirmation; prefer
  `TrustedPeople` over `Root`/`CA`.

- **M3 — Import enrolls an unvalidated (self-signed) certificate.** `Import.cpp:561-610`
  (`ValidateCertificateForImport`) checks **only NotBefore/NotAfter** — no chain, no revocation, no
  smart-card-logon EKU, no UPN/SID binding — then installs the cert (user MY store) and writes the LSA
  secret. *Interaction:* the logon path **does** independently re-validate chain-to-trusted-root + EKU +
  exact binding + private-key possession (see §5), so a self-signed import cert fails at logon **unless**
  `AllowSignatureOnlyKeys`/`AllowCertificatesWithNoEKU` is set or its root is trusted (cf. M2) — then it
  becomes a full bypass with the attacker's own key. Defense-in-depth gap; fix by validating chain/EKU/UPN
  at import time.

- **M4 — Lock-screen escape surface.** The "disconnected" message tile exposes a "disable force policy"
  command link (`CMessageCredential.cpp:285-306`, shown when `scforceoption` is set) that opens a secure-
  desktop dialog which can launch keymgr's **`PRShowRestoreFromMsginaW` Forgotten-Password wizard**
  pre-auth (`helpers.cpp:300-321`) and an ad-hoc `LogonUser` dialog that writes `scforceoption=0` (downgrades
  the smart-card-required policy). The reset wizard's Browse/Open dialogs are a classic secure-desktop
  escape. *Fix:* remove the external-wizard path from the credential provider; perform any "cancel force
  policy" action from an elevated helper only **after** an authenticated session; zero the `szPassword[256]`
  buffer at `helpers.cpp:246`.

- **M5 — SYSTEM log files created with inherited ACLs.** `CSVLogger.cpp:249`, `CSVConfig.cpp:170`,
  `EIDTraceConsumer.cpp:187` create `C:\ProgramData\OpenAccessEID\logs\...` via
  `CreateDirectoryW(..., nullptr)` + `CreateFileW(OPEN_ALWAYS)` with no explicit DACL. The CSV writer runs
  in **LSASS/SYSTEM** and the diagnostics writer in the **LocalSystem** trace-consumer service. Standard
  users inherit read + create rights on ProgramData → (a) read the auth audit trail (usernames/domains/
  session metadata; no secrets), (b) pre-create the path as a **junction/symlink** to redirect the SYSTEM
  writer's `OPEN_ALWAYS` → arbitrary-file create/append as SYSTEM. *Fix:* create with an explicit DACL
  (SYSTEM/Admins full, Users read-only, no create) and open refusing reparse points / verify final path+owner.

- **M6 — Unquoted LocalSystem service ImagePath (CWE-428).** `EIDTraceConsumer.cpp:684` passes a raw
  `GetModuleFileNameW` path **unquoted** to `CreateServiceW` for an auto-start LocalSystem service. If any
  earlier space-delimited segment is user-writable, a planted `*.exe` runs as SYSTEM at boot. *Fix:* quote
  the path.

- **M7 — Import size fields unbounded / truncated.** `FileCrypto.cpp:742-758` trusts the header's
  attacker-controlled `PayloadLength` (uint64) with no check against actual file size → heap OOB read /
  multi-GB allocation DoS (a hard SEH crash not caught by the top-level `catch(...)`). `LsaClient.cpp:622-682`
  casts JSON-supplied cert/key/password sizes to **USHORT** with no cap, so a ≥64 KB field truncates the
  stored size/offset while copying the full bytes — an inconsistent secret later parsed by the SYSTEM auth
  package. *Fix:* validate `filesize == header + PayloadLength + HMAC` (overflow-safe); reject fields >
  sane maxima and keep size fields consistent with bytes copied.

- **M8 — `EID_PRIVATE_DATA` integer underflow.** `LsaClient.cpp:271,291,385-397`:
  `dwDataSize = pSecretData->Length - sizeof(EID_PRIVATE_DATA)` underflows to ~4 GB when `Length` is
  short, defeating the subsequent bounds checks → OOB read. Admin-controlled boundary (LSA secret), so
  Medium. *Fix:* require `Length >= sizeof(EID_PRIVATE_DATA)` and use overflow-safe offset math.

### Low (hardening / hygiene)

- **L1** Stored-password ciphertext uses AES-**CBC with a constant zero IV** (no `KP_IV` ever set) — mitigated by a per-credential random key. `StoredCredentialManagement.cpp:1465-1533`.
- **L2** Stored-password ciphertext is **unauthenticated** (no MAC/AEAD) → tamperable (admin-write only; corruption just fails logon). Same file.
- **L3** Raw AES key left on the stack (`KEY_BLOB bKey`) **not zeroized** in the encrypt/decrypt helpers. `StoredCredentialManagement.cpp:1382-1460, 1562-1684`.
- **L4** **PIN residue**: `ReportResult` clears only the visible field, not `_rgFieldStrings[SFI_PIN]`, after a failed logon; `pwzProtectedPin` freed without zeroizing. `CEIDCredential.cpp:698-713, 789-857`.
- **L5** `CEIDFilter::Filter` is a **no-op** — advertised "hide password tiles when smart card mandatory" is never enforced (LSA still enforces at auth, so not a bypass). `CEIDFilter.cpp:38-52`.
- **L6** `SetSerialization` ignores `SspiUnmarshalCredUIContext` status on attacker-supplied bytes, never null-checks `pcpcs`, and **leaks** the context. `CEIDProvider.cpp:263-289`.
- **L7** `imageres.dll` **loaded by bare name** at 6 EIDMigrateUI sites → DLL-planting if launched from a writable dir. *Fix:* `LOAD_LIBRARY_SEARCH_SYSTEM32`.
- **L8** DebugReport **named pipe created with NULL DACL** + no client-identity check (mitigated by randomized name + same-user self-elevation). `DebugReport.cpp:239`.
- **L9** Recursive JSON parser has **no depth limit** → stack-overflow DoS on import. `JsonHelper.cpp:76-201`.
- **L10** `ValidateJsonSchema` is **dead code with inverted logic** (missing `!` on `formatVersion`) and is never called. `FileCrypto.cpp:425-448`.
- **L11** Misc: non-constant-time HMAC compare (`FileCrypto.cpp:733`); CSP-info name strings not verified NUL-terminated (`CertificateValidation.cpp:209-224`); SSP `ReceiveChallenge/ResponseMessage` lack offset/length bounds (mitigated by `SECPKG_FLAG_CLIENT_ONLY`); `LsaApLogonUserEx2` ignores `UserNameToProfile`/`CompletePrimaryCredential` results then forces `STATUS_SUCCESS` (robustness, not a bypass); elevated helper doesn't null/count-check `CommandLineToArgvW`; `EnforceCSPWhitelist`/`scremoveoption` read fail-open (admin-only keys); `MakeTrustedCertifcate` adds to machine `Root`/`CA` (admin-gated).

---

## 5. Verified secure (explicit negative results)

These were specifically checked and found **sound** — important for prioritization:

- **No smart-card-logon bypass.** Chain built + verified to a trusted root (`IsTrustedCertificate` →
  `CertGetCertificateChain` + `CertVerifyCertificateChainPolicy`); smart-card-logon EKU enforced; expiry
  enforced; **account↔cert binding is an exact byte-for-byte DER match** (`GetUsernameFromCertContext`,
  `StoredCredentialManagement.cpp:218-220`) — not a spoofable UPN; **private-key possession is genuinely
  proven** (`CryptDecrypt`/`CryptSignHash` under the PIN, verified with `CryptVerifySignature`) before any
  token is minted, on both the interactive and network-SSP paths.
- **Untrusted IPC authorization is enforced.** `MatchUserOrIsAdmin` impersonates the caller, resolves its
  RID, and checks Administrators membership; a non-admin can only target its own RID. (H1 is a memory bug,
  not an authz bypass.)
- **`eidpdtCrypted` stored-credential crypto is sound** (random AES-256 key RSA-wrapped to the cert;
  `CryptGenRandom` RNG; no secrets in logs/traces; debug TEMP-file storage disabled).
- **Export/import crypto is strong**: AES-256-GCM + encrypt-then-HMAC-SHA256, PBKDF2-HMAC-SHA256 @ 600k
  iterations, random salt/nonce, version-pinned (no downgrade); certs go to the user **MY** store (not
  Root); LSA secret names use a **locally re-resolved** RID (no path traversal); dry-run by default.
- **CWE-427 consumer-restart is fixed** (pure SCM API, no `CreateProcess`/`sc.exe`); **LSASS/card-module
  DLL loads are System32-pinned** (`SafeLoadLibrary`/`EIDLoadLibrarySystem32`); self-elevation launchers
  all use absolute image paths; **auth-controlling GPO keys are HKLM admin-only ACL'd** and their primary
  defaults are **fail-closed** — a normal user cannot flip them.

---

## 6. Prioritized remediation roadmap

1. **LSASS memory safety (H1, H2, M7, M8):** add strict length/offset/pointer validation at every LSASS
   trust boundary (untrusted call-package buffer, GINA response size, `KEY_BLOB` copy, `EID_PRIVATE_DATA`
   parse, import size fields). These are the highest-impact, lowest-regression-risk fixes.
2. **At-rest credential model (H3):** make private-key-bound encryption the *only* stored form; retire
   DPAPI/ClearText read+write paths.
3. **Trust integrity (M1, M2, M3):** enforce revocation fail-closed for CA chains; require confirmation +
   card re-derivation for root-CA install; validate chain/EKU/UPN at import.
4. **Backdoor prevention (H4):** sign+verify migration files; confirm account/group changes; never
   auto-add to privileged groups.
5. **Local priv-esc hardening (M5, M6, L7):** explicit DACLs on SYSTEM-written log dirs + reparse-point
   refusal; quote the service path; System32-pin all `LoadLibrary`.
6. **Lock-screen surface (M4):** remove the keymgr/reset-wizard path from the credential provider.
7. **Hygiene (L1–L4, L6, L8–L11):** zeroize key/PIN material, authenticated encryption, constant-time MAC,
   JSON depth limit, wire up schema validation, fix leaks/null-checks.

---

## 7. Appendix — per-domain detail

Full per-finding write-ups (exact code, exploit steps, fixes) were produced per domain and are the source
for this consolidation:

| Domain | Result |
|---|---|
| 01 LSA auth core | no bypass; 3 Med (H1/H2/M1 roots), 3 Low, 2 Info |
| 02 Certificate / PKI trust | **core sound**; 2 Med (M1, H2), 3 Low/Info |
| 03 Stored-credential crypto | 1 High (H3), 1 Med, 3 Low |
| 04 Credential provider | no bypass; 1 Med (M4), 3 Low, 1 Info |
| 05 Migration import | 2 High (H4, M3 root), 2 Med (M7), 3 Low |
| 06 Priv-esc / config / GPO | 1 Med (M2), 3 Low; policy keys admin-only (good) |
| 07 DLL / service / install | 2 Med (M5, M6), 2 Low, 3 verified-fixed/good |
| 08 IPC / LSA-call / memory | 1 High (H1), 1 High, 1 Med (M8) |

*Reviewed on branch `security-uplift`. No source was modified by this review.*
