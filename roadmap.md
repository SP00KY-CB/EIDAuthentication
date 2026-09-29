# OpenAccess EID - Roadmap

This document tracks unfinished features, known limitations, and potential enhancements for the OpenAccess EID project.

---

## Completed Features

The following features have been fully implemented:
- EIDMigrate CLI tool (export, import, list, validate commands)
- EIDMigrateUI Wizard (Export, Import, List, Validate flows)
- LSA secret storage and retrieval
- Certificate-based encryption (AES-256-GCM, PBKDF2)
- Smart card credential management
- Group membership during import
- ETW event logging
- View Log button launches EIDLogManager.exe
- ADMX/ADML administrative templates for Group Policy deployment
- SHA-256 release manifest + optional CycloneDX/SPDX SBOM generation in build.ps1
- Disable-LsaProtection.ps1 helper shipped in installer for evaluators
- EnforceCSPWhitelist GPO policy honoured in CSP whitelist check
- Name-constraint violations now hard-fail certificate chain validation
- PIN length clamp in LsaApLogonUserEx2 (prevents LSASS stack OOB)
- CI workflow builds installer on every PR / push to main
- Release workflow uses build.ps1 and publishes SHA256SUMS.txt + SBOM

---

## Outstanding Items

### 1. SSP Optional Functions (Conditional)

**Files:**
- `OpenAccessEIDPackage/EIDSecuritySupportProvider.cpp`
- `OpenAccessEIDPackage/EIDSecuritySupportProviderUserMode.cpp`

**Current Behavior:** The following Security Support Provider (SSP) functions return `STATUS_NOT_IMPLEMENTED`:

| Function | Purpose | Required For |
|----------|---------|--------------|
| `SpSetContextAttributes` | Set context attributes | Advanced scenarios |
| `SpSetCredentialsAttributes` | Set credential attributes | Credential roaming |
| `SpChangeAccountPassword` | Password change operations | Password management |
| `SpQueryMetaData` | Query metadata | Kerberos |
| `SpExchangeMetaData` | Exchange metadata | Kerberos |
| `SpGetCredUIContext` | Get credential UI context | Credential UI |
| `SpUpdateCredentials` | Update credentials | Credential roaming |
| `SpValidateTargetInfo` | Validate target info | Network authentication |
| `SpMakeSignature` | Message signing | Message integrity |
| `SpVerifySignature` | Signature verification | Message integrity |
| `SpSealMessage` | Message encryption | Privacy |
| `SpUnsealMessage` | Message decryption | Privacy |
| `SpCompleteAuthToken` | Complete auth token | Multi-stage auth |
| `SpFormatCredentials` | Format credentials | Credential storage |
| `SpMarshallSupplementalCreds` | Marshall supplemental creds | Credential roaming |
| `SpExportSecurityContext` | Export security context | Process isolation |
| `SpImportSecurityContext` | Import security context | Process isolation |

**Assessment:** These functions are **optional** for basic smart card logon. They are primarily needed for:
- Kerberos authentication
- Network authentication
- Credential roaming across machines
- SSO scenarios

**Decision Needed:** Determine if any of these scenarios are required for your deployment.

**Estimated Effort:** Variable (4-40 hours per function, depending on complexity)

---

### 2. Card Module Caching Functions (Performance Optimization)

**File:** `EIDCardLibrary/smartcardmodule.cpp:153-204`

**Current Behavior:** Stub implementations that do nothing:
- `_CacheAddFileStub()` - returns ERROR_SUCCESS
- `_CacheLookupFileStub()` - returns ERROR_NOT_FOUND
- `_CacheDeleteFileStub()` - returns ERROR_SUCCESS

**Purpose:** Caching improves CSP performance by avoiding repeated reads from the smart card.

**Proposed Implementation:**
1. Implement in-memory cache using a hash map or similar structure
2. Cache file contents after reading from card
3. Return cached data on lookup
4. Invalidate cache on card removal or context deletion

**Impact:** Performance optimization only. Current implementation works correctly but may be slower with repeated operations.

**Estimated Effort:** 8-12 hours

---

## Intentional Limitations (Not Issues)

The following items are intentional design choices and do not require action:

### 1. "Type not implemented" Warnings

**File:** `EIDCardLibrary/StoredCredentialManagement.cpp` (lines 827, 1087, 1547)

These are `default` cases in switch statements that handle unknown `EID_PRIVATE_DATA_TYPE` values gracefully. All currently defined types (ClearText, Crypted, DPAPI) are fully implemented.

### 2. Card Deauthenticate Fallback

**File:** `EIDCardLibrary/smartcardmodule.cpp:535`

Returns `ERROR_CALL_NOT_IMPLEMENTED` only if the underlying card module doesn't provide a deauthenticate function. This is a graceful fallback.

---

## Enhancement Ideas

Below are potential enhancements that are not currently tracked:

| Idea | Description | Priority |
|------|-------------|----------|
| Certificate validation options | Add option to validate certificate expiration during import | Medium |
| Batch import | Support importing multiple .eid files at once | Low |
| Progress cancellation | Allow user to cancel long-running operations | Low |
| Export filtering | Allow selective export of specific credentials | Low |
| Backup/restore scheduler | Automated credential backup on schedule | Low |
| Web-based management | Browser-based UI for credential management | Very Low |
| Multi-factor support | Combine smart card with additional factors | Very Low |

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-04-07 | Initial roadmap created |
| 1.0.0-beta.1 | 2026-04-19 | Beta-readiness pass: security fixes (PIN clamp, name-constraint hard fail, EnforceCSPWhitelist wired), View Log button implemented, ADMX/ADML + SHA-256 manifest + SBOM shipped, CI + release workflows rebuilt on build.ps1, Disable-LsaProtection.ps1 helper added. See `docs/BETA_RELEASE_NOTES.md`. |

---

## Contributing

When implementing items from this roadmap:

1. Create a feature branch from `main`
2. Reference this roadmap in commit messages
3. Update the roadmap item status when complete
4. Delete completed items from the Outstanding Items section

