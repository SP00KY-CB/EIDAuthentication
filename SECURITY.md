# Security Policy

OpenAccess EID is a Windows credential provider and LSA authentication
package: it runs inside the logon path, partly in LSASS. Security reports are
taken seriously and handled with priority.

## Supported versions

Only the latest release receives security fixes. There is no backport
process; upgrading is the remediation path.

## Reporting a vulnerability

Please report vulnerabilities privately — do not open a public issue.

- Preferred: **GitHub private vulnerability reporting** — use *Report a
  vulnerability* under the repository's **Security** tab.
- You should receive an initial response within 7 days.

Please include the affected component (e.g. `EIDCredentialProvider.dll`,
`OpenAccessEIDPackage.dll`, installer), reproduction steps, and the
Windows version tested.

## Scope notes

- The threat model assumes **air-gapped, standalone machines** — findings
  that require network connectivity to the target machine may still be
  valid but are lower priority than local-attacker or logon-path issues.
- A full 8-domain security review of the codebase, including accepted
  residual risks, is documented in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
- Release artifacts are scanned with VirusTotal in CI and carry SLSA build
  provenance attestations (`gh attestation verify <file> --repo
  DangerDawgAU/EIDAuthentication`).
