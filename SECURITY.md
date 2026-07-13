# Security Policy

## Supported versions

Until the first stable release, security fixes are provided only for the latest released version.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's **Report a vulnerability** / private security advisory feature for this repository. If that feature is unavailable, contact the maintainer through the private contact method listed on the `zzwong` GitHub profile.

Include only the minimum information needed to reproduce the issue. Do not send real passwords, MFA codes, cookies, bearer tokens, account identifiers, bills, signed download URLs, HAR files, or unredacted provider responses.

You should receive an acknowledgement within 7 days. Disclosure timing will be coordinated after impact and remediation are understood.

## Scope

Particularly relevant reports include:

- Credential or session disclosure
- Authentication or redirect validation bypasses
- Unsafe file creation, traversal, or symlink handling
- Diagnostic or error-message privacy leaks
- Archive extraction vulnerabilities
- Cross-profile data or keyring isolation failures
- Dependency vulnerabilities reachable by this program

Con Edison website outages, account support requests, and provider API changes without a security impact should use normal issue reporting.

See [docs/security.md](docs/security.md) for the storage model, trust boundaries, and operational limitations.
