# Security

`coned` talks directly to Con Edison and stores secrets only through the operating system credential store.

## Storage

- macOS keeps each secret in its own file under `~/Library/Application Support/coned/secrets` (mode `0600` in a `0700` directory), encrypted with AES-256-GCM and bound to its entry name. The 32-byte key lives in the login Keychain and is read and written only through `/usr/bin/security`.
  - The Keychain pins an item to the code identity that created it, and coned builds are ad-hoc signed, so an item written by coned itself would be unreadable to every later build. Apple's tool keeps one identity, so upgrades keep access without re-authentication.
  - The key item trusts only that tool, but any process running as the user can ask the tool for it while the Keychain is unlocked. The threat model below already excludes other processes of the same user.
  - Secrets that earlier releases stored directly in the Keychain move to sealed files the first time they are read. If an upgrade can no longer read one, `coned auth login --force` replaces it.
- Linux uses the freedesktop.org Secret Service API over D-Bus, commonly provided by GNOME Keyring. A default collection named `login` must be available.
- There is no plaintext fallback. Headless Linux must provide a working Secret Service session or use `auth login --no-store`.
- Non-secret configuration is stored at the OS configuration path with mode `0600`.
- Profiles isolate keyring entries.
- Each profile can have a random entity-handle HMAC key in the keyring. Handles are stable only within that profile and do not reveal provider identifiers.

## Authentication

`coned auth login` prompts without terminal echo. `--password-stdin` is available for operator-controlled automation; no password command-line flag exists. `--no-store` prevents newly obtained credentials and sessions from being persisted. Short-lived Okta and document-download URLs remain in memory.

Session cookies and passwords are never included in normal or JSON output. Errors reduce remote failures to typed categories and safe HTTP status/request identifiers. Debug HTTP-body logging is intentionally unsupported.

## Threat model

The CLI protects secrets at rest from accidental plaintext storage and reduces accidental disclosure through output, arguments, and errors. It cannot protect an unlocked account from the same OS user, a compromised keyring/session bus, a debugger, or a hostile root process.

Con Edison endpoints are private implementation details and may change. Protocol mismatches fail closed rather than following untrusted hosts or writing non-PDF responses.

Contract fixtures carry schema version, fixture version, provenance, and last-verified metadata. Structural diagnostics retain only paths and JSON types plus allowlisted service enums. Raw identifiers remain memory-only. Demo mode uses a deterministic offline provider and does not load production sessions or contact the network.

## Green Button downloads

Green Button result links must be HTTPS on an approved provider host. ZIP downloads are capped at 100 MiB and spooled only to a mode-`0600` temporary file. Archives reject encrypted files, symlinks, traversal names, excessive compression ratios, more than 20 entries, and entries larger than 500 MiB before extraction. Provider URLs, account identifiers, tokens, and response bodies are never emitted.

## Incident handling

If a credential, cookie, bearer token, HAR, or signed bill URL is exposed, lock/delete the local session, change the Con Edison password when appropriate, and remove the artifact. Never attach raw network captures to public bug reports.
