# coned-cli

[![CI](https://github.com/zzwong/coned-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/zzwong/coned-cli/actions/workflows/ci.yml)
[![golangci-lint](https://img.shields.io/github/actions/workflow/status/zzwong/coned-cli/ci.yml?branch=main&label=golangci-lint&logo=go)](https://github.com/zzwong/coned-cli/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A headless CLI for accessing Con Edison account, billing, and energy-usage data.

`coned` supports:

- Native login with SMS MFA and remembered devices
- Secure credential and session storage backed by the OS keyring
- Bill history and validated PDF downloads
- Historical usage, costs, forecasts, weather, and neighbor comparisons
- Green Button CSV, JSON, XML, and ZIP exports
- Human-readable tables and structured JSON output
- A deterministic offline demo that requires no account or network access

The project is pre-1.0. Commands and JSON schemas may change between minor releases. Authentication credentials and utility data are sensitive; review [the security model](docs/security.md) before use.

## Install

Download a release archive, verify its checksum, and, when the `gh` CLI is available, verify its GitHub build provenance:

```bash
sha256sum -c checksums.txt --ignore-missing
gh attestation verify coned-cli_<version>_<os>_<arch>.tar.gz --repo zzwong/coned-cli
```

Alternatively, install with Go:

```bash
go install github.com/zzwong/coned-cli/cmd/coned@latest
```

To build from a checkout:

```bash
make install
```

Go 1.26.8 or newer is required. Release binaries are available for Linux and macOS on amd64 and arm64.

## Try it without an account

Demo mode is deterministic, offline, and isolated from your keyring:

```bash
coned --demo --json entities list
coned --demo usage forecast
coned --demo usage reads --aggregate hour \
  --from 2026-01-01 \
  --to 2026-01-02
```

## Authentication

```bash
coned auth init
coned auth login
coned auth status
coned auth logout
coned auth logout --forget
```

Interactive password input is hidden. With persistence enabled, credentials and session cookies are stored in Linux Secret Service, or on macOS in files encrypted with a key held in the Keychain, which keeps access across upgrades ([details](docs/security.md#storage)). Credentials are saved only after confirmation, and there is no plaintext fallback.

For a one-off session:

```bash
coned auth login --no-store
```

For operator-controlled input, pass one newline-terminated password through standard input:

```bash
printf '%s\n' "$CONED_PASSWORD" | \
  coned auth login --password-stdin --no-store
```

Prompts and progress messages go to standard error, so standard output carries only results. For automation, `--json` makes `auth login` write one JSON event per line to standard output. `{"event":"mfa_required"}` is written just before the verification code is read from standard input, and `{"event":"authenticated"}` ends a successful login:

```bash
coned --json auth login
```

There is intentionally no `--password` argument.

If native login is unavailable, `auth import-browser` can import an authenticated local Chrome or Brave session over a loopback CDP endpoint:

```bash
coned auth import-browser
```

## Bills

```bash
coned bills list
coned --json bills list
coned bills download 2026-06-30-<id>
coned bills download 2026-06-30-<id> --output bill.pdf
coned bills sync --directory "$HOME/Bills"
coned --json-envelope bills sync --since 2026-01-01 --directory "$HOME/Bills"
```

Bill PDFs are first written to an owner-only temporary file with mode `0600`. Before atomically moving the file to its destination, `coned` verifies the PDF file signature and enforces the download size limit. Existing files are left unchanged unless you pass `--force`.

`bills sync` is an automation command for Linux and macOS. The directory must
already exist. It downloads only the newest bill when `--since` is omitted;
otherwise it downloads bills with a document date strictly later than the
exclusive `--since YYYY-MM-DD` cutoff. It processes selected dates oldest
first and writes `coned-bill-<public-bill-id>.pdf` without replacing existing
files. Existing files are skipped only after owner, regular-file, PDF-signature,
size, and checksum verification. Invalid files, symlinks, and other conflicts
remain untouched and are reported in the manifest.

Bill IDs are date-derived, so v1 cannot distinguish two provider documents
issued on the same date. Sync fails closed with `selection_required` if the
provider returns that ambiguity; it does not invent a document-specific name.
If one bill fails, completed files remain and later candidates are marked
`not_attempted` after a systemic failure. The error envelope retains the full
partial manifest. Rerun the same command to verify and skip completed files,
then retry missing bills. A matching SHA-256 proves local file integrity, not
that an older retained PDF is the newest provider copy.

Use `--demo` for a deterministic synthetic bill and PDF without loading a
session or contacting Con Edison:

```bash
coned --demo --json-envelope bills sync --directory "$HOME/Bills"
```

## Usage data

```bash
coned accounts list
coned usage summary
coned usage forecast
coned usage bills
coned usage weather
coned usage neighbors
coned usage meters
coned usage realtime
```

Use `--json` for structured output:

```bash
coned --json usage summary
```

### Versioned automation output

Scripts that need a stable contract can opt in with `--json-envelope`. The flag
may appear before or after a command and implies JSON output; without it,
existing human output and `--json` response shapes are unchanged. A successful
one-shot command emits exactly one v1 JSON object, and a failure emits one
sanitized error object. For example:

```bash
coned bills list --json-envelope
```

```json
{"schema_version":1,"command":"bills.list","ok":true,"captured_at":"2026-10-05T12:00:00+00:00","data":[{"id":"<opaque-public-id>"}]}
```

`captured_at` records when the CLI assembled the result in UTC. Provider
timestamps and read interval `start`/`end` values keep their own meanings.
Download results include the public bill handle, requested output path, byte
count, and SHA-256 digest. CSV and XML exports are returned as strings inside
`data` with a `format` field; file downloads return metadata rather than writing
the path to standard output. Output conflicts leave the existing file intact.

Authentication keeps its interactive timing and emits NDJSON events instead
of buffering a one-shot result. Each event has `schema_version`, `command`, and
`event`; terminal success includes `ok:true`, while terminal failure includes
`ok:false` and the usual sanitized `error` object. The `mfa_required` event is
written before the verification prompt is read. Prompts remain on standard
error, and credentials, verification codes, cookies, challenge contents, and
provider error text are never included.

Consumers can inspect the supported command identifiers, schema versions, and
error codes without opening a session or contacting Con Edison:

```bash
coned capabilities --json
coned capabilities --json-envelope
```

In v1, command identifiers use dot-separated command paths such as
`bills.list`, `usage.reads`, and `auth.login`. Optional `http_status` and
allowlisted `transport_kind` fields give limited transport context. Usage rows
keep provider values when present; fields whose provider presence is known to
be absent are JSON `null`, and unknown units or currencies remain `null` rather
than being inferred. Additive fields may be introduced within v1. A changed
meaning or incompatible shape requires a newly advertised schema version.

Failures use an allowlisted `error.code`; scripts should branch on this value,
not on human text or exit-code subcategories. Exit status is 0 for success, 1
for command failure, and 2 for invalid arguments or flags. `retryable:true`
means only that a timeout or explicitly transient transport failure may be
retried by the caller; it never authorizes an authentication or MFA retry.

| Code | Meaning |
| --- | --- |
| `invalid_argument` | Invalid command argument or flag. |
| `selection_required` | Select an eligible account or meter. |
| `session_expired` | A usable authenticated session is unavailable. |
| `mfa_required` | The provider requires multi-factor verification. |
| `invalid_credentials` | Authentication credentials or verification were rejected. |
| `storage_locked` | The operating-system credential store is locked. |
| `storage_access_denied` | Credential-store access was denied. |
| `storage_failed` | Credential storage failed. |
| `transport_failed` | A non-timeout transport failure occurred. |
| `timeout` | A request or command timed out. |
| `canceled` | The request was canceled. |
| `provider_protocol_changed` | A provider response no longer matches the expected protocol. |
| `bill_not_found` | The requested public bill handle was not found. |
| `output_conflict` | The destination exists or conflicts with a safe file write. |
| `output_failed` | The output could not be written or published. |
| `unsupported_platform` | This operation requires filesystem protections unavailable on this platform. |
| `internal_error` | An unclassified failure occurred; private details are omitted. |

Example migration: keep `coned --json bills list` if the current array shape is
sufficient; switch to `coned bills list --json-envelope` when a caller needs a
version marker and machine-readable failure codes.

### Historical reads and costs

```bash
coned usage reads --aggregate bill
coned usage reads --aggregate day \
  --from 2026-01-01 \
  --to 2026-01-31
coned usage costs --aggregate hour \
  --from 2026-01-01 \
  --to 2026-01-02
```

Supported aggregation levels are `bill`, `day`, and `hour`. Day and hour queries require both `--from` and `--to`. Large ranges are split automatically to stay within provider limits. When granular cost data is unavailable, non-bill cost queries fall back to usage-only reads.

### Normalized exports

```bash
coned usage export --format csv > usage.csv
coned usage export --format json --output usage.json
```

Exports support `csv` and `json`. When `--output` is used, `coned` writes to an owner-only temporary file and atomically moves it to the requested destination. Existing files are left unchanged unless you pass `--force`.

All usage commands are read-only. Missing real-time readings are reported as unavailable rather than returned as a provider error payload.

## Accounts and meters

Provider identifiers can be represented by stable, profile-specific HMAC handles. The HMAC key is stored with the other secrets. Raw account, premise, meter, and register identifiers are not written to configuration or diagnostic files.

```bash
coned entities list
coned --json entities list --type meter
coned entities alias account-xxxxxxxxxxxx home
coned entities alias meter-xxxxxxxxxxxx electric
coned entities select home
```

Use an alias or handle to select an account or meter:

```bash
coned --account home usage summary
coned --account home --meter electric usage realtime
```

If more than one eligible entity exists, `coned` requires an explicit selection instead of silently choosing the first one.

Forecast and REST-history commands currently span all authorized utility accounts. They reject explicit selectors rather than guessing how Con Edison and Opower account identifiers correspond.

## Green Button exports

```bash
coned green-button inspect
coned green-button inspect --json
coned green-button export --format csv \
  --from 2026-01-01 \
  --to 2026-01-31 > usage.csv
coned green-button export --format json > usage.ndjson
coned green-button export --format xml > usage.xml
coned green-button download --format csv --output usage.zip
```

The provider generates these exports asynchronously. `export` writes the selected CSV or XML file to standard output; JSON output consists of newline-delimited objects converted from CSV. `download` saves the original provider ZIP through the same owner-only, atomic file-writing process.

## Safe schema diagnostics

When a provider response changes, generate a value-free structural report:

```bash
coned diagnostics schema --output schema.json
coned diagnostics inspect schema.json
```

Diagnostics contain JSON paths, types, nullability, array cardinality, a schema version, provenance, and a small allowlist of non-sensitive enum values. They do not retain identifiers, names, addresses, dates, usage, costs, tokens, URLs, or response bodies. Diagnostic files are written with mode `0600`.

## Profiles and configuration

Use profiles to isolate credentials and sessions:

```bash
coned --profile home auth login
```

On Linux, non-secret configuration is stored at `~/.config/coned/config.json`. Other operating systems use their standard user configuration directory:

```json
{
  "base_url": "https://www.coned.com",
  "profile": "default",
  "request_timeout": 30000000000
}
```

CLI flags override the configured profile and timeout. The production client accepts only `https://www.coned.com` as its base URL.

## Development

```bash
make check
make build
./bin/coned version
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for build, test, and fixture guidance. Provider fixtures must be synthetic and include version, provenance, and last-verified metadata.

## Support and security

Use GitHub issues for reproducible, sanitized bugs and feature requests. This community project cannot help with Con Edison account, billing, outage, or service requests.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md). See [docs/security.md](docs/security.md) for storage behavior, headless Linux limitations, and the threat model.

## Disclaimer

This project interoperates with non-public web interfaces used by Con Edison’s My Account site. These interfaces are not offered as a documented or supported developer API and may change without notice. It is intended only for account holders and authorized agents accessing data they are permitted to view. Users are responsible for complying with their utility agreements and applicable terms. The software does not bypass access controls.

This project is not affiliated with or endorsed by Consolidated Edison, Inc., Opower, or Oracle. “Con Edison” and related marks belong to their respective owners.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 `zzwong`. Third-party license texts distributed with release archives are in [third_party_licenses/](third_party_licenses/).
