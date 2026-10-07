# Development

Go 1.26.8 or newer is required. Install the pinned lint runner once:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

Then run:

```bash
go mod download
make check
make build
```

Normal tests are offline and must not require credentials. Explicit live contract tests are read-only and locally gated:

```bash
CONED_LIVE_TEST=1 go test ./internal/coned -run TestLiveReadOnlyContracts -v
```

Do not run live tests in CI or retain their output if it contains personal information.

## Fixtures and provider contracts

- Use synthetic fixtures. Never commit captured production data.
- Update contract provenance, fixture version, and `last_verified` when changing a provider parser.
- Preserve read-only defaults and fail closed when provider behavior is unclear.
- Run the complete validation suite after changes.

## Sensitive data

Never commit or attach raw HAR files, cookies, bearer tokens, signed URLs, account numbers, service addresses, bills, or unredacted provider responses. Prefer `coned diagnostics schema`, which records structure without scalar values.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md).
