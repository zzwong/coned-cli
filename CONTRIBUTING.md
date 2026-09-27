# Contributing

Thanks for helping improve `coned`.

## Before opening an issue

- Search existing issues.
- Confirm the problem still occurs with the latest release.
- Never attach raw HAR files, cookies, bearer tokens, signed URLs, account numbers, service addresses, bills, or unredacted provider responses.
- Prefer `coned diagnostics schema`, which records structure without scalar values.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development

Go 1.25.13 or newer is required. Install the pinned lint runner once:

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

Do not run live tests in CI or include their output if it contains personal information.

## Pull requests

- Keep changes focused and include tests.
- Use Conventional Commit titles (`feat:`, `fix:`, `docs:`, `test:`, and so on).
- Preserve read-only defaults and fail closed when provider behavior is unclear.
- Add or update contract provenance, fixture version, and `last_verified` when changing a provider parser.
- Use synthetic fixtures. Never commit captured production data.
- Run the complete validation suite before submitting.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
