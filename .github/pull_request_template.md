## Summary

## Testing

- [ ] `make check`
- [ ] `govulncheck ./...`
- [ ] Provider-contract changes include updated provenance/version/`last_verified` metadata

## Security and privacy

- [ ] No credentials, cookies, tokens, signed URLs, account identifiers, addresses, bills, HAR files, or production response values are included
- [ ] New file writes are atomic and owner-only where data may be sensitive
- [ ] New network redirects and download hosts fail closed
- [ ] The change preserves read-only defaults or clearly documents guarded mutations
