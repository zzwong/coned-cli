# Releasing

Releases are built by the tag-triggered GitHub Actions workflow and GoReleaser. Maintainers should not upload locally built archives to an existing release.

## Preflight

```bash
git status --short
go mod verify
go test -race ./...
go vet ./...
govulncheck ./...
git diff --check
goreleaser check
goreleaser release --snapshot --clean
```

Inspect snapshot archives for the binary, `LICENSE`, `NOTICE`, `README.md`, and third-party license texts. Confirm `coned version` contains the expected build metadata.

## Publish

1. Ensure `main` is green and the working tree is clean.
2. Choose a semantic version. Before 1.0, incompatible CLI/schema changes increment the minor version.
3. Create an annotated tag, for example `git tag -a v0.1.0 -m 'v0.1.0'`.
4. Push the tag: `git push origin v0.1.0`.
5. Verify the Release workflow, generated checksums, and GitHub build-provenance attestations before announcing the release.
6. Test `gh attestation verify <archive> --repo zzwong/coned-cli` against one downloaded archive.

If a release is compromised or materially broken, remove the affected artifacts, publish a security advisory when appropriate, and issue a new version. Do not silently replace published artifacts under an existing tag.
