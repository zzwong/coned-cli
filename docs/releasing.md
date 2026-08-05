# Releasing

Releases are built by the tag-triggered GitHub Actions workflow. Linux archives are built with CGO disabled on an Ubuntu runner; Darwin amd64 and arm64 archives are built natively with CGO enabled on pinned Intel and arm64 macOS runners. Maintainers should not upload locally built archives to an existing release.

## Preflight

```bash
git status --short
go mod verify
go test -race -shuffle=on ./...
go vet ./...
govulncheck ./...
git diff --check
goreleaser check --config .goreleaser.yml
goreleaser check --config .goreleaser.darwin-amd64.yml
goreleaser check --config .goreleaser.darwin-arm64.yml
goreleaser release --snapshot --clean --config .goreleaser.yml
goreleaser release --snapshot --clean --config .goreleaser.darwin-amd64.yml
goreleaser release --snapshot --clean --config .goreleaser.darwin-arm64.yml
```

Run the Darwin amd64 snapshot on an Intel macOS host and the Darwin arm64 snapshot on an arm64 macOS host; a cross-compiled Darwin archive does not satisfy the release invariant. Snapshot configs intentionally do not generate checksums. Inspect each archive for the `coned` binary, `LICENSE`, `NOTICE`, `README.md`, and all third-party license texts. Confirm the binary contains the expected version, commit, commit timestamp, and `dirty=false` metadata.

## Publish

1. Ensure `main` is green and the working tree is clean.
2. Choose a semantic version. Before 1.0, incompatible CLI/schema changes increment the minor version.
3. Create and verify a signed annotated tag: `git tag -s v0.1.0 -m 'v0.1.0' && git tag -v v0.1.0`.
4. Push the tag: `git push origin v0.1.0`.
5. Verify the single published release, its four exact archives, the one generated `checksums.txt`, and GitHub build-provenance attestations covering every archive and the checksum manifest before announcing the release.
6. Test `gh attestation verify <archive> --repo zzwong/coned-cli` against one downloaded archive.

If a release is compromised or materially broken, remove the affected artifacts, publish a security advisory when appropriate, and issue a new version. Do not silently replace published artifacts under an existing tag.
