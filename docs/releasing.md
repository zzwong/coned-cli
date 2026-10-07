# Releasing

GitHub Actions builds and publishes releases from annotated version tags. Tag signing is optional; no signing-key setup is required to release.

## Publish

1. Choose a semantic version. Before 1.0, incompatible CLI/schema changes increment the minor version.
2. Start from a clean checkout of the intended `main` commit and confirm its CI passed:

   ```bash
   git switch main
   git pull --ff-only
   git status --short
   git rev-parse HEAD
   ```

   Stop if the working tree is dirty. Check GitHub CI for that exact commit before tagging it.
3. Create an annotated tag and push it (replace the example with the chosen version):

   ```bash
   version=v0.2.1
   git -c tag.gpgSign=false tag -a "$version" -m "$version"
   git rev-parse "$version^{commit}"
   git push origin "$version"
   ```

   Confirm the tag resolves to the intended commit. Lightweight tags are rejected by the release workflow.
4. Wait for the Release workflow to succeed. It runs tests, vet, vulnerability checks, and release-config validation; builds Linux amd64/arm64 and native macOS amd64/arm64 archives; checks archive contents and build metadata; then publishes four archives, `checksums.txt`, and build-provenance attestations.
5. Download the archive for your machine and `checksums.txt` from the release. Verify the downloaded archive against its checksum and verify provenance:

   ```bash
   gh attestation verify <archive> --repo zzwong/coned-cli
   gh attestation verify checksums.txt --repo zzwong/coned-cli
   ```

   Confirm verification reports the expected release workflow, tag, and source commit. Run the downloaded binary's `version` command and check its version, commit, and `dirty=false` before installing it or announcing the release.

Routine releases do not require local snapshot builds or access to both Mac architectures. When changing release tooling, use `goreleaser check` and snapshot builds for the affected configs; verify Darwin snapshots on the matching native architecture.

## Corrections

Keep published tags and artifacts immutable. Fix a broken release with a new version instead of replacing its files. If artifacts are compromised, remove the affected downloads and publish a security advisory when appropriate.
