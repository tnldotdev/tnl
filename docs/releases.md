# tnl Releases

tnl releases provide combined `tnl` and `tnld` archives for macOS and Linux on
amd64 and arm64, plus a multi-platform `tnld` image in GHCR. Releases before
1.0 are standalone previews and may include forward-only state migrations.

## Install With Homebrew

Stable releases are available from the `0xcadams/tap` Homebrew tap:

```console
brew install 0xcadams/tap/tnl
```

The formula installs both `tnl` and `tnld` and verifies the selected release
archive's SHA-256 checksum. Homebrew does not verify the release's Sigstore
bundle or GitHub provenance; use the manual process below when those checks are
required.

## Verify A Release

Download all assets for the selected tag before checking the checksum file.
For `v0.1.0`, the archive names are:

```text
tnl_0.1.0_darwin_amd64.tar.gz
tnl_0.1.0_darwin_arm64.tar.gz
tnl_0.1.0_linux_amd64.tar.gz
tnl_0.1.0_linux_arm64.tar.gz
```

First verify the keyless Sigstore bundle for the checksum manifest. Replace
`v0.1.0` with the exact tag being installed:

```console
export TNL_VERSION=v0.1.0
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/0xcadams/tnl/.github/workflows/release.yml@refs/tags/$TNL_VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Then verify every downloaded archive and SPDX JSON SBOM:

```console
# Linux
sha256sum --check checksums.txt

# macOS
shasum -a 256 -c checksums.txt
```

GitHub also records build provenance for every entry in `checksums.txt`. If the
GitHub CLI is available, verify an archive with:

```console
gh attestation verify tnl_0.1.0_linux_amd64.tar.gz \
  --repo 0xcadams/tnl
```

Extract the archive only after these checks pass:

```console
tar -xzf tnl_0.1.0_linux_amd64.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 tnl tnld "$HOME/.local/bin/"
tnl version
tnld version
```

The two commands must report the selected version and the same commit. macOS
artifacts are not Apple-signed or notarized. Gatekeeper may quarantine them;
after verifying the Sigstore identity and checksums, remove quarantine only
from the extracted binaries you inspected:

```console
xattr -d com.apple.quarantine tnl tnld
```

## Verify The Container

The release includes `tnld-image-digest.txt`. Use that digest instead of a
mutable tag:

```console
export TNL_IMAGE='ghcr.io/0xcadams/tnl@sha256:...'
cosign verify \
  --certificate-identity "https://github.com/0xcadams/tnl/.github/workflows/release.yml@refs/tags/$TNL_VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$TNL_IMAGE"
docker pull "$TNL_IMAGE"
docker run --rm "$TNL_IMAGE" version
```

Verify the GitHub provenance attestation and inspect the attached BuildKit
SBOM:

```console
gh attestation verify "oci://$TNL_IMAGE" --repo 0xcadams/tnl
docker buildx imagetools inspect "$TNL_IMAGE" --format '{{ json .SBOM }}'
```

The image runs as non-root UID/GID 65532, uses unprivileged internal ports 8443 and 9090,
and contains no shell. Its OCI index carries BuildKit provenance and an SBOM;
GitHub also publishes an image provenance attestation. Project and third-party
license files are available under `/licenses/tnl` in the image filesystem.

## Pre-1.0 Configuration Changes

Current daemon releases derive `tnl.<domain>` and `apps.<domain>` from one
`TNLD_DOMAIN` value. Public ingress requires automatic ACME configuration.

The daemon creates its login token in the state directory. Retrieve it with
`tnld login-token --state-dir DIR`, and use `tnl login` to save a revocable
access credential. Worker and service credentials are generated with `tnld
token worker` and `tnld token service`.

Use `TNLD_RELAY_PROVIDER=tailcat` to explicitly opt into automatic hosted relay
selection, or retain `TNLD_RELAY_MAP_FILE` for an operator-approved custom map.
Review the matching release's [self-hosting guide](self-hosting.md) before
recreating containers.

## Cold Backup

Run these commands from `deploy`. Set `TNL_STATE_VOLUME` to the value in
`.env`; the default is shown below. Use a trusted, pinned backup utility image
in production; `alpine:3.22` is shown as a portable example.

```console
mkdir -p backups
chmod 700 backups
export TNL_STATE_VOLUME=tnl_tnld-state
docker compose stop tnld
docker run --rm \
  --volume "$TNL_STATE_VOLUME:/state:ro" \
  --volume "$PWD/backups:/backup" \
  alpine:3.22 \
  tar -C /state -czf "/backup/tnl-state-$(date +%Y%m%d%H%M%S).tar.gz" .
docker compose start tnld
```

Confirm `tnld` is stopped before the archive starts. Back up the whole volume,
including SQLite files, ACME state, the login token, and the pinned relay
map. Encrypt the archive and retain the matching daemon version alongside it.

Test restoration with a new disposable volume:

```console
export RESTORE_VOLUME=tnl-restore-test
docker volume create "$RESTORE_VOLUME"
docker run --rm \
  --volume "$RESTORE_VOLUME:/state" \
  --volume "$PWD/backups:/backup:ro" \
  alpine:3.22 \
  tar -C /state -xzf /backup/tnl-state-YYYYMMDDHHMMSS.tar.gz
```

Attach that volume only to an isolated test deployment. Do not restore over a
running daemon or an existing non-empty volume.

## Upgrade

1. Verify the new archives, image digest, signatures, SBOMs, and provenance.
2. Stop all publishing clients or expect routes to disconnect during restart.
3. Take and test a cold backup with the currently running version recorded.
4. Set `TNL_IMAGE` to the new digest and run `docker compose pull`.
5. Run `docker compose up -d --force-recreate` and inspect `docker compose logs tnld`.
6. Query `/v1/capabilities` and publish a test route.
7. Upgrade every `tnl` client to the same version before normal use resumes.

The daemon applies embedded SQLite migrations at startup. It refuses a database
whose schema is newer than the binary supports.

## Rollback

Never start an older daemon against a database that a newer daemon has opened.
To roll back after an upgrade:

1. Stop the new daemon.
2. Preserve the failed state volume for diagnosis.
3. Restore the complete pre-upgrade cold backup into an empty volume.
4. Set `TNL_IMAGE` to the previous verified digest.
5. Set `TNL_STATE_VOLUME` to the restored volume name.
6. Run `docker compose pull` and `docker compose up -d --force-recreate`.
7. Confirm `/v1/capabilities`, inspect logs, and publish a test route.
8. Restore matching previous `tnl` clients.

If no pre-upgrade backup exists, stop rather than attempting an in-place schema
downgrade.

## Maintainer Runbook

The `release` GitHub environment should require approval. The `homebrew`
environment must provide a `HOMEBREW_TAP_TOKEN` secret containing a fine-grained
GitHub token with Contents read/write access to `0xcadams/homebrew-tap`. Enable
immutable releases, tag protection, GitHub Packages, and artifact attestations
before the first release.

From a clean, fully verified `main` commit:

```console
git tag -s v0.1.0 -m 'tnl v0.1.0'
git push origin v0.1.0
```

The tag must be an annotated signature that GitHub verifies and must point
directly to a commit reachable from `main`; the workflow enforces both
conditions. After environment approval it builds signed archives and SBOMs,
pushes and signs the versioned image, attaches its digest, and publishes the
release. Stable tags then update `Formula/tnl.rb` in the Homebrew tap. Review
the completed release and never move or reuse a release tag.
