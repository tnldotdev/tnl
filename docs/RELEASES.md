# tnl Releases

tnl releases provide combined `tnl` and `tnld` archives for macOS and Linux on
amd64 and arm64, a multi-platform `tnld` image in GHCR, and the project-local
`@tnldotdev/tnl` client package. The npm framework integrations are versioned
and released independently. Releases before 1.0 are previews and may include
forward-only state migrations.

## Install With Homebrew

Stable releases are available from the `tnldotdev/tap` Homebrew tap:

```console
brew install tnldotdev/tap/tnl
```

The formula installs both `tnl` and `tnld` and verifies the selected release
archive's SHA-256 checksum. Homebrew does not verify the release's Sigstore
bundle or GitHub provenance; use the manual process below when those checks are
required.

## Install With npm

Install the prerelease client in a JavaScript project with:

```console
pnpm add --save-dev @tnldotdev/tnl@next
pnpm exec tnl version
```

Stable releases use the default `latest` tag and do not require the `@next`
suffix. The package exposes only `tnl`; use the release container, Homebrew, or
an archive for `tnld`.

The launcher has exact-version optional dependencies for macOS and Linux on
arm64 and x64. npm and pnpm install only the package matching the current
platform, and no install script downloads executable code. Do not disable
optional dependencies. The reported client version must match the selected
root release tag without its leading `v`. Node.js 22.15 or newer is required.

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
  --certificate-identity "https://github.com/tnldotdev/tnl/.github/workflows/release.yml@refs/tags/$TNL_VERSION" \
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
  --repo tnldotdev/tnl
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
export TNL_IMAGE='ghcr.io/tnldotdev/tnl@sha256:...'
cosign verify \
  --certificate-identity "https://github.com/tnldotdev/tnl/.github/workflows/release.yml@refs/tags/$TNL_VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$TNL_IMAGE"
docker pull "$TNL_IMAGE"
docker run --rm "$TNL_IMAGE" version
```

Verify the GitHub provenance attestation and inspect the attached BuildKit
SBOM:

```console
gh attestation verify "oci://$TNL_IMAGE" --repo tnldotdev/tnl
docker buildx imagetools inspect "$TNL_IMAGE" --format '{{ json .SBOM }}'
```

The image runs as non-root UID/GID 65532, uses unprivileged internal ports 8443 and 9090,
and contains no shell. Its OCI index carries BuildKit provenance and an SBOM;
GitHub also publishes an image provenance attestation. Project and third-party
license files are available under `/licenses/tnl` in the image filesystem.

## Pre-1.0 Configuration Changes

`tnld` derives the control API hostname `tnl.<domain>` and deployment hostname
suffix `<domain>` from `TNLD_DOMAIN`. Set `TNLD_DOMAIN` to a lowercase DNS
domain without a trailing dot. `TNLD_CONTROL_HOSTNAME` and
`TNLD_HOSTNAME_SUFFIX` set those values independently. Public ingress requires
automatic ACME configuration.

The daemon creates its login token in the state directory. Retrieve it with
`tnl admin server login-token --state-dir DIR`, and use `tnl login` to save a revocable
control session. Worker and service credentials are generated with `tnl admin
server token worker` and `tnl admin server token service`.

`TNLD_ACCESS_TOKEN_LIFETIME` controls rotating access tokens from five minutes
through 30 days and defaults to one hour. `TNLD_REFRESH_TOKEN_LIFETIME` controls
the fixed absolute session lifetime through 365 days and defaults to 30 days.
Existing control sessions retain their stored absolute expiry.

Use `TNLD_RELAY_PROVIDER=tailcat` to explicitly opt into automatic hosted relay
selection, or use `TNLD_RELAY_MAP_FILE` for an operator-approved custom map.
Public ingress requires exactly one of those relay configurations.
Review the matching release's [self-hosting guide](SELF-HOSTING.md) before
recreating containers.

## Cold Backup

Run these commands from `deploy`. Set `TNL_STATE_VOLUME` to the value in
`.env`; the default is shown below. In production, select a reviewed backup
utility image by digest; `alpine:3.22` is shown as a portable example.

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
including SQLite files, ACME state, the login token, and the stored relay map.
Encrypt the archive and retain the matching daemon version alongside it.

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
6. Query `/v1/ready`, inspect `/v1/capabilities`, and publish a test route.
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
7. Confirm `/v1/ready`, inspect `/v1/capabilities` and logs, and publish a test route.
8. Restore matching previous `tnl` clients.

If no pre-upgrade backup exists, stop rather than attempting an in-place schema
downgrade.

## Maintainer Runbook

The `release` GitHub environment should require approval. The `homebrew`
environment must provide a `HOMEBREW_TAP_TOKEN` secret containing a fine-grained
GitHub token with Contents read/write access to `tnldotdev/homebrew-tap`. Enable
immutable releases, tag protection, GitHub Packages, and artifact attestations
before the first release.

Use the `tnl-release` agent skill to assess changes, propose versions, run the
required checks, and prepare either release family. `tnl`, `tnld`, and the five
packages that distribute the npm client share a root `v<version>` tag. The
framework integration packages use independent `npm/<package>/v<version>` tags.

From a clean, fully verified `main` commit:

```console
git tag -s v0.1.0 -m 'tnl v0.1.0'
git push origin v0.1.0
```

The tag must be an annotated signature that GitHub verifies and must point
directly to a commit reachable from `main`; the workflow enforces both
conditions. After environment approval it builds signed archives and SBOMs,
pushes and signs the versioned image, publishes the npm client packages, and
attaches the image digest. Stable tags then update `Formula/tnl.rb` in the
Homebrew tap. Review the completed release and never move or reuse a release
tag.

### npm client

`@tnldotdev/tnl` exposes the client launcher. Its four implementation packages
contain the native clients for Darwin and Linux on arm64 and x64. The workflow
uses npm OIDC and does not use an npm token.

npm requires a package to exist before its trusted publisher can be configured.
Before the first root release, an npm organization owner must publish reviewed,
inert placeholders for all five names under a non-release dist-tag, configure
`release.yml` as their trusted publisher, and revoke the bootstrap credential.
This one-time setup is the only manual-publish exception. Normal releases must
use the workflow.

The release workflow derives every npm package version from the root tag and
packages the exact GoReleaser binaries already placed in the release archives.
It verifies installation through npm and pnpm with lifecycle scripts disabled,
publishes the four native packages first, and publishes the launcher last.
Prereleases receive the npm `next` dist-tag; stable releases receive `latest`.
Do not create an `npm/tnl/v<version>` tag or publish these packages manually.

### npm framework integrations

`@tnldotdev/dev`, `@tnldotdev/next`, and `@tnldotdev/vite` have independent
versions. Configure `release-npm.yml` as the trusted publisher for each package.
The workflow uses npm OIDC and does not use an npm token.

Changes to the local `tnl dev` protocol must release `dev`, `next`, and `vite`
in the same release window as the root product. Publish the integrations first,
then the root product immediately afterward. The protocol is replaced in place
during the pre-1.0 series; mismatched installed versions fail with an upgrade
error.

Use the `tnl-release` agent skill to identify changed packages, propose version
bumps, and run the release checks. After the version bump is committed to a
fully verified `main`, create a signed tag for each selected package:

```console
git tag -s npm/vite/v0.1.0-rc.1 -m '@tnldotdev/vite 0.1.0-rc.1'
git push origin npm/vite/v0.1.0-rc.1
```

The tag must use `npm/<package>/v<version>`, match the selected package's
manifest version, and point directly to a commit reachable from `main`. The
workflow verifies those conditions and publishes only that package. Push a
`dev` tag before tags for adapters that depend on its new version. Prereleases
receive the npm `next` dist-tag; stable versions receive `latest`. Never move or
reuse a package tag.
