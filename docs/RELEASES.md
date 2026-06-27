# tnl Releases

tnl releases provide combined `tnl` and `tnld` archives for macOS and Linux on
amd64 and arm64, a multi-platform `tnld` image in GHCR, and the project-local
`@tnldotdev/tnl` client package. The npm framework integrations are versioned
and released independently. Releases before 1.0 are previews and may require a
PostgreSQL schema migration before serving processes can start.

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
root release tag without its leading `v`. Node.js 22.18 or newer is required.

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

The image runs as non-root UID/GID 65532, uses unprivileged internal ports, and
contains no shell. Its OCI index carries BuildKit provenance and an SBOM; GitHub
also publishes an image provenance attestation. Project and third-party license
files are available under `/licenses/tnl` in the image filesystem.

## Server Configuration

`TNLD_SERVER_DOMAIN` is the infrastructure DNS suffix used to derive control,
ingress, and relay hostnames. `TNLD_MANAGED_DEPLOYMENT_DOMAIN` independently
defines public route namespaces. Both must be lowercase canonical DNS names
without trailing dots.

Set `TNLD_MODE` to `standalone`, `control`, `ingress`, or `relay`. Standalone and
control require the pooled runtime `TNLD_DATABASE_URL`. Ingress and relay are
stateless, enroll through the public control API, and must not receive database
credentials. Run `tnld migrate` separately with the direct
`TNLD_DATABASE_DIRECT_URL`; serving processes never apply migrations.

Generate the bootstrap credential with `tnld login-token`, provide it as
`TNLD_LOGIN_TOKEN` to control and standalone processes, and use `tnl login` to
save a revocable control session. Rotating the configured token invalidates
control sessions issued from the previous token.

`TNLD_ACCESS_TOKEN_LIFETIME` controls rotating access tokens from five minutes
through 30 days and defaults to one hour. `TNLD_REFRESH_TOKEN_LIFETIME` controls
the fixed absolute session lifetime through 365 days and defaults to 30 days.
Existing control sessions retain their stored absolute expiry.

Control and standalone obtain the public control certificate through ACME and
do not require certificate files. Split ingress and relay processes require only
their control hostname, scoped service-enrollment token, and process identity;
relay additionally requires its internal relay address. Control issues
short-lived service and relay transport certificates from its durable service
CA. Review the matching release's [self-hosting guide](SELF-HOSTING.md) before
recreating containers.

## PostgreSQL Backup

Use the PostgreSQL platform's supported physical or logical backup tooling. The
following logical-backup example requires a direct URL whose role can read all
tnl schemas:

```console
umask 077
mkdir -p backups
pg_dump --format=custom \
  --file="backups/tnl-$(date -u +%Y%m%d%H%M%S).dump" \
  "$TNLD_DATABASE_DIRECT_URL"
```

Retain the matching `tnld` version and schema version with the backup. Encrypt
backups and restrict access because PostgreSQL contains identity, route,
certificate, session, service CA, enrollment-token digest, and relay transport
key state. Back up the deployment secret store separately; it owns database
credentials, the bootstrap management token, enrollment tokens, and optional
DNS or static public TLS credentials.

Test restoration into a new disposable database, never over the live database:

```console
createdb tnl_restore_test
pg_restore --exit-on-error --no-owner \
  --dbname=tnl_restore_test \
  backups/tnl-YYYYMMDDHHMMSS.dump
```

Start only an isolated test deployment against the restored database. Verify
that its schema is accepted by the matching `tnld` version and exercise login,
team/domain reads, route creation, and route-session establishment.

## Upgrade

1. Verify the new archives, image digest, signatures, SBOMs, and provenance.
2. Record the running `tnld` version and take a tested PostgreSQL backup.
3. Gate route creation, route-session creation, and certificate issuance when
   the running version supports those maintenance controls.
4. Pull the new digest and stop control and standalone processes. Ingress and
   relay processes must not be given the migration URL.
5. Run the new image's `tnld migrate` once with
   `TNLD_DATABASE_DIRECT_URL`.
6. Start controls or standalone processes, then roll ingress and relay services.
   Inspect logs, service certificate expiry, leases, routing-table progress, and
   ready publisher connections.
7. Query `/v1/ready`, inspect control discovery, and publish a test route.
8. Re-enable maintenance controls and upgrade `tnl` clients before normal use
   resumes.

Serving controls and standalone processes require the exact PostgreSQL schema
version supported by the binary. They fail closed on an older or newer schema.

## Rollback

Never start an older control or standalone process against a database migrated
for a newer release.
To roll back after an upgrade:

1. Stop the new controls, standalone processes, ingress, and relays.
2. Preserve a diagnostic backup of the failed database.
3. Restore the complete pre-upgrade PostgreSQL backup into a new database.
4. Set `TNL_IMAGE` to the previous verified digest.
5. Point the old control or standalone configuration at the restored database.
6. Run `docker compose pull` and recreate the deployment without running the
   newer migration image.
7. Confirm `/v1/ready`, inspect control discovery and logs, and publish a test route.
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
workflow verifies those conditions, publishes only that package, and creates a
GitHub Release with the npm tarball attached. Framework prereleases are marked
as prereleases, and framework releases never replace the combined product as
the repository's latest release. Push a `dev` tag before tags for adapters that
depend on its new version. Prereleases receive the npm `next` dist-tag; stable
versions receive `latest`. Tags published before GitHub Releases were enabled
must be backfilled without moving the tag or republishing the package. Never
move or reuse a package tag.
