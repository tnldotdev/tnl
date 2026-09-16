# tnl Releases

tnl releases provide combined `tnl` and `tnld` archives for macOS and Linux on
amd64 and arm64, a multi-platform `tnld` image in GHCR, and the project-local
`@tnldotdev/tnl` client package with its Next.js and Vite integrations. Releases
before 1.0 are previews and may require a PostgreSQL schema migration before
serving processes can start.

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
suffix. The package exposes `tnl`, project configuration types, and Next.js and
Vite integration subpaths; use the release container, Homebrew, or an archive
for `tnld`.

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

Use the matching release's [self-hosting guide](SELF-HOSTING.md) for required
settings, secret ownership, deployment, and current capability limitations.
Keep production images digest-pinned. CI publishes artifacts but does not
deploy production.

## PostgreSQL Backup

Follow the [backup and restore procedure](SELF-HOSTING.md#backups). Preserve the
matching binary/schema versions and deployment secrets alongside each backup.

## Upgrade

After artifact verification, follow the [upgrade procedure](SELF-HOSTING.md#upgrade).
Schema-changing upgrades require stopping control-side writers; serving processes
require the exact supported schema.

## Rollback

Follow the [rollback procedure](SELF-HOSTING.md#rollback). Do not run an older
binary against a newer schema or attempt an in-place schema downgrade.

## Maintainer Runbook

The `release` GitHub environment should require approval. The `homebrew`
environment must provide a `HOMEBREW_TAP_TOKEN` secret containing a fine-grained
GitHub token with Contents read/write access to `tnldotdev/homebrew-tap`. Enable
immutable releases, tag protection, GitHub Packages, and artifact attestations
before the first release.

Use the [`tnl-release`](../.agents/skills/tnl-release/SKILL.md) agent skill to
assess changes, propose one version, run the required checks, and prepare the
release. `tnl`, `tnld`, `@tnldotdev/tnl`, and the four native packages share a
root `v<version>` tag.

### Stable promotion

A release-candidate tag may be published before live staging qualification; its
artifacts are the inputs to that testing. Do not describe it as qualified until
the [`tnl-release-smoke`](../.agents/skills/tnl-release-smoke/SKILL.md) skill has
produced a passing report.

Before creating a stable tag without a prerelease suffix:

1. Publish an RC with the same base version from the exact commit intended for
   the stable tag.
2. Deploy that RC's verified image digest to staging and install its published
   client package.
3. Run the common live smoke suite. Run the conditional split and replica suites
   only when those roles are actually deployed separately on staging; an
   incomplete intended split deployment is blocked rather than treated as
   standalone.
4. Restore staging and require a `qualified` report with no mandatory failed,
   blocked, or unrun checks.
5. Verify `main`, the qualified RC, and the proposed stable tag all resolve to
   the same commit. Any later commit or file change requires another RC and
   another qualification.

The smoke report records the client version, source commit, signed image digest,
deployed release, topology, test evidence, cleanup, and residual topology
limitations. Stable qualification does not authorize production deployment.

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
tag. After stable publication, verify npm `latest`, Homebrew installation, and
that the stable archives, binaries, and container report the qualified commit.

### npm client

`@tnldotdev/tnl` exposes the client launcher, project configuration types, and
the Next.js and Vite integrations. Its four implementation packages contain the
native clients for Darwin and Linux on arm64 and x64. The workflow uses npm OIDC
and does not use an npm token.

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

The private `tnl dev` socket implementation ships inside `@tnldotdev/tnl` and
is not a public export. Changes to that protocol or either framework integration
therefore use the same root release as the native client and server. Configure
`release.yml` as the trusted publisher for all five npm package names; there is
no separate npm package tag or workflow.
