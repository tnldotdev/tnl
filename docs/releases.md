# install and verify releases

Each tnl release includes:

- archives containing `tnl` and `tnld` for macOS and Linux on amd64 and arm64;
- a multi-platform `tnld` container image;
- the `@tnldotdev/tnl` npm package and native platform packages;
- checksums, SPDX SBOMs, Sigstore bundles, and GitHub provenance.

Releases before 1.0 are previews. Read a release's compatibility notes before
updating a tnl server because some releases require a PostgreSQL migration.

## install with homebrew

```console
brew install tnldotdev/tap/tnl
```

The formula installs both `tnl` and `tnld` and checks the selected archive's
SHA-256 checksum. Homebrew does not verify the Sigstore bundle or GitHub
provenance. Follow the manual process below when you need those checks.

## install with npm

Install a preview client in a JavaScript project:

```console
pnpm add --save-dev @tnldotdev/tnl@next
pnpm exec tnl version
```

Stable releases use the default `latest` tag and do not need `@next`.

The package installs only the native dependency for the current platform. It
does not use an install script or download executable code from another host.
Do not disable optional dependencies. Node.js 22.18 or newer is required.

The npm package provides the `tnl` client. Install `tnld` through Homebrew, a
release archive, or the release container.

## verify an archive

Verification follows this chain:

```text
GitHub Actions identity
          |
          v
signed checksums.txt
          |
          v
archive and SBOM checksums
          |
          v
installed tnl and tnld
```

Download all assets for the selected tag before checking the manifest. For
`v0.1.0`, archives are named:

```text
tnl_0.1.0_darwin_amd64.tar.gz
tnl_0.1.0_darwin_arm64.tar.gz
tnl_0.1.0_linux_amd64.tar.gz
tnl_0.1.0_linux_arm64.tar.gz
```

First verify the keyless Sigstore bundle for `checksums.txt`:

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

GitHub also records build provenance for every manifest entry:

```console
gh attestation verify tnl_0.1.0_linux_amd64.tar.gz \
  --repo tnldotdev/tnl
```

Extract and install only after verification succeeds:

```console
tar -xzf tnl_0.1.0_linux_amd64.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 tnl tnld "$HOME/.local/bin/"
tnl version
tnld version
```

Both commands should report the selected version and commit.

## handle macos quarantine

Release binaries are not Apple-signed or notarized, so Gatekeeper may quarantine
them. Verify the Sigstore identity and checksums first. Then remove quarantine
only from the binaries you inspected:

```console
xattr -d com.apple.quarantine tnl tnld
```

## verify a container

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

Verify GitHub provenance and inspect the attached BuildKit SBOM:

```console
gh attestation verify "oci://$TNL_IMAGE" --repo tnldotdev/tnl
docker buildx imagetools inspect "$TNL_IMAGE" --format '{{ json .SBOM }}'
```

The image runs without a shell as non-root UID and GID 65532. It uses
unprivileged internal ports and includes project and dependency licenses under
`/licenses/tnl`.

## update a server

Keep production images pinned by digest. Back up PostgreSQL and deployment
secrets before an update.

Follow the [self-hosting upgrade procedure](self-hosting.md#upgrade). A
schema-changing release requires stopping control-side writers, running the new
binary's migration, and then starting matching process versions.

Do not run an older control or standalone binary against a newer schema. Follow
the [rollback procedure](self-hosting.md#roll-back) instead of attempting an
in-place downgrade.
