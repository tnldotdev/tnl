# releasing tnl

Audience: maintainers publishing `tnl`, `tnld`, `@tnldotdev` packages, or
`tnldotdev-tnl` on PyPI. Users
installing a release should follow [install and verify releases](https://tnl.dev/docs/releases).

Use the `tnl-release` agent skill for the complete assessment, approval, and
verification workflow. The rules below describe the repository contract; they
do not replace the skill's gates.

## prepare release infrastructure

Add a `HOMEBREW_TAP_TOKEN` to the `homebrew` environment with read and write
access to `tnldotdev/homebrew-tap` contents.

Before the first release, enable immutable releases, tag protection, GitHub
Packages, and artifact attestations.

## publish one root release

`tnl`, `tnld`, `@tnldotdev/tnl`, its four native npm packages, and
`tnldotdev-tnl` on PyPI share one root `v<version>` tag. Python prereleases map
`-rc.N` to PEP 440 `rcN` (for example `0.1.0-rc.40` to `0.1.0rc40`).

From a clean, fully verified `main` commit:

```console
git tag -s v0.1.0 -m 'tnl v0.1.0'
git push origin v0.1.0
```

The tag must be signed, annotated, verified by GitHub, and point directly to a
commit on `main`. Never move or reuse a release tag.

The release workflow also checks that Checks and Integration passed for that
commit before publishing.

The workflow then:

- builds archives and SPDX SBOMs;
- signs the checksum manifest and container image;
- publishes GitHub provenance;
- publishes all npm packages;
- verifies and publishes four platform Python wheels with PyPI Trusted Publishing;
- keeps the GitHub release draft unpublished until both npm and PyPI succeed;
- attaches the image digest;
- updates the Homebrew formula for stable releases.

The Homebrew formula template is `deploy/tnl.rb.template`. The workflow fills it
with archive checksums and updates the tap using `scripts/update-homebrew.ts`.

CI publishes artifacts and images. It does not deploy production.

Use [deployed release checks](release-checks.md) after publication: require
staging to pass before promotion and check production after deployment.

## bootstrap npm once

The launcher package exposes the client, configuration types, and framework
integrations. Four implementation packages contain native clients for Darwin
and Linux on arm64 and x64.

npm requires each package to exist before its trusted publisher can be set. An
npm organization owner must perform this one-time setup before the first root
release:

1. Publish reviewed placeholder packages under a non-release dist-tag. They must
   run no code.
2. Configure `release.yml` as the trusted publisher for all five packages.
3. Revoke the one-time publishing credential.

Normal releases use npm OIDC and never use an npm token. Do not publish packages
manually after bootstrap.

The workflow publishes native packages first and the launcher last. Prereleases
receive the `next` dist-tag. Stable releases receive `latest`.

## bootstrap pypi once

Configure a pending Trusted Publisher for the `tnldotdev-tnl` project on PyPI,
bound to this repository's `.github/workflows/release.yml`. No PyPI API token
is needed. The root release workflow builds four wheel-only distributions for
macOS and Linux on arm64 and x64 from the same verified GoReleaser binaries as
the archives and npm packages. Each wheel includes the required license files.
`task release:snapshot` followed by `task py:build` checks the four wheels and
installs and runs the local platform wheel without publishing anything.

Do not create an `npm/tnl/v<version>` tag. The private development socket and
framework integrations ship with the same root release as the native client and
server.
