# releasing tnl

Audience: maintainers publishing `tnl`, `tnld`, or `@tnldotdev` packages. Users
installing a release should follow [install and verify releases](../releases.md).

Use the `tnl-release` agent skill for the complete assessment, approval, and
verification workflow. The rules below describe the repository contract; they
do not replace the skill's gates.

## prepare release infrastructure

Require approval for the `release` GitHub environment. Add a
`HOMEBREW_TAP_TOKEN` to the `homebrew` environment with read and write access to
`tnldotdev/homebrew-tap` contents.

Before the first release, enable immutable releases, tag protection, GitHub
Packages, and artifact attestations.

## publish one root release

`tnl`, `tnld`, `@tnldotdev/tnl`, and the four native npm packages share one root
`v<version>` tag.

From a clean, fully verified `main` commit:

```console
git tag -s v0.1.0 -m 'tnl v0.1.0'
git push origin v0.1.0
```

The tag must be signed, annotated, verified by GitHub, and point directly to a
commit on `main`. Never move or reuse a release tag.

After environment approval, the workflow:

- builds archives and SPDX SBOMs;
- signs the checksum manifest and container image;
- publishes GitHub provenance;
- publishes all npm packages;
- attaches the image digest;
- updates the Homebrew formula for stable releases.

CI publishes artifacts and images. It does not deploy production.

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

Do not create an `npm/tnl/v<version>` tag. The private development socket and
framework integrations ship with the same root release as the native client and
server.
