---
name: tnl-release
description: Use when checking whether tnl, tnld, or @tnldotdev npm packages need releases, proposing a version, or preparing a signed v* release tag.
compatibility: opencode
metadata:
  project: tnl
  workflows: release.yml
---

# tnl releases

Release the combined `tnl` and `tnld` product, including `@tnldotdev/tnl` and
its framework integrations, four native npm packages, and the `tnldotdev-tnl`
Python wheels, with root `v<version>`
tags. GitHub Actions is the publisher; never publish artifacts manually during
a normal release.

## Safety rules

- Work only from `main` with a clean worktree and `HEAD` synchronized with
  `origin/main`.
- Never include unrelated changes, create an empty release commit, amend,
  force-push, move a tag, or reuse a published version.
- Require user approval before the release commit.
- Stop on failed signing, verification, CI, push, workflow, or registry checks.
  Do not bypass branch protection or signing.

## Assess releases

1. Fetch `origin/main` and tags, then verify the branch, worktree, and tracking
   state.
2. Assess `tnl`, `tnld`, the npm client, and the Python binding as one product. Find
   the latest signed `v*` tag and inspect committed changes to Go code,
   protocols, deployment files, native npm packaging, the container, release
   configuration, and user documentation since that tag.
3. Confirm the latest root release has the same published `@tnldotdev/tnl`
   version and all four exact-version native dependencies, plus the corresponding
   PyPI version and four platform wheels. Treat absent npm or PyPI packages
   before their initial release as explained bootstrap states.
4. Review `packages/ts` source, all public subpath types, runtime and optional
   peer dependencies, README, tests, package verification, and framework
   compatibility changes since the latest root tag. The private app-registration
   socket protocol and framework integrations ship in this package.
   Review `packages/py` and its ASGI lifecycle, lockfile, wheel metadata,
   bundled native binary, legal files, and Python tests as part of the same product.
5. Treat changes confined to tests or development tooling as evidence to
   review, not an automatic release. Confirm whether shipped artifacts changed.
6. Present one concise row with the published version, relevant changes,
   release recommendation, proposed version, and rationale.
7. Ask the user to approve or correct the proposal before editing files.

During the `0.1.0` prerelease series, default to incrementing `rc.N`. Never
infer that a stable release is wanted.

## Prepare approved versions

1. The combined product version comes from its tag. The release workflow
   derives the npm client package versions from GoReleaser metadata; do not edit
   their `0.0.0-development` source placeholders.
2. Run `task generate-check`, `task format-check`, `task lint`, `task test`,
   `task py:check`, `task go:test:race`, `task build`, and `task package`.
3. Inspect all five npm tarballs and four Python wheels produced by
   `task package`. Confirm that each native binary is executable and identical
   to its release archive, both npm and pnpm installations run `tnl version`,
   all four public exports import, no `tnld` executable is installed, and the
   private socket implementation has no public export. Verify the Python wheel
   tags, legal files, installation, import, binary version, and commit.
4. Confirm the proposed tag is absent from Git and the proposed versions of all
   five npm packages and the PEP 440 Python distribution are absent from their
   registries.
5. Show the user the final version, verification results, and exact diff.

## Commit and push

1. If release preparation changed files, ask for approval to create one signed
   release-preparation commit. Stage only approved files.
2. If no files changed, do not create a release commit; use the verified current
   `main` commit.
3. After a release commit succeeds, ask separately before `git push origin main`.
4. Verify `origin/main` points to the release commit and wait for the main CI
   checks. If checks cannot be queried, ask the user to confirm they passed.

## Tag releases

For the combined product, show and separately approve:

```console
git tag -s v<version> -m 'tnl v<version>'
git push origin v<version>
```

The root release workflow publishes the archives, image, Homebrew formula,
`@tnldotdev/tnl` with its framework integrations, four native npm packages,
and four Python wheels. Do not create separate language tags. Verify all five
npm versions, their public subpaths, and the PyPI wheels after the workflow
completes. Diagnose a failed workflow instead of publishing manually.

After verifying the release, use the `tnl-release-check` skill to qualify
staging before production promotion and to check production after deployment.
