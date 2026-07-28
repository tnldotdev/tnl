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
its framework integrations and four native packages, with root `v<version>`
tags. GitHub Actions is the publisher; never publish artifacts manually during
a normal release. Stable releases additionally require live qualification of a
published release candidate through the `tnl-release-smoke` skill.

## Safety rules

- Work only from `main` with a clean worktree and `HEAD` synchronized with
  `origin/main`.
- Never include unrelated changes, create an empty release commit, amend,
  force-push, move a tag, or reuse a published version.
- Require user approval before the release commit.
- Stop on failed signing, verification, CI, push, workflow, or registry checks.
  Do not bypass branch protection or signing.
- Never create a stable tag without a qualifying smoke report for an RC from the
  exact same commit. Missing, failed, blocked, or incomplete live checks stop
  stable promotion.

## Assess releases

1. Fetch `origin/main` and tags, then verify the branch, worktree, and tracking
   state.
2. Assess `tnl`, `tnld`, and the npm client distribution as one product. Find
   the latest signed `v*` tag and inspect committed changes to Go code,
   protocols, deployment files, native npm packaging, the container, release
   configuration, and user documentation since that tag.
3. Confirm the latest root release has the same published `@tnldotdev/tnl`
   version and all four exact-version native dependencies. Treat an absent npm
   client before its initial release as an explained bootstrap state.
4. Review `packages/tnl` source, all public subpath types, runtime and optional
   peer dependencies, README, tests, package verification, and framework
   compatibility changes since the latest root tag. The private `tnl dev`
   socket protocol and framework integrations ship in this package.
5. Treat changes confined to tests or development tooling as evidence to
   review, not an automatic release. Confirm whether shipped artifacts changed.
6. Present one concise row with the published version, relevant changes,
   release recommendation, proposed version, and rationale.
7. Ask the user to approve or correct the proposal before editing files.

During the `0.1.0` prerelease series, default to incrementing `rc.N`. Never
infer that a stable release is wanted. When the user explicitly requests a
stable release, identify the published RC with the same base version that will
be promoted and apply the stable promotion gate below.

## Prepare approved versions

1. The combined product version comes from its tag. The release workflow
   derives the npm client package versions from GoReleaser metadata; do not edit
   their `0.0.0-development` source placeholders.
2. Run `task generate-check`, `task format-check`, `task lint`, `task test`,
   `task go:test-race`, `task build`, and `task package`.
3. Inspect all five tarballs produced by
   `task package`. Confirm that each native binary is executable and identical
   to its release archive, both npm and pnpm installations run `tnl version`,
   all four public exports import, no `tnld` executable is installed, and the
   private socket implementation has no public export.
4. Confirm the proposed tag is absent from Git and the proposed versions of all
   five npm packages are absent from the registry.
5. Show the user the final version, verification results, and exact diff.

## Commit and push

1. If release preparation changed files, ask for approval to create one signed
   release-preparation commit. Stage only approved files.
2. If no files changed, do not create a release commit; use the verified current
   `main` commit.
3. After a release commit succeeds, ask separately before `git push origin main`.
4. Verify `origin/main` points to the release commit and wait for the main CI
   checks. If checks cannot be queried, ask the user to confirm they passed.

## Stable promotion gate

This section applies to a tag without a SemVer prerelease suffix. A stable tag
updates npm `latest` and triggers Homebrew publication, so it cannot be used as
the artifact that decides whether it is safe to publish.

1. Load and follow `.agents/skills/tnl-release-smoke/SKILL.md`.
2. Require an already-published RC with the same base version as the proposed
   stable release. The RC tag, stable tag, smoke report, and current `main` must
   all resolve to the exact same commit.
3. Verify the report identifies the released client, signed image index digest,
   actual staging deployment, topology, mandatory results, cleanup, and UTC
   test window.
4. Require `qualified` with no mandatory `fail`, `blocked`, or `not run`
   results. `not applicable` is valid only for the topology and change
   conditions defined by the smoke skill.
5. Inspect the repository diff after the RC tag. If any commit or file changed,
   including documentation, do not promote that RC; publish and qualify a new
   RC from the new commit.
6. Reconfirm the commit is clean, synchronized with `origin/main`, and still has
   successful Checks and Integration workflows before asking to tag stable.

RC publication does not require prior smoke qualification because it produces
the immutable artifacts that staging must test. Never describe an RC as
qualified without the completed smoke report.

## Tag releases

For the combined product, show and separately approve:

```console
git tag -s v<version> -m 'tnl v<version>'
git push origin v<version>
```

The root release workflow publishes the archives, image, Homebrew formula,
`@tnldotdev/tnl` with its framework integrations, and the four native packages.
Do not create separate npm tags. Verify all five npm versions and the package's
public subpaths after the workflow completes. Diagnose a failed workflow instead
of publishing manually. For a stable release, also verify npm `latest`, the
updated Homebrew formula and installation, and that stable archives, binaries,
and the container report the qualified commit. Post-publication artifact checks
do not substitute for pre-tag RC smoke qualification.
