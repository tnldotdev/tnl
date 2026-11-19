---
name: Release
description: Prepare, review, tag, or publish a tnl release, including compatibility, deprecations, database upgrades, and release notes.
---

# release tnl

Run from the repository root through `mise exec --`. Read `AGENTS.md` and
`.github/workflows/release.yml` before preparing a release.

## keep upgrades boring

Released APIs and documented behavior stay compatible. Introduce replacements
alongside old APIs; keep deprecated behavior working and tested. Use the normal
language or contract marker with the first released version and a replacement:

```go
// Deprecated: use NewName. Deprecated in tnl v0.4.0.
```

Use `unreleased` while a deprecation is on the development branch. Before tagging,
replace it with the version that will first publish it. Verify that version
against published tags and release notes; never guess from a merge date or change
an already-published deprecation version. For OpenAPI, set `deprecated: true` and
include the version and replacement in the description, then regenerate.

Deprecation has no removal deadline. Breaking a stable contract or dropping an
upgrade path requires explicit user approval for that specific change. Explain
who is affected and how they can migrate. Record the approval and reason in the
PR and release notes. A request to release, a version bump, or urgency is not an
override.

## prepare

1. Find the previous published release and review the changes since its tag.
   Check public APIs, commands, configuration, protocols, and stored formats.
   Check existing consumers as well as tests written for the new code.
2. Confirm the candidate version and commit. Use a prerelease for changes that
   need user testing. Keep experimental features explicitly opt-in.
3. Check database upgrades. Migration 1 is frozen in both state packages; later
   changes use new numbered migrations. Test populated older databases through
   the supported upgrade path, including skipped releases. Preserve data and
   credentials, and spell out any required intermediate release.
4. Write release notes with new behavior, deprecations and replacements, and
   upgrade steps. Include any approved break and its migration instructions.
   For schema changes, give the upgrade order and recovery procedure. Claim
   rolling upgrades or binary rollback only when tested. Put these notes in
   `.goreleaser.yaml`'s `release.header`, replacing any previous release's header.
   CI replaces draft releases, so notes added to a draft beforehand will be lost.
5. Run the relevant Task checks from `contributing.md`. The release commit must
   have successful `checks.yml` and `integration.yml` push runs on `main`.
   `mise exec -- task package` builds and verifies local release packages.

## publish

```text
reviewed PR -> main + passing CI -> signed tag -> release CI
                                                   |
                         archives + image + npm + Python
                                                   |
                                             GitHub release
```

Merge the release preparation through a PR. Push a signed, annotated `vX.Y.Z`
tag for the verified commit. Use the existing workflow to publish and check every
job, including Homebrew for stable releases. Stop on authentication or signing
errors.

Confirm the published release notes, version, artifacts, and image digest.
Report the release URL and any incomplete publication. Published tags and
artifacts stay fixed; fixes get a new version. Release CI publishes artifacts;
production deployment is a separate operation.

## inspiration

Rust records deprecations with a
[`since` version and replacement note](https://doc.rust-lang.org/reference/attributes/diagnostics.html#the-deprecated-attribute),
keeps stable interfaces working, and tests changes through
[nightly, beta, and stable](https://doc.rust-lang.org/book/appendix-07-nightly-rust.html).
Its [release process](https://forge.rust-lang.org/release/process.html) checks
consumer regressions before publishing. Use those habits here without requiring
Rust's release cadence.
