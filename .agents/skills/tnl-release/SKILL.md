---
name: tnl-release
description: Use when checking whether tnl, tnld, or @tnldotdev npm packages need releases, proposing versions, or preparing signed v*, npm/dev, npm/next, or npm/vite release tags.
compatibility: opencode
metadata:
  project: tnl
  workflows: release.yml, release-npm.yml
---

# tnl releases

Release the combined `tnl` and `tnld` product with root `v<version>` tags.
Release `@tnldotdev/dev`, `@tnldotdev/next`, and `@tnldotdev/vite`
independently with `npm/<package>/v<version>` tags. GitHub Actions is the
publisher; never publish artifacts manually during a normal release.

## Safety rules

- Work only from `main` with a clean worktree and `HEAD` synchronized with
  `origin/main`.
- Never include unrelated changes, create an empty release commit, amend,
  force-push, move a tag, or reuse a published version.
- Require separate user approval for the version plan, release commit, main
  push, and each tag push. Earlier approval does not cover a later gate.
- Stop on failed signing, verification, CI, push, workflow, or registry checks.
  Do not bypass branch protection or signing.

## Assess releases

1. Fetch `origin/main` and tags, then verify the branch, worktree, and tracking
   state.
2. Assess `tnl` and `tnld` as one product. Find the latest signed `v*` tag and
   inspect committed changes to Go code, protocols, deployment files, the
   container, release configuration, and user documentation since that tag.
3. For each npm package, find the latest signed `npm/<package>/v*` tag and
   published npm version. Stop if Git and npm disagree in a way that is not
   explained by the initial bootstrap.
4. Review each package's source, public types, runtime dependencies, README,
   tests, and shared TypeScript or packaging changes since its latest tag.
5. Treat changes confined to tests or development tooling as evidence to
   review, not an automatic release. Confirm whether shipped artifacts changed.
6. When `dev` changes, identify whether `next` or `vite` must also be released.
   Their packed `workspace:*` dependency resolves to the current exact `dev`
   version.
7. Present one concise table with target, published version, relevant changes,
   release recommendation, proposed version, and rationale.
8. Ask the user to approve or correct the complete table before editing files.

During the `0.1.0` prerelease series, default to incrementing `rc.N` only for
selected targets. Never infer that a stable release is wanted. The Go product
and each npm package have independent versions.

## Prepare approved versions

1. The Go product version comes from its tag; do not add or edit a version file.
2. Update only the selected `packages/<package>/package.json` versions.
3. For a Go product release, run `task generate-check`, `task format-check`,
   `task lint`, `task test`, `task go:test-race`, `task build`, and `task package`.
4. For an npm release, run `pnpm install --frozen-lockfile`, `pnpm build`,
   `pnpm typecheck:ci`, `pnpm test:ci`, `pnpm lint`, `pnpm format:check`, and
   `pnpm run pack`.
5. Run `node scripts/verify-package-versions.mjs <package> <version>` for each
   selected npm package.
6. Pack each selected npm package and inspect its manifest and file list.
   Confirm that no `workspace:` dependency remains and that adapter dependencies
   refer to a published or concurrently selected `dev` version.
7. Confirm every proposed tag is absent from Git and every proposed npm version
   is absent from the registry.
8. Show the user the selected targets, final versions, verification results, and
   exact diff.

## Commit and push

1. If npm version files changed, ask for approval to create one signed
   version-bump commit. Stage only approved package manifests and any directly
   required lockfile change.
2. If no files changed, do not create a release commit; use the verified current
   `main` commit.
3. After a release commit succeeds, ask separately before `git push origin main`.
4. Verify `origin/main` points to the release commit and wait for the main CI
   checks. If checks cannot be queried, ask the user to confirm they passed.

## Tag releases

For the combined Go product, show and separately approve:

```console
git tag -s v<version> -m 'tnl v<version>'
git push origin v<version>
```

For each npm package, show and separately approve:

```console
git tag -s npm/<package>/v<version> -m '@tnldotdev/<package> <version>'
git push origin npm/<package>/v<version>
```

If `dev` is selected with adapters, release `dev` first. Verify its npm version
exists before asking to push an adapter tag. After every tag, verify the
workflow-published release before continuing. Diagnose failed workflows instead
of publishing manually.
