# browser, action, and publisher template qualification

all four targeted local checks passed on 2026-10-22 after the parent's full
generation and formatting pass. no source fix was needed.

## tested worktree

- worktree: `/Users/chase/.worktree/tnl/role-organization`.
- branch: `0xcadams/role-organization`.
- execution base: `bc1efd09c871124a62281d968c7cad2ba9913a7b`.
- platform: macOS arm64; Node `v22.23.2`, Vitest `5.0.3`, Playwright `1.63.0`.
- these results cover the current uncommitted second-PR tree, including its
  moved and untracked source/generated paths. the base commit alone does not
  contain that tree. the index was empty at the end of the test run.
- this lane adds only this qualification note. the action targets rebuilt their
  own bundles; `connect/dist` still matches `HEAD`, with no untracked output.
  the existing SDK build was reused, and no SDK clean/build, global generation,
  global formatting, or root documentation edit ran here.

## commands and results

all commands ran from the worktree root through `mise exec --`.

| command after `mise exec --`   | result                                                                                                                                                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `task js:test:browser`         | passed: one suite, one Chromium test; 4.12 seconds. the committed `internal/publisher/toolbar/toolbar.js` loaded from a loopback HTTP fixture under CSP.                              |
| `task connect:check`           | passed: independent main/post action builds, TypeScript, all 48 tests in one suite, oxlint, formatting, actionlint, and zizmor.                                                       |
| `task connect:generate-check`  | passed: rebuilt main/post bundles, compared `connect/dist` with `HEAD`, and rejected untracked bundle output; no drift.                                                               |
| `task deploy:publishers:check` | passed: selected Go tests in `internal/publisher/deployment` and `cmd/tnl`, four Fargate tests in one suite, TypeScript, oxlint, and all three pinned `cfn-lint==1.40.2` invocations. |

Chromium was already installed; no browser download or system/keychain change
was needed. the browser test checks Shadow DOM, the local font, pin movement and
mutation, resolve/reopen, canceled drafts, text-selection reports, reflow,
changed/missing anchors, and absence of page errors against the committed bundle.

the action's zizmor run used its default offline mode and reported no findings
with one ignored and two suppressed findings. no workflow was dispatched.

the three CloudFormation checks cover defaults, new resources with explicit KMS
parameters, and existing cluster/security-group/log-group/role parameters. these
are offline schema/template checks; no AWS operation or deployed service was used.

## framework evidence reused

the parent reported a successful `task js:check`, including source-package
verification and all 285 ordinary tests, before this qualification. the current
`vitest.config.ts` includes the moved framework suites in its normal Node project:

- `packages/ts/test/frameworks/vite.test.ts` starts real Vite subprocesses and
  checks HTTP host filtering, metadata, WebSocket HMR, fallback ports, and IPv6.
- `packages/ts/test/frameworks/next.test.ts` starts real Next subprocesses and
  checks HTTP assets/origins, metadata, WebSocket HMR, and fallback listeners.

therefore a separate `task js:test:frameworks` run was unnecessary. its five-suite
selection is already part of the ordinary run, and its `js:build` prerequisite
would clean/rebuild the shared SDK output. the pinned default framework versions
are Next `16.3.8` and Vite `8.3.3`. this is reused parent evidence, not another
framework execution by this lane.

## skipped platform and compatibility qualification

- the Ubuntu GitHub Actions runner's real action main/post lifecycle and
  later-step fixture checks remain with the `connect.yml` workflow owner. the
  local 48-test action result does not establish runner lifecycle behavior.
- alternate framework/Vitest combinations remain with the compatibility CI
  owner: Next `16.3.4` / Vitest `5.0.0`, Vite `6.0.9` / Vitest `4.1.11`, and
  Vite `7.0.0` or `8.2.2` / Vitest `5.0.0`.
- Linux and other native platform execution was not repeated on this macOS arm64
  host. publisher replacement with disposable PostgreSQL and real CLI recovery
  remains with the publisher/integration owner through
  `go:test:integration:publisher-replacement` and the existing CLI workflow job.
  the offline template target does not execute that integration tier.

## remaining owner handoff

- parent integration owner: finish the agreed Go lint/test and integrated checks,
  and attach the final tested commit to the second PR. this lane introduced no
  source change requiring a parent regression rerun.
- Python/package owner: retain ownership of `py:check`, native-owner and release
  wheel/platform qualification; this lane did not rebuild their shared inputs.
- CI owners: retain the platform and compatibility checks listed above.
- operator: any deployed/server/cloud or live qualification is separate and was
  not executed here.

the qualification note is untracked and unstaged at handoff. this lane made no
commit, staging change, push, or PR operation.
