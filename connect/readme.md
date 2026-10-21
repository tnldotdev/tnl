# github action boundary

`tnldotdev/tnl/connect` prepares native connections for one saved GitHub workload and
keeps them available to later steps in the same job. pin the action to a full
commit, install the project's locked dependencies first, and select the policy:

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # set up your package manager and install locked dependencies here
      - uses: tnldotdev/tnl/connect@<full-commit-sha>
        with:
          workload: deploy
      - run: pnpm exec drizzle-kit migrate
      - run: pnpm run deploy
```

this directory documents the action's implementation contract. public setup and
saved-policy administration belong in the [tnl guides](https://tnl.dev/docs).
the supported execution boundary is an ordinary Linux GitHub-hosted job on x64
or arm64. container jobs and shared self-hosted runners have not been qualified.
same-user job steps can read the private runtime capability; it is not an
isolation boundary between mutually untrusted steps.

## inputs

| input               | contract                                                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `workload`          | required key in the project's `workloads` declarations with `provider: github`; for example `deploy` |
| `working-directory` | selected project directory, relative to the workspace; defaults to `.`                               |
| `services`          | optional newline-separated service keys; only narrows the workload declaration                       |
| `timeout`           | native startup wait in seconds, 1–300; defaults to 90                                                |
| `version`           | optional exact npm release version, such as `0.1.0-rc.1`; no `v`, ranges, tags, or URLs              |
| `cli-path`          | optional explicit native executable, relative to the project directory or absolute                   |

`version` and `cli-path` are mutually exclusive. by default, resolution starts at
the selected directory's installed `@tnldotdev/tnl` export and finds its manifest
without importing package code or requiring an exported `package.json`. the
matching platform package resolves from that manifest, including through pnpm's
virtual store. its version must equal both the launcher's version and exact
optional dependency; its binary must be executable and match the release
manifest's SHA-256. a missing, broken, or old package fails before OIDC. there is
no search for `tnl` on `PATH` and no automatic install fallback.

an explicit `version` runs `npm install` with the exact package specifier in a
private runner-temp directory, with lifecycle scripts disabled and the npm
registry selected explicitly. npm checks package integrity; the action checks
the platform binary digest recorded by existing release packaging. it does not
implement another archive downloader. the installed distribution and its legal
files remain for the session. an explicit `cli-path` supports a locally built
native binary and still must pass machine capability checks.

## native contract

the action copies the selected executable and available legal files into a
mode-0700 directory outside the checkout under `RUNNER_TEMP`. installed packages
must provide `LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`. this exact copy
is used for all operations, including the native owner's own child process and
post cleanup after later package installs or checkout changes.

1. `tnl --no-telemetry runtime connections capabilities` must report schema 1,
   `context`, `start`, `status`, `stop`, both private transport capabilities, and
   `team_names: saved_policy`.
2. `... context --directory <project> --workload <key> [--service <key>]` resolves the
   selected project and nonsecret source identity. a team name remains a selector
   for the saved policy; an applied binding can supply its canonical team ID.
3. the official Actions OIDC client requests an assertion for exactly that
   context's HTTPS audience. the assertion is masked and passed only on stdin.
   the checkout's context cannot authorize itself: control verifies GitHub's
   signature and claims, saved policy, service subset, audience, and one-use JTI.
4. `... start <same-scope-flags> --runner-temp <private-session>` consumes
   `{schema: 1, context, assertion}` on stdin. the action accepts only schema-1
   `state: ready`, a future deadline no more than six hours away, the exact
   copied executable, the selected service set, and canonical private paths
   within this action's session directory. private files must be regular,
   current-user-owned mode-0600 files with a current-user-owned mode-0700 parent
   directory; symlink paths are rejected before environment exports.
5. the action saves the exact executable and handle in `GITHUB_STATE` and a
   mode-0600 cleanup record. the official Actions file helpers export
   `TNL_CONNECTION_HANDLE`, `TNL_PROJECT_RUNTIME` JSON, and optional `KUBECONFIG`
   through `GITHUB_ENV`, including delimiter-safe multiline path handling.
6. post calls `... stop --handle <saved-handle>` with the saved executable and
   accepts only the native joined-cleanup acknowledgement. successful cleanup
   removes the action's own directory. failure retains it so post can retry.
   a complete response's handle is saved even if the starter exits unsuccessfully.

the native process owns listeners, TLS, private IPC, session kubeconfig,
renewal, revocation, and partial-startup rollback. its renewable lease is 90
seconds; renewal stays within the fixed one-hour default or saved-policy
deadline, at most six hours. the action's startup timeout does not extend it.
`RUNNER_TRACKING_ID` is preserved; OIDC request bearer variables are stripped
from native command environments. cancellation signals only the spawned native
command and allows its cleanup grace period. post never finds or kills a PID,
resolves a changed `PATH`, or stops another project's owner.

if the starter dies before delivering a complete response, the action has no
cleanup capability and cannot confirm joined cleanup. it retains the session
directory, reports `TNL_ACTION_CLEANUP_UNCONFIRMED`, and exports no connections.
post reports the same boundary rather than claiming it stopped an owner. any
surviving native owner still has its fixed execution deadline and runner tracking;
its 90-second renewable lease alone does not stop an owner that can still renew.
ordinary cancellation asks the starter to join partial cleanup, but an absent
response cannot prove that cleanup completed.

native stdout/stderr and request size are bounded. child output is never
forwarded to Actions logs, including error output that could echo stdin. only
the browser-safe public metadata shape is exported. no application command,
environment mapping language, job definition, or URL rewrite input is provided.
see the [native lifecycle contract](../docs/maintainers/connection-runtime.md)
for wire fields and the native trust boundary.

action failures have stable `TNL_ACTION_*` codes and catalog-authored messages.
only an owned `ActionError` selects a displayed classification; unexpected
errors use fixed setup or cleanup fallback text. filesystem, OIDC, JSON, and
child-process causes remain available to callers, including both setup and
cleanup failures, but their messages and payloads are never rendered.

## local checks and generated files

```console
mise exec -- pnpm install --frozen-lockfile
mise exec -- task connect:check
mise exec -- task connect:generate-check
mise exec -- actionlint connect/test/workflow.yml
mise exec -- zizmor connect
```

strict TypeScript and Vitest exercise real child processes, a loopback OIDC
fixture using the official client, stdin-only assertions, post cleanup after
removing the original executable, cancellation, partial failure, invalid fixed
deadlines, exact install selection, and npm/pnpm package layouts. the
`test/workflow.yml` fixture can be installed in `.github/workflows` by the CI
owner to exercise the bundled action across separate runner steps without real
GitHub OIDC or cloud access. its action post runs after the original executable
has been removed. a live hosted-runner execution is a separate qualification.

`src/` is handwritten TypeScript. `scripts/build.ts` uses the repository's
esbuild to transpile before ncc bundling, since ncc's TypeScript loader does not
support the pinned native TypeScript compiler API. `dist/main/index.mjs`,
`dist/post/index.mjs`, both `licenses.txt` files, and `dist/package.json` are
committed generated output. regenerate with
`mise exec -- pnpm --filter @tnldotdev/connect-action build`.
