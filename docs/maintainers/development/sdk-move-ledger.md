# sdk move ledger

The TypeScript SDK implementation and its tests now follow publisher, connector,
project, and native ownership. Public entry files, package export conditions,
native package roots, method signatures, and error identities are preserved.
Python remains flat, and the GitHub Action remains under `connect`.

Execution base: `bc1efd09c871124a62281d968c7cad2ba9913a7b`. Results below are for
the uncommitted shared `0xcadams/role-organization` worktree, not a committed
checkpoint. The parent integration ledger must attach the final tested commit.

## implementation and build boundary

All paths in this table are relative to `packages/ts/src/internal/`.

| original files                                                                                                    | destination                                                        | boundary retained                                                                                                  |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `app.ts`, `local.ts`, `register.ts`, `target.ts`, `port.ts`, `status.ts`, `open.ts`, `fetch.ts`, `fetch_types.ts` | `publisher/`, with the same filenames                              | app preparation, scoped registration, listener ownership, status fencing, ad-hoc publication, and Fetch adaptation |
| `connection.ts`, `connection_bridge.ts`, `connection_ipc.ts`, `awaitable_connection.ts`, `cancellation.ts`        | `connector/`, with the same filenames                              | prepared reads, native owner lifetime, authenticated IPC, awaitable settings, and cancellation                     |
| `workload_contract.ts`, `workload_provider.ts`                                                                    | `connector/workload/contract.ts`, `connector/workload/provider.ts` | bounded assertion acquisition, exact contracts, identity selection, and fixed session expiry                       |
| `runtime.ts`, `service_metadata.ts`                                                                               | `project/`, with the same filenames                                | browser-safe metadata parsing, serialization, and service reads                                                    |
| `launcher.ts`, `native-targets.ts`                                                                                | `native/`, with the same filenames                                 | installed platform package selection, matching versions, and executable checks                                     |
| `tracing.ts`                                                                                                      | `tracing.ts`                                                       | shared SDK trace context, finite operations, launch parentage, and linked background work                          |

The public roots, `vite.ts`, `next.ts`, and `bin/tnl.ts` import the new owners
directly. There are no old-path forwarding modules. `index.browser.ts` imports
only browser-safe project values, errors, and the awaitable helper.

`scripts/build-ts-bridges.ts` moved to `scripts/build/ts-bridges.ts`. It now builds
`dist/internal/connector/connection.cjs`. Both server roots keep their external
reference to `internal/connector/connection_bridge.js`; that bridge requires the
same connection module lazily. The bridge's error reference is
`../../errors.js`, preserving the public `TnlError` identity. Publisher imports
remain lazy and external in the CommonJS root.

The launcher resolves `../../../package.json` from its deeper native directory.
The bundled connector has the same directory depth, so native version checks
still read the SDK package root. Native distribution manifests stay under
`packages/ts/native/<platform>-<architecture>/`.

The SDK manifest's build and clean commands now use:

```text
node ../../scripts/build/ts-bridges.ts
node ../../scripts/package/node-licenses.ts
node ../../scripts/build/clean-package.ts
```

## assertion mapping

Every original test title, `test.each` input, assertion, and timeout is retained
at the destination. The table identifies each moved suite by an existing test
title and records its remaining unique coverage together. The title maps to the
identical title at the destination; the same one-to-one rule applies to every
other test in that file. No suite or assertion was retired or combined.

Original and destination paths below are relative to `packages/ts/`. These are
routine Node Vitest suites selected by `task js:test`; the focused Task membership
is recorded after the table. Framework and installed-consumer subprocesses still
load the built package, including during source coverage runs.

| original file                       | destination file                                   | unchanged assertion anchor and retained coverage                                                                                                                                                                                                                                                                                            |
| ----------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `adhoc-fetch.test.ts`               | `test/publisher/adhoc-fetch.test.ts`               | `inline Fetch handlers receive a public origin and can stream request and response bodies`; request/response streaming and rejecting WebSocket upgrades before handler dispatch                                                                                                                                                             |
| `adhoc-open.test.ts`                | `test/publisher/adhoc-open.test.ts`                | `status fences scope, registration, target, and publish run without public GET probes`; real port-0 listeners, exact native readiness, joined close, owner replacement, and explicit publisher selection without exposing private values                                                                                                    |
| `app-runtime.test.ts`               | `test/publisher/app-runtime.test.ts`               | `accepts the native private protocol golden assignment`; scoped HTTP discovery/authentication, real listener registration, cancellation joins, service selection, owner replacement, Bun replacement fencing, safe diagnostics, mounted descriptors, and reconnecting capability plus registration together                                 |
| `awaitable-connection.test.ts`      | `test/connector/awaitable-connection.test.ts`      | `creation is immediate and unprepared reads fail before resolving a binary`; handle-bound context, coalesced preparation, prepared-only synchronous reads, coherent spread snapshots, Kubernetes options, secret rejection, expiry, rollback capability retention, typed cleanup causes, and joined replacement without extending deadlines |
| `connection.test.ts`                | `test/connector/connection.test.ts`                | `browser connect rejects with an owned server-only diagnostic`; cancellation during credential acquisition, bounded fetch, SQL protocol validation, frozen snapshots, managed HTTP origins, and opaque TCP helper restrictions                                                                                                              |
| `connection-fetch.test.ts`          | `test/connector/connection-fetch.test.ts`          | `HTTP keeps the managed origin, Host and SNI while dialing verified loopback TLS`; failed/canceled/uncooperative acquisition, streamed responses beyond 30 seconds, and same-address transport replacement without replay or moving existing streams                                                                                        |
| `connection-ipc.test.ts`            | `test/connector/connection-ipc.test.ts`            | `direct async IPC reuses one authenticated socket and rejects unsafe handles before requests`; bounded handle validation, authenticated socket reuse, and retiring idle agents beyond 32 handles without disturbing active requests                                                                                                         |
| `connection-installed.test.ts`      | `test/connector/connection-installed.test.ts`      | `installed ESM and CommonJS connections use verified owned HTTP transport on Node and actual Bun`; packed installation from a fresh store, public export resolution, prepared metadata, non-enumerable handles, real Host/SNI verification, manual redirects, streaming, and no replay                                                      |
| `connection-owner-recovery.test.ts` | `test/connector/connection-owner-recovery.test.ts` | `a timed-out prepared read retains the live owner and its fixed-port listener`; real helper subprocesses, sibling isolation, canceled preparation, joined cleanup before same-port replacement, deadline coalescing, caller-owned handles, and current authentication denial                                                                |
| `workload-contract.test.ts`         | `test/connector/workload-contract.test.ts`         | `session metadata is exact for %s`; all GitHub, Vercel, Fly, and generic OIDC variants, plus required immutable GitHub execution IDs                                                                                                                                                                                                        |
| `workload-native.test.ts`           | `test/connector/workload-native.test.ts`           | `all protocols share a verified native identity owner and assertions travel only through private stdin`; current identity attachment, denied-control behavior, sibling isolation, current-owner fetch, synchronous identity restrictions, concurrent recovery, and cold/warm/rotation budgets                                               |
| `workload-provider.test.ts`         | `test/connector/workload-provider.test.ts`         | `the SDK's ten-second acquisition deadline rejects a callback that never settles`; late-result rejection, fixed request-scoped callbacks, bounded reread token files, private causes, real Fly Unix-socket wire exchange, and canonical GitHub audiences                                                                                    |
| `runtime.test.ts`                   | `test/project/runtime.test.ts`                     | `imports the built root runtime with no process global`; port defaults, optional/unprepared metadata, deep freezing, mounts, inherited-property rejection, every protocol, strict malformed/oversized metadata, canonical hostname fixtures, and browser-safe serialization                                                                 |
| `service-metadata.test.ts`          | `test/project/service-metadata.test.ts`            | `optional metadata and serialization do not invent a preparation error`; absent optional services and serialization keep their original semantics                                                                                                                                                                                           |
| `errors.test.ts`                    | `test/project/errors.test.ts`                      | `preserves transport causes while keeping messages safe`; authored code/class/retry, cause identity, safe public text, and idempotent classification                                                                                                                                                                                        |
| `next.test.ts`                      | `test/frameworks/next.test.ts`                     | `registers the actual fallback port selected by Next.js`; aliases, exact development origins, production/no-metadata behavior, invocation override, real HTTP/WebSocket/HMR, and actual fallback listeners                                                                                                                                  |
| `vite.test.ts`                      | `test/frameworks/vite.test.ts`                     | `registers and serves an IPv6 localhost target`; aliases without widening host access, prepared metadata, app-owned ports, safe malformed hosts, cleanup causes, replacement listeners, real HTTP/WebSocket/HMR, fallback ports, and IPv6                                                                                                   |
| `bun.test.ts`                       | `test/native/bun.test.ts`                          | `two Bun Hono servers register different ports and read project URLs during import`; actual Bun listeners, import-time metadata, and `Bun hot reload keeps the registered listener available`                                                                                                                                               |
| `launcher.test.ts`                  | `test/native/launcher.test.ts`                     | `catalog matches independent targets and native manifests`; independent darwin/linux arm64/x64 catalog checks, installed version/permission failures, executable selection, unsupported platforms, and one safe line for malicious manifest control characters                                                                              |
| `tracing.test.ts`                   | `test/native/tracing.test.ts`                      | `warm connection IPC uses each caller's trace on its reused socket`; host context, finite attempts, launch parentage, linked asynchronous operations, renewal, and private-cause exclusion                                                                                                                                                  |
| `test-helper.test.ts`               | `test/helpers/test-helper.test.ts`                 | `drains both output pipes while running and kills/reaps a child that ignores SIGTERM`; cleanup on bootstrap errors, malformed requests, spawn failures, bounded HTTP/WebSocket waits, listener cleanup, and test/subprocess environment restoration                                                                                         |

### compiler assertions

All nine type-test source files moved unchanged into `test/types/`. Keeping the
contents unchanged retains every `satisfies` and `@ts-expect-error` assertion,
including negative compiler checks. The three package-level TypeScript project
filenames remain stable; their explicit `files` inputs point at the new paths.

| original file                         | destination                                      | retained contract                                                                                                                                            |
| ------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `config-type-test.ts`                 | `test/types/config-type-test.ts`                 | config literals/factories, exact service references, target/provider settings, and invalid field combinations                                                |
| `sdk-type-test.ts`                    | `test/types/sdk-type-test.ts`                    | publisher file versus ID, native enrollment separation, removed credentials, and IP-setting shape                                                            |
| `runtime-type-test.ts`                | `test/types/runtime-type-test.ts`                | ungenerated protocol unions, readonly browser metadata, driver compatibility, and the absent `/server` export                                                |
| `runtime-augmented-type-test.ts`      | `test/types/runtime-augmented-type-test.ts`      | exact generated registry, optional services, SQL/HTTP/Kubernetes settings, readonly fields, hidden credentials, and spreading handles without copying `then` |
| `runtime-augmented-cjs-type-test.cts` | `test/types/runtime-augmented-cjs-type-test.cts` | the same augmented service registry and readonly protocol-specific settings through CommonJS declarations                                                    |
| `next-type-test.ts`                   | `test/types/next-type-test.ts`                   | object, Promise, synchronous factory, and asynchronous factory inputs; project-only settings rejected                                                        |
| `vite-type-test.ts`                   | `test/types/vite-type-test.ts`                   | public plugin call signature and rejected project settings                                                                                                   |
| `workload-type-test.ts`               | `test/types/workload-type-test.ts`               | readonly request-scoped provider callbacks/token files; static tokens, multiple sources, and provider policy rejected                                        |
| `workload-cjs-type-test.cts`          | `test/types/workload-cjs-type-test.cts`          | CommonJS workload types and rejecting provider policy in SDK configuration                                                                                   |

`task js:typecheck` continues to run `type-test.tsconfig.json` and
`augmented-type-test.tsconfig.json`. `sdk-type-test.tsconfig.json` remains the
framework-matrix subset.

### fixtures and test mechanics

- `test-helper/*` moved to `test/helpers/*`. Relative SDK imports, source bridge
  imports, copied package roots, and framework executable paths follow the move.
  Environment setup remains global for both Node and DOM projects.
- `fixtures/*` moved to `test/fixtures/*`: Bun server; Next app/config/layout/page;
  Vite app/config/HTML/client and dev binary; workload TLS material; database
  drivers, Drizzle config, installed Drizzle launcher, and native runtime consumer.
  Fixture bytes are unchanged except the installed launcher's SDK import/root
  depth. Its consumer commands still run from the installed consumer's cwd.
- The cross-language registration golden is read from its integrated native owner,
  `internal/publisher/localapi/protocol/testdata/runtime.json`. Shared project
  metadata and hostname JSON fixtures remain under `api/fixtures`.
- Installed transport packing runs from `packages/ts`; its pnpm version lookup
  runs from the repository root. Fresh-store installation and the Node/Bun
  consumer subprocess cwd remain the temporary installed consumer directory.
- Vitest coverage aliases accept nested role paths under `../../dist/internal/`
  and redirect the connector bridge to `test/helpers/source-connection-bridge.ts`.
  Normal runs exercise built modules; coverage runs instrument the source graph.
  Coverage still includes every `packages/ts/src/**/*.ts` owner.
- Root TypeScript discovery includes `test/helpers`, TypeScript/TSX fixtures,
  moved tests, tooling, and `internal/client/project/loader.ts`. Node, DOM, and
  browser project selection retains its previous suffix rules.

## parent task and caller handoff

These changes belong to the parent Taskfile/tooling/CI owners. Existing public
Task names remain the selectors; only their file arguments change.

| old selector or caller input                                                                                    | final input                                                  |
| --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `packages/ts/*.test.ts`                                                                                         | `packages/ts/test/**/*.test.ts`                              |
| `packages/ts/tracing.test.ts`                                                                                   | `packages/ts/test/native/tracing.test.ts`                    |
| `packages/ts/app-runtime.test.ts`, `packages/ts/adhoc-*.test.ts`                                                | same filenames under `packages/ts/test/publisher/`           |
| `packages/ts/connection*.test.ts`, `packages/ts/awaitable-connection.test.ts`, `packages/ts/workload-*.test.ts` | same filenames under `packages/ts/test/connector/`           |
| `packages/ts/runtime.test.ts`, `packages/ts/service-metadata.test.ts`, `packages/ts/errors.test.ts`             | same filenames under `packages/ts/test/project/`             |
| `packages/ts/vite.test.ts`, `packages/ts/next.test.ts`                                                          | same filenames under `packages/ts/test/frameworks/`          |
| `packages/ts/bun.test.ts`, `packages/ts/launcher.test.ts`                                                       | same filenames under `packages/ts/test/native/`              |
| `packages/ts/test-helper.test.ts`                                                                               | `packages/ts/test/helpers/test-helper.test.ts`               |
| `.github/workflows/checks.yml`: `packages/ts/$FRAMEWORK.test.ts`                                                | `packages/ts/test/frameworks/$FRAMEWORK.test.ts`             |
| `packages/ts/fixtures/connections/installed-drizzle.ts`                                                         | `packages/ts/test/fixtures/connections/installed-drizzle.ts` |
| `packages/ts/fixtures/connections/drizzle.config.ts`                                                            | `packages/ts/test/fixtures/connections/drizzle.config.ts`    |
| `packages/ts/src/internal/native-targets.ts`                                                                    | `packages/ts/src/internal/native/native-targets.ts`          |
| `scripts/build-ts-bridges.ts`                                                                                   | `scripts/build/ts-bridges.ts`                                |

Exact focused Vitest arguments after `mise exec -- pnpm exec vitest run`:

```text
# js:test:client-tracing
packages/ts/test/native/tracing.test.ts packages/ts/test/publisher/app-runtime.test.ts packages/ts/test/connector/connection.test.ts packages/ts/test/connector/connection-fetch.test.ts packages/ts/test/connector/connection-owner-recovery.test.ts packages/ts/test/publisher/adhoc-open.test.ts packages/ts/test/publisher/adhoc-fetch.test.ts packages/ts/test/frameworks/vite.test.ts packages/ts/test/frameworks/next.test.ts

# js:test:connections
packages/ts/test/connector/connection.test.ts packages/ts/test/connector/awaitable-connection.test.ts packages/ts/test/connector/connection-fetch.test.ts packages/ts/test/connector/connection-ipc.test.ts packages/ts/test/connector/connection-installed.test.ts packages/ts/test/connector/connection-owner-recovery.test.ts packages/ts/test/connector/workload-native.test.ts packages/ts/test/connector/workload-provider.test.ts packages/ts/test/connector/workload-contract.test.ts packages/ts/test/project/service-metadata.test.ts

# js:test:frameworks
packages/ts/test/publisher/app-runtime.test.ts packages/ts/test/native/bun.test.ts packages/ts/test/frameworks/vite.test.ts packages/ts/test/frameworks/next.test.ts packages/ts/test/project/runtime.test.ts
```

The moved `scripts/package/npm-consumer.ts` browser input guard now rejects
`internal/native/` and connector implementation imports, allowing only the
browser-safe `connector/awaitable_connection` helper. Its installed ESM/CommonJS,
error identity, shared workload singleton, and negative browser workload assertions
remain intact.

## execution evidence

Platform: macOS arm64, Node `v22.23.2`, Bun `1.4.2`, installed pinned workspace
dependencies. Commands ran through `mise exec --`. No deployed server or workload
was used.

| command after `mise exec --`                                                                                                  | result                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm --filter @tnldotdev/tnl build`                                                                                          | passed; clean output rebuilt declarations, ESM, CommonJS bridges, browser CommonJS, and dependency licenses                                                                 |
| `pnpm exec tsc --project packages/ts/type-test.tsconfig.json`                                                                 | passed, including all ordinary positive and negative type assertions                                                                                                        |
| `pnpm exec tsc --project packages/ts/augmented-type-test.tsconfig.json`                                                       | passed, including augmented ESM/CommonJS assertions                                                                                                                         |
| `pnpm exec tsc --project packages/ts/sdk-type-test.tsconfig.json`                                                             | passed                                                                                                                                                                      |
| `pnpm exec vitest run packages/ts/test`                                                                                       | initial run: 171 passed, one missing in-flight Go golden; that golden path was corrected to the integrated owner                                                            |
| `pnpm exec vitest run packages/ts/test/publisher/app-runtime.test.ts`                                                         | passed, 15 tests against built modules after correcting the golden path                                                                                                     |
| `pnpm exec vitest run --coverage --mode coverage packages/ts/test`                                                            | passed, all 172 tests in 21 suites; nested owner source aliases exercised; 82.14% line coverage                                                                             |
| `pnpm exec vitest run --project dom`                                                                                          | passed, 19 tests in three suites; shared DOM setup retained                                                                                                                 |
| direct built-package Node/esbuild assertions                                                                                  | passed: ESM/CommonJS public exports and `TnlError` identity, shared workload singleton, browser import/require input guards, and rejected browser workload imports/requires |
| focused `oxlint --deny-warnings --report-unused-disable-directives` on SDK, bridge builder, consumer guard, and Vitest config | passed                                                                                                                                                                      |
| focused `oxfmt --check` on SDK, bridge builder, consumer guard, root TypeScript config, and Vitest config                     | passed                                                                                                                                                                      |
| `pnpm exec tsc --project tsconfig.json`                                                                                       | blocked by concurrent tooling changes: missing moved `validation.ts` imports and OpenAPI generator/test strict typing; no SDK diagnostics                                   |

The latest root TypeScript check narrowed the remaining failure to
`scripts/development/render-local-capacity.ts`: its `./validation.ts` import must
follow the helper to `../package/validation.ts`. The earlier generator typing
failures were resolved by their owner. The tooling owner also needs to update
`scripts/package/verify-packages.ts` to copy the moved
`test/fixtures/connections/drizzle.config.ts` input.

The browser-condition installed-consumer checks and framework version matrix
remain in their existing packaging/CI owners. Local SDK tests exercised real
Next/Vite/Bun subprocesses and installed Node/Bun transport. The independent
darwin/linux arm64/x64 catalog assertions passed; this macOS run does not claim
execution on the other native targets.

Native Go fixture integration, Python native-owner checks, the full package
verifier, the browser automation tier, and alternate framework/platform matrix
jobs remain parent validation work after all Go/tooling paths settle. The source
moves retain their fixtures and assertions. No native Go fixture tier was run
during the concurrent Go moves.
