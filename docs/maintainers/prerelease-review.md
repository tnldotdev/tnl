# prerelease implementation review

this ledger tracks corrections and remaining qualification for the coordinated
native and website rewrite. the native documentation review uses integration
commit `b3711908` as its source checkpoint. a correction commit proves what was
integrated; a test present in that commit is not a claim that every cumulative
or deployed check passed. parent integration may advance after this checkpoint.

## delivery order

review and fixes, local qualification, focused signed PRs, matching staging
deployment, live qualification and accounts/tracing dogfooding, then production.
fresh databases and protocol v1 remain the agreed boundary. retired code is
deleted after its unique assertions move to replacement paths.

## accepted work

- shared native workload owners across all protocols, control-verified identity
  reuse, incremental service preparation, and deletion of HTTP-only credentials;
- distinct process/session/lease/stream lifetimes, recovery, bounded pools,
  streamed HTTP, and actual installed database-client compatibility;
- real system-install configuration and readiness, persistent Compose identities,
  and verified target TLS with application-owned HTTP credentials;
- fixed lists of independently provisioned publisher group identities in one
  process, including different teams, with explicit per-group dependencies;
- policy narrowing, complete service-access inventory, invitation retry recovery,
  and bounded durable-state retention;
- typed observability authoring followed by client/framework/group tracing;
- asynchronous accounts database/auth readiness through the deployed native
  connector for separate staging and production Vercel identities;
- updated public guides and comprehensive post-staging qualification in tnl.dev.

the fixed-list group worker reuses existing publisher authorization, server
schema, and tunnel protocol. managed hosted-publisher operations and stable
egress remain a separate proposal. privileged access remains separately reserved.

publisher-to-target credential injection was canceled. its configuration, runtime
packages, secret providers, target IAM permissions, and public guide are deleted.
Secrets Manager remains part of publisher signing-identity bootstrap only.

## review gates

read both changes and existing dependencies. trace documented entry points,
configuration, current authorization, cancellation, recovery, and joined cleanup.
inspect test setup for preconstructed jobs, fake prepared owners, hidden preloads,
or mocks that omit the boundary being claimed. use installed packages, actual CLI
parsing, real ordinary drivers, and the smallest real infrastructure needed.
record local and deployed evidence separately.

## phase status

| phase | status at this checkpoint                                                                                                                                    |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1–3   | correction commits below are integrated through `b3711908`; local regression coverage is identified by boundary, with cumulative qualification still pending |
| 4     | pending parent implementation/review and qualification; this documentation pass does not close adjacent runtime, infrastructure, or observability findings   |
| 5     | native Markdown corrections and evidence ledger prepared from the checkpoint; final parent integration review remains pending                                |
| 6     | cumulative checks, matching staging deployment, live qualification, accounts/tracing dogfooding, and production qualification remain pending                 |

phase numbers describe the coordinated review sequence, not a protocol version.
the transport remains protocol v1 and the machine contracts remain schema 1.

## phase 1–3 correction evidence

these commits and their regression sources are reachable from the checkpoint.
the Task names identify reproducible checks, not an assertion that this docs pass
ran every tier. evidence for earlier rewrite handoffs remains scoped to their
component runs.

| boundary and correction                                                                                                                                                         | commit proof                          | regression boundary                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ad-hoc publication selects the right identity/server, binds one invocation, applies request limits, and cleans up allocation                                                    | `a1d44c1d`                            | `go:test:invocations`; real local publisher handler and SQLite workers                                                                                                   |
| Python app metadata preserves protocol siblings, managed ports and exposure                                                                                                     | `16b1f94e`                            | `py:test`; native-produced assignments and Uvicorn lifecycle fixtures                                                                                                    |
| actual npm release packing and installed consumer exports                                                                                                                       | `e97ccf58`                            | `release:npm-package`; independent npm/pnpm consumers of snapshot artifacts                                                                                              |
| management locks precede publication; private claim response-loss recovery and combined relay capacity                                                                          | `0d4fe298`, `54e891f6`                | `go:test:integration:state-locks`, `go:test:integration:private-claims`; disposable PostgreSQL and actual claim/lease fences                                             |
| durable secret rotation, workload cleanup progress, pageable admission history, bounded inventory summaries                                                                     | `7d9e3073`                            | `go:test:integration:state-boundaries`; projection omission is fixed, closed projection types remain a design follow-up below                                            |
| public HTTP streaming/upgrade guards retain current authorization; alias browser sign-in works; canceled coalesced callers do not cancel siblings                               | `03534bde`, `82342fe4`                | `go:test:live-authorization`, `go:test:integration:live-authorization`; deterministic clocks, HTTP/2 isolation, browser/alias state                                      |
| issued-login cancellation revokes the session; connector conflicts and assignment cleanup remain isolated and bounded                                                           | `2f762702`, `660af9bd`                | `go:test:owner-lifecycle`; cancellation, conflict and cleanup ownership                                                                                                  |
| native process/session deadlines are separate, services prepare independently, prepared reads remain local, and replacement joins cleanup                                       | `cd4ece73`                            | `go:test:owner-lifecycle`, `go:test:integration:owner-lifecycle`, `go:test:connections:budget`; shared HTTP/PostgreSQL owner with a stalled sibling                      |
| configured local apps need no Git/origin; named/app reuse is fenced by the evaluated snapshot; private readiness, mounts, companions and install paths use current declarations | `7a815e62`                            | `go:test:app-workflows`, Linux `go:test:integration:app-workflows`; local identity survives Git initialization/origin changes                                            |
| config serialization, evaluated snapshots, target trust, service references and protocol enums match native contracts                                                           | `ea8f7076`, `fb8559ce`                | `go:test:config-contracts`, `js:typecheck`; real loader/snapshot round trips and status protocol validation                                                              |
| production ingress wiring, pool selection, run-lifetime traffic totals, pending promotion, private fallback and half-closes                                                     | `f94e01b7`                            | `go:test:ingress`, `go:test:integration:ingress`, `go:test:integration:local-oidc`; split/standalone wiring and UID-65532 fixture                                        |
| HTTP upload deadlines, early responses, trailer ownership and interrupted-response inspection                                                                                   | reproducer `fc2bc12b`, fix `141f469b` | `go:test:http-streaming`; real HTTP/1 and HTTP/2 wires, streamed uploads and no payload replay                                                                           |
| TypeScript immutable snapshots, captured caller handles, bounded IPC/provider waits, native transport generation, and owned HTTP dispatch                                       | `1bdf6723`                            | `js:test:connections`; installed ESM/CommonJS consumers run actual Node and Bun with managed Host/SNI and loopback TLS                                                   |
| GitHub Action OIDC acquisition obeys cancellation/deadline and rejects late tokens                                                                                              | `6f9f918f`                            | `connect:check`; hanging provider and cancellation before native startup/export                                                                                          |
| Python publication joins registration/cleanup; failed cleanup is retryable; forked handles cannot stop the parent's owner; subprocess exchange is bounded                       | reproducer `78eacbe9`, fix `8ebc2cf0` | `py:check`; subprocess lifecycle, native owner and private IPC tests                                                                                                     |
| one bounded automatic readiness checker per publish run; repeated ready/target events do not reset its budget                                                                   | `b3711908`                            | `go:test:app-workflows`; `internal/projectpublisher/automatic_readiness_test.go` checks success, budget exhaustion, target changes, replacement, and joined cancellation |

`da9ee72f` also adds current-team-member authorization for signed website usage
reads; `go:test:team-usage` covers its local authority boundary. website consumer
behavior and account readiness need their own repository's evidence.

earlier rewrite findings remain tracked at their owning boundaries:

- non-GitHub session responses omit GitHub execution metadata; common session
  fields and provider-specific validation are described in
  [workload sessions](workload-sessions.md);
- real mysql2, pg, Postgres.js, Drizzle and CLI qualification is version/path
  scoped in the [connection runtime](connection-runtime.md). legacy `mysql`
  2.18.1 remains unsupported; the Node/Bun HTTP check does not qualify SQL drivers;
- [fixed-list groups](publisher-groups.md) retain immutable per-group identities,
  explicit AWS discovery dependencies and local cross-team run/certificate
  isolation evidence. production role/storage qualification remains open;
- [service access](service-access.md) retains complete cursor pagination and
  bytewise ordering. invitation creation retries are secretless and require
  explicit revoke/reissue after response loss; website recovery UI remains open.

## native documentation corrections

- local startup uses directory-bound `LocalPublicationIdentity` and
  `LocalWorktreeKey`; portable apply and workload manifests use Git-based
  `SourceIdentity`. neither local startup nor a visitor lookup applies a revision.
- one evaluated configuration belongs to the local publication owner. discovery
  and named leases compare the complete snapshot digest. after an edit, stop and
  restart all project apps and named local publishers together.
- registered, routable and ready remain distinct. automatic public readiness is
  once per run with a two-minute budget; `tnl wait` can explicitly check again.
- native process, workload session, lease, service adapter, snapshot, pool and
  admitted operation have different lifetimes. HTTP/WebSocket and PostgreSQL
  operations retain current authorization. renewal cannot extend the original
  session window, and replacement never replays admitted application traffic.
- every SDK protocol requires the native binary. mysql2 keeps the managed `host`
  for identity verification and dials loopback with its `stream` factory; its SSL
  copy is mutable. psql/psycopg use verified TLS with `channel_binding=disable` and
  `gssencmode=disable`; the Python guide states libpq trust/version limits.
- publisher certificates require DNS-01 automation even for exact names. named
  groups own managed endpoints; service `public_url` settings cannot override the
  hostname/domain/port or enable anonymous access. the applied API example now
  uses group reachability and a restricted HTTP policy.
- private local publisher docs now list `access_mode`, `ip`, application `limits`,
  `publisher_file`, required lease `configuration_digest`, and the protocol enum;
  removed `allow_ip`/`allow_all_ips` fields are no longer advertised as inputs.

## material Go design follow-ups

runtime fixes do not by themselves complete the requested type-boundary work.
at this checkpoint the following are still pending:

| design boundary               | current evidence                                                                                                                                                                                                                    | remaining work                                                                                                                                                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| closed installed-job variants | `internal/publisherjob/registry.go` still has one exported `Job` struct with kind-specific optional fields; `validateJob` rejects mixed states at runtime                                                                           | introduce closed public-URL/private-service/connector/group variants and deliberate storage conversion; preserve persisted format and joined ownership                                                      |
| safe service projections      | `7d9e3073` adds `serviceaccess.Summary`, omitting target TLS and HTTP limits for bounded inventory; the function still clears fields on `PrivateServiceRecord` and returns the full `controlv1.PrivateService` type                 | split target-free visitor/inventory projections from publisher/manager records so newly added sensitive fields cannot cross by reuse; retain omission and payload-bound checks                              |
| closed principals             | `tunnelv1.VisitorSubject` validates exclusive human/workload wire variants; state APIs recheck the exact subject, key and session. `ControlPrincipal`, `OIDCIdentity`, and the exported subject fields remain constructible records | make verified principal construction and role-specific capabilities explicit at internal API boundaries; keep human control sessions, signed-human bridge proofs, workload visitors and publishers distinct |

the wire subject's validation and the inventory payload fix are resolved runtime
items. closed Go representations remain follow-ups, not a claim that those
runtime fixes are absent. these changes do not require a new protocol version.

## still-open qualification and review

- **Vercel:** the emitted Node 24 artifact starts its own packaged native owner
  and shares HTTP/PostgreSQL locally. deployed token delivery, freeze/thaw,
  native process limits, filesystem behavior, warm pools and recovery after a
  frozen or killed owner still need live evidence. the old external-prepared-owner
  description is corrected.
- **publisher replacement and AWS:** local filesystem and signed SDK fixtures do
  not qualify production EFS advisory locking, ownership/permissions, SDK role
  refresh/assumption, single-replica fencing, or partial certificate-directory
  restore. exercise the real task role, replica-private mount and replacement
  path. a signing identity without its certificate directory is not recovery.
- **telemetry and failure recovery:** typed authoring and local trace-carrier
  tests are component evidence. actual AWS collector/export delivery,
  exporter outage/backpressure, bounded shutdown, process/lease loss and target
  recovery need deployed observation and accounts/tracing dogfooding.
- **certificates and DNS:** qualify real DNS-01 propagation, issuance/renewal,
  uncertain finalization, cleanup after endpoint moves and restored pending/current
  keys. local CA/Pebble and offline infrastructure checks do not establish public
  ACME or production DNS recovery.
- **website and existing workflows:** complete company/account linking and session
  review, actual accounts database/auth environment bindings, invitation
  revoke/reissue recovery UI, preview/sharing/feedback, alias handoff, mounts,
  OAuth/webhooks and usage consumer review against the integrated revisions.
  the earlier website handoff reports asynchronous pool/auth owners and local
  real-driver fixtures; this native documentation pass does not requalify them.
- **cumulative:** phase 4–6 checks and final parent diff review remain open.
  local fixes and passing focused checks do not qualify staging or production.
- **contract prose:** `ProjectServicePublicURL` in
  `api/control/v1/openapi.yaml` still describes named-group domain/hostname and
  pooled-public-URL behavior that the production validator rejects. the Markdown
  example follows `normalizeAppliedProjectService`; aligning the OpenAPI source
  descriptions and regenerated descriptions remains pending in the parent
  contract pass.

the targeted local Bun question is resolved by `1bdf6723`'s explicit owned Undici
transport and actual installed-runtime test. it is not an unresolved direct-dial
transport question; deployed provider lifetime behavior remains open separately.

## documentation-pass validation

at `b3711908` plus this Markdown change:

- `mise exec -- task go:test:config-contracts` passed;
- `mise exec -- task js:test:connections` passed: 10 files, 64 tests, including
  actual Node/Bun installed HTTP transport;
- `mise exec -- task go:test:app-workflows` passed, including the race-enabled
  owner/configuration/readiness packages;
- `mise exec -- task go:test:live-authorization` passed;
- a temporary Go test overlay outside the checkout extracted the actual applied
  API example, decoded the generated request model, and passed its configuration
  through `NormalizeProjectConfiguration`. the same check loaded the private
  service and portable-generation YAML examples through `config.LoadDocument`.
  all three passed; no duplicate validation rules or repository test files were
  added;
- scoped `oxfmt --check` passed for all 13 changed Markdown files, and
  `git diff --check` passed.

these local checks do not exercise deployed systems. no blanket readiness claim
is recorded.
