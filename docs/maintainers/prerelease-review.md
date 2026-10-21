# prerelease implementation review

this ledger tracks the remaining coordinated native and website rewrite. a
component test or implementation handoff does not qualify the whole rewrite.
planning, integration, and direct review remain in the parent conversation;
subagents implement bounded tasks in separate worktrees.

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

## findings and implementation evidence

| boundary              | failing scenario                                                                   | implementation or next correction                                                                | regression and remaining evidence                                                                                             |
| --------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| provider contracts    | non-GitHub sessions require GitHub metadata                                        | integrated `4b5ba42a`                                                                            | implementation tests reported; cumulative review pending                                                                      |
| owner expiry          | an explicit await retains a scheduled-expired owner                                | integrated `c84add47`; broader native-owner changes under review                                 | early death, stable pools, and deployed freeze/thaw still require review                                                      |
| native workload owner | HTTP-only dispatch rejects databases; services start and fail together             | shared incremental owner and prepared-only synchronous reads integrated                          | real emitted Node 24 HTTP/PostgreSQL artifact implemented; deployed startup remains open                                      |
| HTTP pool             | replacement may keep an existing pool because loopback settings stay the same      | transport-generation pool invalidation and verified warm IPC reuse integrated                    | local streaming, generation and cold/warm budgets covered; deployed freeze/thaw remains open                                  |
| MySQL                 | mysql2 mutates SSL options and verifies config.host                                | ordinary mysql2 stream factory dials loopback while config.host retains managed TLS identity     | real mysql2, pg, Postgres.js, Drizzle and CLI fixtures passed in implementation; legacy mysql lacks required TLS/auth support |
| installer             | `--install --system` skips selected project settings                               | configured system entry point and relative CA capture integrated                                 | actual CLI, readiness, logout and disposable Ubuntu reboot fixture retained after credential removal                          |
| multi-group worker    | ambient AWS/provenance and user-only job gates prevent independent groups          | fixed-list worker with immutable identity bindings and explicit discovery credentials integrated | same-process real-control target/certificate/run isolation fixture retained; live cloud remains open                          |
| service inventory     | LIMIT 101 hides access; locale-dependent ordering disagrees with client cursors    | complete pagination plus explicit bytewise SQL ordering integrated                               | mixed-case three-page CLI/API fixtures passed in the combined candidate; website consumer uses all pages                      |
| invitation retry      | a committed response loss leaves the secret unrecoverable without guidance         | candidate returns secretless exact-retry state and explicit revoke/reissue                       | CLI/signed-human tests reported; website recovery UI pending                                                                  |
| observability         | untyped attributes allow mismatches; direct warm IPC bypasses older trace wrappers | typed authoring, client tracing, and warm IPC carrier correction integrated                      | combined tracing/race qualification pending; actual collector dogfooding follows staging                                      |
| accounts startup      | synchronous DB/auth creation cannot await native preparation                       | asynchronous pool/auth owners implemented in the website candidate                               | local real-driver/authority fixtures passed in implementation; actual environment bindings and live qualification remain open |

the latest implementation handoffs also add bounded workload history cleanup and
native-owned function artifacts. direct review checked deletion dependency order,
replay retention, real target forwarding, and absence of a caller-prepared owner.
the final cumulative checks and published PR revisions are recorded separately.

## uncompleted broad review

complete company/account-linking/session review; certificate/DNS recovery;
publisher deployment/fencing and infrastructure generation; existing preview,
sharing, feedback, alias, mount, OAuth, webhook, and usage boundaries; and
observability/exporter failure behavior. no blanket readiness claim is recorded.
