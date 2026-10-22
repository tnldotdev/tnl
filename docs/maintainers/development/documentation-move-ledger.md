# documentation move ledger

The documentation now describes the frozen role-owned source tree in
`/Users/chase/.worktree/tnl/role-organization`, branch
`0xcadams/role-organization`, with `HEAD` at `bc1efd09`. This is an uncommitted
documentation integration snapshot. Source moves are implemented; final
generation, behavioral/platform checks, reviewed commit, and second-PR delivery
are separate parent work.

## plans and evidence boundary

Both full accepted plans remain at their original paths:
[domain boundaries](../domain-boundaries-plan.md) and
[role organization](../reorganization-plan.md). Their historical source columns,
scope, and earlier command evidence are preserved. The organization plan now
separates implemented moves from pending final checks and links the actual maps.

The parent reports PR [#448](https://github.com/tnldotdev/tnl/pull/448) completed
its checks after reconciliation with main at
`b6428e0dde41cabc02432b6a4b321c23bb534057`. The newer domain-plan completion
record is in the separate domain worktree and has not been merged here. Leave
this branch's domain plan intact for that merge; its pending-delivery language
is a historical snapshot, not the current first-PR status. Those first-PR results
do not qualify this uncommitted role-organization tree. No second PR URL or final
tested role-organization commit has been supplied.

The six implementation inventories retain their own scoped evidence:
[Go](go-move-ledger.md), [publisher](publisher-move-ledger.md),
[connector](connector-move-ledger.md), [contracts](contracts-move-ledger.md),
[SDK](sdk-move-ledger.md), and [tooling](tooling-move-ledger.md).
The [deduplication ledger](deduplication-ledger.md) records subsequent ownership
consolidation. An initial blocked compile, a later source repair, and a passing
behavioral run are different facts; retain all three when the parent adds results.

## complete documentation rename map

Paths are repository-relative. Each row is an exact old/new pair for the parent
path rewriter, including Go fixture/baseline source strings and assembled
`filepath.Join` components. This documentation pass edits Markdown only; apply
the same map to source consumers at their owners without changing assertions or
baseline bytes. There are no forwarding Markdown stubs.

| original path                               | final path                                            |
| ------------------------------------------- | ----------------------------------------------------- |
| `docs/maintainers/applied-projects.md`      | `docs/maintainers/control/applied-projects.md`        |
| `docs/maintainers/company-access.md`        | `docs/maintainers/control/company-access.md`          |
| `docs/maintainers/control-state.md`         | `docs/maintainers/control/control-state.md`           |
| `docs/maintainers/hosted-integration.md`    | `docs/maintainers/control/hosted-integration.md`      |
| `docs/maintainers/oidc.md`                  | `docs/maintainers/control/oidc.md`                    |
| `docs/maintainers/private-services.md`      | `docs/maintainers/control/private-services.md`        |
| `docs/maintainers/service-access.md`        | `docs/maintainers/control/service-access.md`          |
| `docs/maintainers/team-usage.md`            | `docs/maintainers/control/team-usage.md`              |
| `docs/maintainers/workload-sessions.md`     | `docs/maintainers/control/workload-sessions.md`       |
| `docs/maintainers/connection-runtime.md`    | `docs/maintainers/connector/connection-runtime.md`    |
| `docs/maintainers/kubernetes-native.md`     | `docs/maintainers/connector/kubernetes-native.md`     |
| `docs/maintainers/platform-access.md`       | `docs/maintainers/connector/platform-access.md`       |
| `docs/maintainers/vercel-functions.md`      | `docs/maintainers/connector/vercel-functions.md`      |
| `docs/maintainers/aws-bootstrap.md`         | `docs/maintainers/publisher/aws-bootstrap.md`         |
| `docs/maintainers/aws-target-discovery.md`  | `docs/maintainers/publisher/aws-target-discovery.md`  |
| `docs/maintainers/database-cancellation.md` | `docs/maintainers/publisher/database-cancellation.md` |
| `docs/maintainers/publisher-egress.md`      | `docs/maintainers/publisher/publisher-egress.md`      |
| `docs/maintainers/publisher-generation.md`  | `docs/maintainers/publisher/publisher-generation.md`  |
| `docs/maintainers/publisher-groups.md`      | `docs/maintainers/publisher/publisher-groups.md`      |
| `docs/maintainers/publisher-provenance.md`  | `docs/maintainers/publisher/publisher-provenance.md`  |
| `docs/maintainers/client-state.md`          | `docs/maintainers/development/client-state.md`        |
| `docs/maintainers/client-tracing.md`        | `docs/maintainers/development/client-tracing.md`      |
| `docs/maintainers/errors.md`                | `docs/maintainers/development/errors.md`              |
| `docs/maintainers/metrics.md`               | `docs/maintainers/development/metrics.md`             |
| `docs/maintainers/portable-generation.md`   | `docs/maintainers/development/portable-generation.md` |
| `docs/maintainers/server-readiness.md`      | `docs/maintainers/development/server-readiness.md`    |
| `docs/maintainers/prerelease-review.md`     | `docs/maintainers/releases/prerelease-review.md`      |
| `docs/maintainers/release-checks.md`        | `docs/maintainers/releases/release-checks.md`         |
| `docs/maintainers/releasing.md`             | `docs/maintainers/releases/releasing.md`              |

The root `docs/maintainers/architecture.md` remains the system/dependency/API
index. Its detailed ownership and lifecycle content is consolidated into:

| final architecture page                        | content owner                                                                                                |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `docs/maintainers/publisher/architecture.md`   | publication, app registration/readiness, local process, targets, groups, integrations/aliases/OAuth/webhooks |
| `docs/maintainers/connector/architecture.md`   | native visitor operations, private owner IPC, selected/prepared transport, workload and cleanup              |
| `docs/maintainers/control/architecture.md`     | durable transactions, serving APIs, current policy, issuer/proxy/secrets, schema and DNS                     |
| `docs/maintainers/transport/architecture.md`   | ingress/relay, retry commitment, capacity, leases, TLS, streaming and transport replacement                  |
| `docs/maintainers/development/architecture.md` | commands/processes, static versus operational config, SDKs, fixtures, Tasks and generation                   |
| `docs/maintainers/releases/architecture.md`    | artifacts, packaging/export checks, installer, deployment and qualification                                  |

## live reference closure

- Root `AGENTS.md` names all seven actual OpenAPI roots, SQL origins/outputs,
  canonical public compatibility exceptions, exact schema/baseline behavior,
  dependency direction, command-versus-process rules, and test placement.
- `contributing.md` follows the current included Task implementations, root
  working directory, focused selectors, sharded/unsharded accounting, standalone
  harness vet/tests, generator order, and SDK CJS/workload export boundaries.
- Moved guides retain their content while source paths and relative links follow
  actual API/role/script/deploy owners. Root, action, deployment and package-local
  readmes and benchmark references follow the same map. The local publisher API
  readme names extracted operations rather than deleted command hooks.
- `.agents/skills/tnl-release-check/SKILL.md` links the moved release-check guide;
  skill discovery paths and root `AGENTS.md` remain uppercase. Release skill
  headings are lowercase; its approval/signing workflow is preserved.
- Both full plans and the six implementation move inventories retain historical
  old-path evidence. User-project output examples such as
  `deploy/publishers/aws.json`, hosted OpenAPI URLs, public `scripts/install.sh`,
  and the seven `pkg/api/*` imports are intentional stable paths.

## code and external ownership handoffs

| owner                          | remaining operation                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| parent source/fixture rewriter | Apply the exact documentation rename map to any source-assembled fixture/baseline paths; preserve assertions, SQL identity, and generated ownership. No Go source is edited by this pass.                                                                                                                                                                                            |
| parent integration             | Regenerate from moved sources, format the integrated code, review generated/wire/public consumer diffs, and run required routine/race/harness/integration/platform/package checks. Static path closure and dry runs are not behavioral proof.                                                                                                                                        |
| parent domain/main merge       | Merge the newer domain completion record and `b6428e0d` reconciliation intentionally; keep role-specific path edits and current exact-baseline guidance when resolving it.                                                                                                                                                                                                           |
| sibling `tnl.dev` sync         | Update `scripts/sync-shared.ts` to map the six served public snapshots and generated website models from serving-owned entrypoints/portable bundles. Preserve hosted `openapi/<name>/v1/openapi.yaml` URLs and rewrite their cross-contract refs deliberately; do not copy only fragment entrypoints. Update diagnostic source/header to `internal/failure/diagnostic/catalog.json`. |
| sibling public/operator docs   | Sync source/deploy references to `deploy/server/{standalone,split}`, `deploy/publisher/{compose,fargate}`, `development/local`, moved maintainer links, and the new contract map. Public generated-project default paths remain unchanged.                                                                                                                                           |

The earlier Go compile diagnostics are repaired in the current source:
`invocation/private_publication.go` keeps `PublisherEnrollmentResult` separate
from the human `currentIdentity`, and connector's metadata lifecycle test uses
`starting`/`publicationReady` callbacks. Their initial failure remains historical
evidence; final execution belongs to the parent's integrated validation record.
Likewise, the SDK/tooling handoffs for the capacity renderer validation import and
Drizzle fixture copy are closed in source. The old contract-prose finding is
corrected in `api/control/public/v1/schemas/projects.yaml`; regenerated comments
still belong to generation.

No new forbidden product import was found in the focused checks of transport
into role orchestrators, local publisher API into its process owner, connector
stream into connector root, or security/policy into server roles. That focused
inspection is not a full dependency audit. The structural differences from the
draft plan are intentional actual ownership: combined `publisher/app`, retained
`internal/config`/`internal/clioutput`, installed jobs in `client/service`, shared
proof in `security/publisherproof`, and cohesive ingress/relay lifetimes.

## validation record

This pass ran scoped Markdown formatting, local link/anchor/path inspection,
and whitespace checks on macOS against the uncommitted documentation tree.
It does not run code generation, global formatting, Go/SDK behavioral suites, a
deployed workload, or release checks. Public product docs in sibling `tnl.dev`
are a reported sync requirement; no sibling files were edited.

| check                                                                         | status                                                                                                                                |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| scoped Markdown formatting and read-only format check                         | passed: `mise exec -- pnpm exec oxfmt --write` on owned files, then `--check` on all 52 selected Markdown files                       |
| local Markdown link targets and anchors, including `.agents` references       | passed: 178 local links across 82 Markdown files and 14 Markdown fragments, zero unresolved; remote HTTP availability was not checked |
| active documentation source paths and rename-map closure                      | passed: all 29 exact old/new ledger pairs resolve, old files absent, zero stale mapped paths outside historical plans/ledgers         |
| lowercase headings                                                            | passed: 451 Markdown headings checked, zero uppercase prose; code identifiers retain exact case                                       |
| owned Markdown whitespace check                                               | passed: scoped `git diff --check`; the domain plan also has zero diff against `HEAD`                                                  |
| final role-organization generated/runtime/platform qualification and delivery | parent-owned, pending                                                                                                                 |

The read-only link/heading/path audit used a temporary script outside the
repository. Its rename-map check parses table cells after oxfmt alignment; the
initial whitespace-sensitive comparison was corrected before recording the
passing result. No validation result here claims code execution or a tested
implementation commit.
