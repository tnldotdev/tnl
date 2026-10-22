# role organization plan

Organize implementation by the role that owns its lifecycle and authority.
Publisher, connector, control, ingress, relay, and daemon composition should be
findable without tracing a large set of unrelated top-level packages. Keep
shared policy, security, naming, transport, observability, and failures below the
roles that use them.

This is the complete second-PR plan. The first PR follows the
[domain boundaries plan](https://md.cormo-turtle.ts.net/.worktree/tnl/role-organization/docs/maintainers/domain-boundaries-plan.md).
Status: planned. Target paths below are decisions to implement, not a description
of completed moves. Implementation commits, generated-source checks, preserved
assertions, and actual validation results belong in the ledgers at the end.

The first PR's domain implementation is complete in the shared tree; its final
validation and delivery are still pending. The linked domain plan records that
execution snapshot. All organization, coverage-move, and delivery entries in this
second-PR plan remain pending.

## baseline and two-pr sequence

| Item                   | Execution anchor                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| Latest baseline        | `5203676605d98999cfc012ec20fa857fa0271db9`                                                       |
| Landed rewrite         | PR #442 at `48a2b8e5`; its tree matches `331def37`                                               |
| Superseded checkpoints | Earlier `45c`, `b371`, and `e423` checkpoints are stale and supply no current execution evidence |
| First PR branch        | `0xcadams/domain-boundaries`                                                                     |
| Second PR branch       | `0xcadams/role-organization`, stacked on the first PR                                            |
| Working directory      | `/Users/chase/.worktree/tnl/role-organization`                                                   |

The execution request covers both comprehensive plans and two shipped PRs. Add
both plans with the first PR. Complete domain ownership and correctness changes
there, then move those owners and their tests in the second PR. Record the first
PR's final commit as the second PR's execution base. Review the second PR against
`0xcadams/domain-boundaries` while stacked, then update the base after it lands.

Use semantic commit messages and PR titles. Keep implementation evidence tied to
the commit actually tested. A stale checkpoint's check results do not qualify a
new tree, and a plan entry is not implementation evidence.

## compatibility and move rules

- Preserve public Go APIs, SDK exports, HTTP and tunnel contracts, stored
  encodings, token/hash derivation, CLI behavior, defaults, and artifact content.
  Apply the first plan's deliberate malformed-input and typed-nil corrections in
  the first PR, with their own regression evidence.
- Preserve all seven canonical generated Go import paths under `pkg/api`.
  The newest public Go compatibility requirement overrides earlier proposals to
  move or break them. Preserve `pkg/tnl` and `pkg/protocol/tunnelv1` as well.
- Move internal implementations and all callers together. Remove old internal
  packages after the move; do not leave forwarding functions, type-alias
  facades, duplicate implementations, or a second canonical package.
- Edit generator sources and configurations before regenerating outputs. Keep
  source, generator, embed path, output, fixtures, and drift-check paths in one
  inventoried move.
- Preserve PostgreSQL/SQLite schemas, migration versions, baseline identities,
  and migration behavior. Relocating a migration is not permission to edit it or
  create a new baseline.
- Split a package only around an owned boundary with a useful consumer. Avoid
  one package per file, generic `common` packages, and role names that hide the
  actual owner. Keep relay cohesive.
- Preserve unique test assertions before removing or consolidating old suites.
  Fix imports and test selection rather than dropping difficult coverage.

## target ownership map

The tables give the complete migration scope from the execution baseline.
Paths are relative to the repository. A row can require more than a directory
rename when files currently combine lifecycles; record that split and its callers
in the move ledger. Keep a package's existing name when it is still clear, or
update import aliases consistently when the new leaf name is clearer.

### publisher

`internal/publisher` continues to own a publication's visitor TLS, certificate
installation, publisher connections, visitor admission, and target forwarding.
Its root is the reusable publication runtime. App-led orchestration, local owner
HTTP, groups, and setup compose that runtime from children; the root does not
import those orchestrators.

| Current owner                             | Target owner                                        | Boundary                                                                                           |
| ----------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `internal/publisher`                      | `internal/publisher`                                | One public or managed publication, admission, visitor TLS, and publisher connections               |
| `internal/projectpublisher`               | `internal/publisher/app`                            | Configured app workers, target bindings, exact-run observations, and automatic readiness           |
| `internal/clientruntime`                  | `internal/publisher/local`                          | Local registration leases, owner liveness, snapshots, events, and readiness journal                |
| `internal/localpublisher`                 | `internal/publisher/localapi`                       | Private native owner HTTP serving, scoped capabilities, descriptors, and app/invocation requests   |
| `internal/privateprotocol`                | `internal/publisher/protocol`                       | Bounded app/CLI registration protocol and validated local assignments                              |
| `internal/publisherprovision`             | `internal/publisher/setup`                          | Explicit installation, enrollment, bootstrap, and setup cleanup                                    |
| `internal/publisherjob`                   | `internal/publisher/invocation`                     | One owned publication job, preparation, retry, cancellation, and joined completion                 |
| `internal/privatepublisher`               | `internal/publisher/managed`                        | Managed private/service publication and its approved run/target plan                               |
| `internal/grouppublisher`                 | `internal/publisher/group`                          | Applied group assignment polling, independent member jobs, acknowledgments, and joined shutdown    |
| `internal/publisherruntime`               | `internal/publisher/runtime`                        | Publisher runtime lease, signed deployment/egress context, and identity-bound runtime coordination |
| `internal/publisheridentity` and children | `internal/publisher/identity` and matching children | Signing identity, native grants, proof, and portable credential-file ownership                     |
| `internal/adhoc`                          | `internal/publisher/adhoc`                          | Temporary public URL allocation and cleanup for an invocation                                      |
| `internal/integrationurls`                | `internal/publisher/integrations`                   | OAuth, webhooks, and alias worker election, selection, readiness, locks, and drain                 |
| `internal/localproxy`                     | `internal/publisher/proxy`                          | Local HTTP target forwarding, mounts, header handling, and request observation                     |
| `internal/publishertarget`                | `internal/publisher/target`                         | Exact local/Compose target identity and per-connection capture                                     |
| `internal/targettransport`                | `internal/publisher/target/transport`               | Approved publisher-to-target TLS and protocol-aware preflight/handshake                            |
| `internal/tcptarget`                      | `internal/publisher/target/tcp`                     | Validated opaque TCP target addresses and dialing inputs                                           |
| `internal/targetdiscovery`                | `internal/publisher/discovery`                      | Publisher-side bounded EKS/RDS discovery and assignment adaptation                                 |
| `internal/rdsroots`                       | `internal/publisher/discovery/rdsroots`             | Pinned RDS CA catalog and region/resource trust selection                                          |
| `internal/kubernetes`                     | `internal/publisher/k8s`                            | Publisher-side Kubernetes target authentication and HTTP stream handling                           |
| `internal/inspection`                     | `internal/publisher/inspection`                     | Bounded HTTP and supported TCP summary values, without application payloads or credentials         |
| `internal/protocolinspection`             | `internal/publisher/inspection/protocol`            | Bounded PostgreSQL/MySQL/Redis response parsers and body-free observations at the publisher        |
| `internal/feedbacktoolbar`                | `internal/publisher/toolbar`                        | Development-only feedback browser source, tests, bundle, and Go embedding                          |
| `internal/publisherapi`                   | `internal/publisher/browserapi`                     | Same-origin browser contract adapters and generated browser validators                             |
| `internal/publisherdeployment`            | `internal/publisher/deployment`                     | Offline publisher infrastructure generation, manifests, and storage checks                         |
| `internal/publisherprovenance`            | `internal/publisher/provenance`                     | Signed publisher deployment metadata and verification                                              |
| `internal/awsbootstrap`                   | `internal/publisher/setup/aws`                      | AWS bootstrap verification and scope-bound enrollment adapter                                      |
| `internal/demo`                           | `internal/publisher/demo`                           | Demo publication composition and its existing feedback/access behavior                             |

Keep app registration protocol separate from connector owner IPC and from the
browser feedback API. Share a lower-level HTTP/IPC primitive only when its
contract is genuinely identical. A package move must not broaden an app's
capability to include native owner or connector authority.

Move the toolbar's TypeScript and generated `toolbar.js` together. Update its
builder, embed directive, browser test configuration, CSP fixtures, lint paths,
and generated drift checks. Browser validators continue to derive from the
publisher browser OpenAPI contract rather than copied Go or TypeScript shapes.

### connector

`internal/connector` names the native visitor-side connection capability.
Publishing an app and connecting to a private service remain different roles,
even when one local native owner composes both for an SDK.

| Current owner                                        | Target owner                    | Boundary                                                                                                    |
| ---------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Control/lifecycle selection in `internal/tcpconnect` | `internal/connector`            | Human or workload connect operation, current assignment, loopback/stdio ownership, and cleanup              |
| Stream/session mechanics in `internal/tcpconnect`    | `internal/connector/stream`     | Device-authenticated ingress paths, accepted peer, per-stream admission, inner TLS, and half-close          |
| `internal/connectionruntime`                         | `internal/connector/runtime`    | Bounded native owner IPC, prepared metadata/transport identity, listener generations, and sibling isolation |
| `internal/workloadclient`                            | `internal/connector/workload`   | Native workload acquisition, assertion refresh, subject binding, and fixed session expiry                   |
| `internal/kubeconfig`                                | `internal/connector/kubeconfig` | Owned kubeconfig projection, selected-user credentials, exec-plugin bounds, and cleanup                     |

Split `tcpconnect` by responsibility, not filename count. Root operations compose
stream mechanics; the stream package accepts the smallest validated assignment
and peer values and does not import root operations. The runtime exposes a narrow
backend interface, so it can own process/listener lifetime without importing its
CLI or concrete connector backend. Workload and kubeconfig adapters retain their
existing authentication and cancellation boundaries.

Preserve prepared-only reads, atomic publication of metadata with transport
identity, selected connection lifetimes, HTTP fetch Host/SNI verification,
loopback-only dial behavior, stream close ordering, and action-owned cleanup.
An SDK's native registration capability must not become a private extension API.

### control

Control owns durable state and current decisions. Its API names identify the
caller, not a separate serving role. Only control/standalone receives PostgreSQL,
storage, DNS, ACME, mailer, and authority configuration.

| Current owner                          | Target owner                            | Boundary                                                                                                    |
| -------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `internal/controlapi`                  | `internal/control/api`                  | Public control HTTP handlers, authentication adapters, and problem rendering                                |
| `internal/authorityapi`                | `internal/control/authorityapi`         | Built-in authority, identity/session/team/domain/company/workload operations                                |
| `internal/ingressapi`                  | `internal/control/ingressapi`           | Control's private ingress coordination endpoints                                                            |
| `internal/relayapi`                    | `internal/control/relayapi`             | Control's private relay coordination endpoints                                                              |
| `internal/controlstate`                | `internal/control/state`                | Transactions, authoritative authorization, placement, runs, retention, routing history, and audit           |
| `internal/controlstate/controlstatedb` | `internal/control/state/controlstatedb` | Generated PostgreSQL access; migrations, queries, and sqlc configuration stay with its owning state package |
| `internal/certificates`                | `internal/control/certificates`         | Certificate work orchestration and durable order/installation transitions                                   |
| `internal/acmeclient`                  | `internal/control/certificates/acme`    | ACME protocol adapter without independent authorization policy                                              |
| `internal/dnscontroller`               | `internal/control/dns`                  | DNS authority, challenge work, and public/managed endpoint DNS coordination                                 |
| `internal/emaildelivery`               | `internal/control/email`                | Invitation email delivery leases and external mailer adapter                                                |
| `internal/publicurlusageworker`        | `internal/control/usage`                | Durable public URL usage checkpointing, finalization, and delivery                                          |
| `internal/webhookcatalog`              | `internal/control/webhookcatalog`       | Bounded documented webhook sender-feed lookup and cache                                                     |
| `internal/controlproxy`                | `internal/control/proxy`                | Public control HTTPS proxy peer/origin validation                                                           |

Keep state transactions cohesive during this move. Group files by named domain
inside the state package where helpful, but do not create a collection of
mutually dependent repositories or replace one transaction with cross-package
calls that change lock scope. Preserve exact-schema/baseline checks and the
direct migration URL versus pooled serving URL boundary.

API packages depend on owned state/service interfaces and generated contracts;
state does not import HTTP handlers. Ingress and relay import their coordination
client contracts or small shared projections, never the control database package.
Standalone adapters enforce the same identities, leases, and authorization as
split HTTP calls.

### ingress, relay, transport, and daemon

| Current owner                                          | Target owner                    | Boundary                                                                               |
| ------------------------------------------------------ | ------------------------------- | -------------------------------------------------------------------------------------- |
| `internal/ingress`                                     | `internal/ingress`              | Acceptance and one-time visitor forwarding composition                                 |
| Routing projection and selection leaves within ingress | `internal/ingress/routing`      | Immutable validated routing views and eligible candidate selection                     |
| Admission/capacity leaves within ingress               | `internal/ingress/admission`    | Pending/ordinary reservations, promotion, and exact release                            |
| Usage/traffic leaves within ingress                    | `internal/ingress/usage`        | Bounded run-lifetime accounting, checkpoints, and terminal retirement evidence         |
| `internal/router`                                      | `internal/ingress/inspect`      | Bounded ClientHello inspection and original-port selection before forwarding           |
| `internal/relay`                                       | `internal/relay`                | Cohesive relay lease, claim registry, authenticated sessions, capacity, and streams    |
| `internal/tunnel`                                      | `internal/transport/tunnel`     | Shared publisher/relay handshakes and transport behavior                               |
| `internal/muxsession`                                  | `internal/transport/mux`        | Multiplexed byte-stream mechanism                                                      |
| `internal/streamcopy`                                  | `internal/transport/streamcopy` | Bidirectional copying, cancellation, deadlines, and half-closes                        |
| `internal/proxyproto`                                  | `internal/transport/proxyproto` | Bounded PROXY v2 encoding/decoding                                                     |
| `internal/httpstream`                                  | `internal/transport/httpstream` | HTTP body/trailer ownership and full-duplex streaming primitive                        |
| `internal/routebackend`                                | `internal/transport/forwarding` | Shared forwarding boundary/adapters, with no control database dependency               |
| `internal/tnldruntime`                                 | `internal/daemon`               | Role startup, listeners, process lifecycle, workers, standalone adapters, and shutdown |
| `internal/tnldconfig`                                  | `internal/daemon/config`        | Server role/environment validation and effective settings                              |

Extract focused ingress leaves only when their inputs can be owned independently
of the root. The root owns visitor lifecycle, retry commitment, control-loop
composition, and private/public handoff. Children cannot call back into the root
to manipulate its mutable state. Keep cross-cutting lifecycle tests on production
composition, not just leaf helpers.

Keep relay's registry, lease, connection claim, stream accounting, and drain
coordination together. Separate files and private types are enough when the
lifetime is one cohesive operation. Transport provides mechanics, not placement,
visitor authorization, or a second interpretation of a lease.

`cmd/tnld` remains the daemon entrypoint; `cmd/tnl` remains client command
composition; `cmd/tnlbench` remains the benchmark driver. Standalone composes
control, ingress, and two logical relay services against PostgreSQL. Its in-process
adapters are real implementations of the same role interfaces, not compatibility
forwarders for deleted packages.

### client-shared and cross-role leaves

Use shared packages for concrete common ownership. A role must not import another
role's orchestrator to obtain a formatter, selector, policy value, or key parser.

| Current owner                                                             | Target owner                                            | Boundary                                                                           |
| ------------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `internal/clientauth`                                                     | `internal/client/auth`                                  | Human login/session selection, refresh, and cancellation                           |
| `internal/clientserver`                                                   | `internal/client/server`                                | Normalized server selection and saved context                                      |
| `internal/clientstate` and generated child                                | `internal/client/state` and `clientstatedb` child       | Client SQLite, durable identity/certificate storage, local records, and locks      |
| `internal/projectconfig`                                                  | `internal/client/projectconfig`                         | Project/config discovery, evaluation, provenance, and effective settings           |
| `internal/projectmeta`                                                    | `internal/client/projectmeta`                           | Browser-safe metadata and portable project declarations                            |
| `internal/config`                                                         | `internal/client/config`                                | Versioned configuration types, validation, and schema generation                   |
| `internal/clioutput`                                                      | `internal/client/output`                                | Shared deterministic ASCII diagram renderer                                        |
| `internal/controlclient`                                                  | `internal/client/control`                               | Control API client adapters and selected authentication                            |
| `internal/authorityclient`                                                | `internal/client/authority`                             | Authority API client adapters                                                      |
| `internal/serviceaccess`                                                  | `internal/client/serviceaccess`                         | Signed-human service selection and exact-service access adapter                    |
| `internal/authorization`                                                  | `internal/policy/authorization`                         | Shared decision vocabulary and checks without process startup                      |
| `internal/applicationlimits`, `internal/trafficlimits`                    | Matching children of `internal/policy`                  | Validated request/connection/traffic limits and their distinct accounting          |
| `internal/ippolicy`, `internal/ingresspool`                               | Matching children of `internal/policy`                  | IP policy and pool identity shared across control and ingress                      |
| `internal/readiness`                                                      | `internal/policy/readiness`                             | Readiness definitions/proofs used by app and publisher boundaries                  |
| `internal/webhookips`                                                     | `internal/policy/webhookips`                            | Bounded source ranges and provider-independent matching                            |
| `internal/credentials`, `internal/oidcauth`                               | Matching children of `internal/security`                | Credential primitives and issuer/signature verification                            |
| `internal/certificateidentity`, `internal/privatetrust`                   | Matching children of `internal/security`                | Certificate plan/key validation and private trust primitives                       |
| `internal/visitorcert`, `internal/visitorsubject`, `internal/httpsubject` | Matching children of `internal/security`                | Key-bound certificates and validated subject variants                              |
| `internal/workloadproof`, `internal/workloadmanifest`                     | Matching children of `internal/security`                | Signed assertion proof and portable workload declarations                          |
| `internal/storagekey`                                                     | `internal/security/storagekey`                          | Control-only recoverable-secret encryption primitive                               |
| `internal/naming`, `internal/opaqueid`, `internal/tcpport`                | Retain focused top-level leaves                         | Hostname/worktree composition, opaque IDs, and validated ports                     |
| `internal/observability`, `internal/operatorlog`, `internal/serviceaudit` | Retain focused top-level leaves                         | Process-owned telemetry, safe operational reporting, and audit vocabulary          |
| `internal/failure`, `internal/diagnostic`, `internal/problemtype`         | Retain focused top-level leaves                         | Authored reason/retry catalog, client diagnostics, and HTTP problem classification |
| `internal/httpclient`, `internal/httpjson`, `internal/serviceapi`         | Retain focused top-level leaves                         | Safe HTTP mechanics and service-authenticated problem adapters                     |
| `internal/filelock`, `internal/sqlite`, `internal/workerloop`             | Retain focused top-level leaves                         | Filesystem locks, SQLite mechanics, and bounded worker lifecycle                   |
| `internal/sourcestate`, `internal/githubmetadata`                         | Retain focused top-level leaves                         | Source evidence and bounded GitHub metadata used across roles                      |
| `internal/buildinfo`, `internal/browserfonts`                             | Retain focused top-level leaves                         | Build identity and embedded browser resources                                      |
| `internal/devdns`, `internal/devoidc`                                     | `internal/development/dns`, `internal/development/oidc` | Development-only DNS/OIDC processes and fixtures                                   |
| `internal/benchworkload`                                                  | Retain `internal/benchworkload`                         | Shared local/deployed publisher, visitor, and measurement implementations          |
| `internal/testutil`                                                       | Retain `internal/testutil` with focused children        | Test-only shared fixtures, never imported by product implementations               |
| `internal/publicurlusage`                                                 | Retain `internal/publicurlusage`                        | Usage report/checkpoint values shared with an external receiver contract           |

The configuration package is a shared client-facing contract even when control
validates an applied document. It must remain free of local owner startup, CLI
handlers, and publisher orchestration. Security leaves can be shared code without
sharing access to secrets: ingress and relay still never receive the storage key.

## dependency direction and cycle handling

Use this direction when reviewing each proposed import:

```text
commands and daemon composition
             |
             v
role operations and API adapters
             |
             v
owned runtime/state and focused role leaves
             |
             v
shared policy, security, naming, failure, telemetry, and transport
             |
             v
stable public contracts and external libraries
```

The diagram describes ownership, not a requirement that every call cross every
layer. Generated `pkg/api/*` contracts remain leaves; they do not import role
implementations. Shared leaves do not import CLI commands, daemon composition,
HTTP handlers, or control state. Observability records approved values without
becoming an authorization authority.

When a move exposes a cycle, identify the misplaced responsibility. Prefer an
interface owned by the consumer, an immutable validated value owned at the lower
boundary, or composition in the command/daemon. Move the real implementation and
callers to that owner. Do not solve cycles with an old-path facade, a service
locator, callbacks that expose all root state, or a generic shared package.

In particular, check publisher root versus app/group/integrations; connector root
versus stream/runtime; control state versus API packages; ingress root versus
routing/admission/usage; and standalone composition versus role clients. Keep
public URL placement, current authorization, and durable transaction ownership
in control even when a shared reference type moves lower.

## openapi by serving boundary

Move contract sources to show who serves the HTTP surface. The ingress and relay
coordination APIs are served by control. Local publisher HTTP is private native
registration, and browser publisher HTTP is same-origin visitor functionality.
The public URL usage contract is served by an external receiver.

| Current root source                    | Planned serving-owned root source                   | Canonical Go package retained |
| -------------------------------------- | --------------------------------------------------- | ----------------------------- |
| `api/control/v1/openapi.yaml`          | `api/control/control/v1/openapi.yaml`               | `pkg/api/controlv1`           |
| `api/authority/v1/openapi.yaml`        | `api/control/authority/v1/openapi.yaml`             | `pkg/api/authorityv1`         |
| `api/ingress/v1/openapi.yaml`          | `api/control/ingress/v1/openapi.yaml`               | `pkg/api/ingressv1`           |
| `api/relay/v1/openapi.yaml`            | `api/control/relay/v1/openapi.yaml`                 | `pkg/api/relayv1`             |
| `api/publisher/v1/openapi.yaml`        | `api/publisher/browser/v1/openapi.yaml`             | `pkg/api/publisherv1`         |
| `api/local-publisher/v1/openapi.yaml`  | `api/publisher/local/v1/openapi.yaml`               | `pkg/api/localpublisherv1`    |
| `api/public-url-usage/v1/openapi.yaml` | `api/integrations/public-url-usage/v1/openapi.yaml` | `pkg/api/publicurlusagev1`    |

Keep each root as the entrypoint for its generator and consumers. Split long
contracts into referenced `paths/` and `schemas/` fragments by owned domain. The
following grouping is a source-layout scope, not permission to add endpoints:

| Contract                | Fragment domains for existing operations and schemas                                                                                                                                                         |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Control                 | Discovery/health, projects/applied configuration, public URLs, publish runs, publishers/groups, private services/runs, visitor admission, certificates/DNS, previews/shares, feedback, administration, usage |
| Authority               | Sessions/device login, identities, teams/memberships, invitations, domains, company setup/recovery, service access, workload sessions                                                                        |
| Ingress coordination    | Process leases/pools/ports, routing snapshots/history, admission/promotions, recovery and usage                                                                                                              |
| Relay coordination      | Process leases, publisher claims/assignments, transport certificates, admission, and drain                                                                                                                   |
| Publisher browser       | Feedback reports/threads/events, evidence/source state, and existing browser access operations                                                                                                               |
| Local publisher         | Prepare/register/renew/unregister, invocation operations, status/check/watch, and scoped problems                                                                                                            |
| External usage receiver | Usage bucket report, acknowledgment/problem shapes, and shared report values                                                                                                                                 |

Use one source for byte-identical shapes; reference control schemas when that is
the established wire ownership. `api/shared/v1/components.yaml`, if needed, may
contain only byte-identical referenced schemas and generates no Go package.
Similar names or concepts are not enough to merge schemas. Keep stable schema
names, operation IDs, tags used by generators, enum values, and generated public
types. Update every relative `$ref`, oapi-codegen import mapping, normalizer,
browser validator input, fixture loader, and website consumer reference.

Regenerate all seven packages in place. Their `generate.go`, generator config,
and generated files remain the canonical public implementation at the existing
import paths. There is no old/new generated API bridge. Any generated diff beyond
source provenance or internal reference plumbing needs an explicit compatibility
explanation and the existing wire/consumer evidence.

## typescript, python, and action layout

Keep public TypeScript entrypoints and `package.json` export conditions stable.
Group private implementation and tests by role so importing browser metadata
cannot pull in Node credentials or native startup.

| Private TypeScript scope | Planned location and contents                                                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Publisher app lifecycle  | `packages/ts/src/internal/publisher/`: preparation, registration, local owner requests, targets, ports, status, ad-hoc open/fetch                          |
| Connector lifecycle      | `packages/ts/src/internal/connector/`: awaitable connection, owner IPC/bridge, prepared reads, connector fetch, service metadata, and connection lifetime  |
| Workload adapter         | `packages/ts/src/internal/connector/workload/`: assertion/provider acquisition, validated contracts, fixed expiry, cancellation, and late-result rejection |
| Shared SDK mechanics     | `packages/ts/src/internal/shared/`: cancellation, tracing, launcher/platform selection, and genuinely shared fetch types                                   |
| Framework integration    | Public `vite.ts` and `next.ts` retain exports; their private helpers depend on publisher preparation and browser-safe project metadata                     |
| Browser runtime          | `index.browser.ts`, browser-safe project APIs, and generated declarations keep current import restrictions and no native credentials                       |

Move tests into `packages/ts/test/publisher`, `test/connector`, `test/frameworks`,
`test/browser`, and `test/packaging` according to the boundary exercised. Keep
shared test helpers and installed-consumer fixtures explicit. Update Vitest
discovery, coverage includes/excludes, Task selectors, fixture relative paths,
type-test projects, build bridges, ESM/CommonJS checks, and framework version
matrices. Keep source/test naming consistent and preserve every public export,
browser condition, type declaration, and executable target.

The Python binding stays flat under `packages/py`, with its existing public
modules, distribution layout, `py.typed`, and locked dependencies. Update native
fixture imports and source references where Go owners move. Preserve ASGI
lifespan, streamed responses, WebSockets, unregister/drain joins, fork ownership,
and bounded native exchange. Run Ruff, mypy, pytest, and packaging checks.

The GitHub Action remains its separate package under `connect`, with its own
public action inputs, outputs, bundles, and workflow fixture. Update references
to moved SDK/native sources, preserve OIDC cancellation and action-owned cleanup,
and regenerate its committed bundles through its build. Do not fold the action
into the SDK or flatten its independent ownership.

## tests, fixtures, and coverage preservation

Move tests with the behavior they prove. Unit tests stay beside owned Go code;
cross-role runtime proofs stay with daemon composition; subprocess/installed
consumer fixtures stay with their caller. Shared helpers belong in focused
test-only packages. Preserve local `testdata` ownership and use an explicit shared
fixture path only when several implementations consume the same contract.

Inventory `api/fixtures`, tunnel golden/framed fixtures, native registration
goldens, browser metadata, config literals/type tests, SQLite/PostgreSQL fixtures,
cloud signed fixtures, generated deployment goldens, installed npm/Python
consumers, and action workflow data. Update references before removing old paths.
Do not change fixture bytes merely to hide a contract change.

### coverage ledger requirements

For each moved, combined, or removed suite, record:

1. Original package/file, test name, tier, and unique invariant.
2. Destination package/file and assertion name.
3. New owning Task, discovery/selector/shard changes, and fixture destination.
4. Actual command, platform/prerequisites, tested commit, and result.
5. Any remaining gap and the operation needed to close it.

Line coverage is diagnostic; it does not prove preserved authorization,
cancellation, lock ordering, transport behavior, or platform execution. A suite
may be retired only after its unique assertions have moved and passed. A renamed
test must remain discoverable in its intended tier and shard. Keep integration
tests opt-in with `-tnl-*` inputs and no `TNL_TEST_*` variables.

## source-generator-output inventory

Complete this inventory before moving a generated owner. Each row includes the
authoritative source, generator entrypoint, committed output, and all path users.
The paths in the first column are the execution-baseline paths; update the actual
destination and evidence in the move ledger as implementation proceeds.

| Source and generator at baseline                                                                      | Outputs and consumers to move or update                                                                                                                                                             |
| ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Seven OpenAPI roots; `pkg/api/*/generate.go`, oapi-codegen configs, `scripts/normalize-openapi-go.ts` | Preserve seven `pkg/api/*` outputs; update root/fragment refs, generation inputs, Go import mappings, fixtures, documentation, and external source consumers                                        |
| `api/publisher/v1/openapi.yaml`; `scripts/generate-publisher-model.ts`                                | `internal/publisherapi/model.gen.ts` moves with `publisher/browserapi`; update input, exports, tests, lint/typecheck, and drift checks                                                              |
| `internal/controlstate/migrations`, `queries`, `sqlc.yaml`, `generate.go`                             | Move PostgreSQL sources and `controlstatedb` under `control/state`; update embeds, module imports, migration/schema checks, harness, and generated-path filters without changing SQL/baseline bytes |
| `internal/clientstate/migrations`, queries/sqlc config, `generate.go`                                 | Move SQLite sources and `clientstatedb` under `client/state`; preserve `v1.db`, wrapping-key paths, permissions, certificate storage, and lock behavior                                             |
| `internal/config` generators and `scripts/generate-config-types.ts`                                   | Preserve `schema/v1.json` and `packages/ts/src/config.gen.ts`; move `internal/projectconfig/keys.gen.json` with its owner and update every mapping/input                                            |
| `internal/projectconfig/loader.ts`; `scripts/generate-projectconfig-loader.ts`                        | Move source and generated `loader.mjs` with `client/projectconfig`; update embed, Node build input, TypeScript paths, and loader fixtures                                                           |
| `internal/feedbacktoolbar`; `scripts/build-feedback-toolbar.ts`                                       | Move toolbar source/tests and committed `toolbar.js` with `publisher/toolbar`; update Go embed, browser CSP tests, assets, and bundle checks                                                        |
| `internal/publisherdeployment` and its fixture command                                                | Move generator with `publisher/deployment`; preserve `deploy/publishers/fargate.yaml`, example parameters/manifest, storage policy, resource identities, and golden checks                          |
| `internal/diagnostic/catalog.json`; `scripts/generate-diagnostic-codes.ts`                            | Preserve `codes.gen.go`, stable IDs/help URLs, and tnl.dev diagnostic page generation                                                                                                               |
| `internal/failure/reasons.go` and catalog generator                                                   | Preserve `catalog.gen.json`, authored messages/retry policy, and tnl.dev client-error generation                                                                                                    |
| `internal/observability` declarations and vocabulary command                                          | Preserve `api/observability/v1/vocabulary.json`, approved instrument labels, process ownership, and tnl.dev consumption                                                                             |
| `scripts/install.sh.in`; `scripts/generate-installer.go`; CLI renderer                                | Preserve generated `scripts/install.sh` behavior and installer fixtures while updating generator paths                                                                                              |
| SDK build config and `scripts/build-ts-bridges.ts`                                                    | Rebuild disposable `packages/ts/dist`; preserve export conditions, bridge paths, executable modes, native startup, and installed ESM/CommonJS/browser tests                                         |
| `connect` build scripts                                                                               | Regenerate committed `connect/dist`; preserve action inputs/outputs, cleanup, workflow fixture, and separate drift check                                                                            |
| Package/release scripts and GoReleaser config                                                         | Update moved source/tool paths while preserving archive/native npm/wheel contents, hashes' derivation, legal files, notices, and platform targets                                                   |

Update `go generate` ordering: generated API models must exist before internal
generators compile. Keep the full generated-path inventory in `generate-check`,
including untracked-file detection. Update coverage filters and formatter ignores
for generated files; a stale exclusion can hide source from lint or coverage.
Keep disposable build output distinct from committed generated sources.

## tasks, scripts, deployment, and development

### task split and public targets

Keep `Taskfile.yml` as the discoverable public entrypoint. Split implementation
into included Taskfiles by responsibility: generation/formatting, Go routine
checks, Go integration/load, JavaScript, Python, action, local development,
publisher deployment, and release/packaging. Preserve existing public names,
parameters, working directory, dependency ordering, descriptions, and exit status.
Use internal helper Tasks for shared command bodies where appropriate; keep a
single real implementation rather than stale duplicate commands.

Update every hard-coded Go package, Vitest file, generated path, fixture binary,
container mount, and script entrypoint. Keep CI on the same public Task targets.
Retain stable whole-test shard discovery, empty/unsupported selector failures,
separate real-clock proofs, PostgreSQL ownership, tier flags, and timeout budgets.
The separate `tools/testharness` module must have its imports and package lists
updated and be tested independently of the root module.

### script ownership

Group TypeScript tooling by generation, package verification, release tooling,
and development/benchmark reporting where it makes ownership clearer. Move each
script with its tests and update every caller: package scripts, Go directives,
Taskfiles, workflows, release config, and documentation. Keep all Node tooling
authored in TypeScript, strict compiler/lint checks, and external-data validation.
Preserve the shell installer's generated source/output boundary.

### deploy and development boundaries

`deploy` continues to own generic self-hosted Compose and publisher infrastructure
templates. Development Compose, DNS/OIDC helpers, certificates, and fixture
assets remain development-only even when their source paths move. Keep the normal
dev/local commands and working-directory behavior intact.

Preserve local startup order (`local:up`, `local:trust`, `local:login`), keychain
behavior, state preservation on `local:down`, and destructive reset semantics.
Keep direct migration versus pooled serving URLs, role-specific secrets,
nonroot ownership, digest pins, listener ports, volume permissions, and health
checks. Update Docker build COPY paths, Go build targets, Compose mounts, and
private fixture permissions alongside each source move.

Hosted Fly deployment, selected production image digests, and staging rollout
tooling remain owned by the sibling `tnl.dev` repository. Coordinate any source
contract references there explicitly. CI still publishes artifacts without
deploying production. This reorganization does not require a deployed workload
or a change to production Compose images.

### documentation and agent guidance

After the actual moves, update architecture, contributor validation/generator
tables, maintainer topic references, API source links, benchmark commands,
deployment instructions, and root agent guidance to match the implemented tree.
Public product/client/operator guides remain in the sibling `tnl.dev` content
tree. Keep canonical terms, lowercase concrete prose, and failure-boundary rules.

The planning pass owns these two new plan documents. Root agent and contributor
guidance updates are an implementation step for the parent execution after paths
are real. Add focused nested `AGENTS.md` only where ownership needs local rules;
avoid copying the entire root instructions. Update repository discovery and
tooling references so the new layout is usable by both people and agents.

## implementation order

1. Finish the domain-boundaries PR, record its exact commit and coverage ledger,
   and create the stacked role-organization branch from it.
2. Inventory imports, source/generator/output ownership, embeds, fixtures, Task
   selectors, workflows, package exports, and external source consumers.
3. Move shared leaves first. Resolve dependency cycles at the owner and compile
   affected consumers with the smallest existing Task.
4. Move publisher and connector owners, including local/native contracts,
   lifecycle tests, TypeScript helpers, and installed-consumer fixture imports.
5. Move control APIs/state/workers, PostgreSQL and SQLite generator sources,
   daemon composition, and focused ingress leaves. Keep relay cohesive.
6. Move OpenAPI sources/fragments by serving role, update all generator mappings,
   and regenerate the seven canonical public packages in place.
7. Move SDK tests/tooling and update Python/action fixture references, Taskfile
   includes, scripts, deployment/dev paths, embeds, and coverage discovery.
8. Update maintainer/contributor/agent guidance from the implemented tree.
   Remove old internal paths after all consumers have moved.
9. Run generation/formatting and the efficient validation sequence below. Review
   the full diff against the first PR, including generated output and removed
   assertions; complete the ledgers and open the stacked PR.
10. After the first PR lands, update the second PR's base, review its complete
    resulting diff, and rerun checks justified by any resulting changes. Record
    both PR URLs and actual delivery status.

These are implementation phases within two PRs, not a request to stop after a
partial move or open a separate PR for every package.

## validation sequence and evidence

Run repository commands through `mise exec --` with pinned dependencies. Use a
focused existing Task during a move, then validate the final tree once. Avoid
repeating `go test ./...` or `go vet ./...` outside the Tasks that already run
them.

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task format-check
mise exec -- task go:test
mise exec -- task go:lint
mise exec -- task js:check
mise exec -- task py:check
mise exec -- task connect:check
mise exec -- task workflows:lint
mise exec -- task go:vulncheck
mise exec -- task go:test:race
mise exec -- task go:test:harness
mise exec -- task go:test:integration
mise exec -- task build
```

`go:test` runs `go test ./...` and the public Go consumer fixture through
`go:test:public-api`; `go:lint` runs `go vet ./...` plus staticcheck.
`js:check` builds once and reuses that build for typecheck/test `:run` scripts,
lint, formatting, and source npm packing. `py:check` includes Ruff, mypy, pytest,
and wheel-source/type-marker checks. `connect:check` checks the separate action.
Record an aggregate's existing execution instead of duplicating its component
checks on the same tree. Broaden or repeat only for a new change, a failure, or an
unresolved boundary.

Run `mise exec -- task generate-check` against the intended committed generated
tree. It regenerates files before comparing generated paths to `HEAD`, and is
not read-only. Intentional uncommitted moves/output changes can therefore report
drift. Keep this comparison separate from the claim that regeneration itself
succeeded. `format-check` is read-only. Use `connect:generate-check` for committed
action bundles when they change.

### integration, platform, and packaging proof

- Use Docker and Pebble with the existing disposable PostgreSQL harness. Each
  database-backed Task must create, use, and remove its own digest-pinned
  infrastructure. Preserve state/runtime shards and the separate real-clock
  lease/workload proofs; do not count ordinary `go:test` as their execution.
- Run Linux-only CLI, binary, app-workflow, and cross-team group tests in an
  isolated Linux environment with their declared trust, DNS/port, OpenSSH, and
  filesystem prerequisites. A macOS skip is a pending result, not a pass.
- Update and exercise publisher installation/Compose/DNS Tasks when their paths
  move. Preserve short native socket paths and shared host/container temporary
  mount paths in Linux runners.
- Run Chromium toolbar checks, supported framework matrices, Node/Bun and
  installed ESM/CommonJS consumers, Python native/ASGI fixtures, and action
  workflow checks for changed source/build/fixture paths. Keep Vercel's explicit
  Node 24 artifact prerequisite and kind/kubectl's opt-in cluster requirement.
- Run offline `deploy:publishers:check` for moved generation/deployment paths.
  Verify immutable storage checks and output ownership without cloud access.
- Preserve source-pack verification and, where release packer paths change,
  archive/native npm/platform wheel checks using local snapshot artifacts and
  installed consumers. Keep `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.txt`,
  executable modes, platform targets, and browser restrictions. Follow the
  release skill before any release/version/tag work.
- Keep large load/fault sweeps and deployed benchmarks opt-in. Record a boundary
  that needs separate qualification honestly; package moves do not establish
  live provider or production deployment behavior.

## move and progress ledger

All implementation rows are pending at plan authoring. The parent implementer
fills in actual source/destination changes, commits, checks, and any unresolved
scope. Existing code or an existing test name alone does not complete a row.

| ID  | Scope                                                              | Implementation evidence | Validation evidence | Status  |
| --- | ------------------------------------------------------------------ | ----------------------- | ------------------- | ------- |
| r01 | First PR complete and exact stacked base recorded                  | pending                 | pending             | pending |
| r02 | Import/dependency graph and source-path inventory                  | pending                 | pending             | pending |
| r03 | Publisher app/local/localapi/protocol/setup/invocation owners      | pending                 | pending             | pending |
| r04 | Publisher managed/group/runtime/identity/adhoc owners              | pending                 | pending             | pending |
| r05 | Publisher integrations/proxy/target/discovery/k8s owners           | pending                 | pending             | pending |
| r06 | Publisher inspection/toolbar/browserapi/deployment/provenance/demo | pending                 | pending             | pending |
| r07 | Connector root/stream/runtime/workload/kubeconfig split            | pending                 | pending             | pending |
| r08 | Control APIs/state/SQL/certificates/DNS/email/usage/catalog/proxy  | pending                 | pending             | pending |
| r09 | Focused ingress leaves and cohesive relay                          | pending                 | pending             | pending |
| r10 | Transport and daemon/config composition                            | pending                 | pending             | pending |
| r11 | Client-shared, policy, security, and retained focused leaves       | pending                 | pending             | pending |
| r12 | Serving-owned OpenAPI roots and domain fragments                   | pending                 | pending             | pending |
| r13 | Seven canonical `pkg/api/*` paths and public Go compatibility      | pending                 | pending             | pending |
| r14 | TypeScript internal/test roles and public exports                  | pending                 | pending             | pending |
| r15 | Flat Python binding and separate action consumers                  | pending                 | pending             | pending |
| r16 | Test/fixture moves and unique assertion preservation               | pending                 | pending             | pending |
| r17 | Complete source-generator-output/embed/drift inventory             | pending                 | pending             | pending |
| r18 | Task includes, script ownership, CI selectors, and testharness     | pending                 | pending             | pending |
| r19 | Deploy/development assets, Docker paths, and permissions           | pending                 | pending             | pending |
| r20 | Architecture, contributor, maintainer, and agent guidance          | pending                 | pending             | pending |
| r21 | Cycle resolution and removal of old internal facades/paths         | pending                 | pending             | pending |
| r22 | Routine, race, integration, platform, and package validation       | pending                 | pending             | pending |
| r23 | Full stacked diff reviewed and both PR URLs recorded               | pending                 | pending             | pending |

## coverage-preservation ledger

Expand each row into individual assertions when moving or consolidating tests.
The initial rows define required families; they are not claims that all tests
have been inventoried or run.

| Family                                                                                | Original assertion inventory | Destination/assertion and owning Task | Tested commit/platform/result | Status  |
| ------------------------------------------------------------------------------------- | ---------------------------- | ------------------------------------- | ----------------------------- | ------- |
| Public Go/HTTP/tunnel compatibility and golden bytes                                  | pending                      | pending                               | pending                       | pending |
| PostgreSQL/SQLite baseline, transactions, locks, and generated queries                | pending                      | pending                               | pending                       | pending |
| Company identity, setup/recovery, membership, and offboarding                         | pending                      | pending                               | pending                       | pending |
| Native scopes, enrollment, device stages, and canceled/late completion                | pending                      | pending                               | pending                       | pending |
| Local app/ad-hoc lifecycle, readiness accepted result, and once-per-run budget        | pending                      | pending                               | pending                       | pending |
| Group/runtime identity, durable certificates, deployment, and replacement             | pending                      | pending                               | pending                       | pending |
| Connector owner isolation, prepared reads, stream lifetime, and fixed workload expiry | pending                      | pending                               | pending                       | pending |
| Ingress routing, pending promotion, retry commitment, usage, and retirement           | pending                      | pending                               | pending                       | pending |
| Relay leases/claims, lost responses, exact assignments, capacity, and half-close      | pending                      | pending                               | pending                       | pending |
| Visitor subjects, managed HTTP credentials, target TLS/database/Kubernetes            | pending                      | pending                               | pending                       | pending |
| OAuth/aliases/webhooks, receiver selection, listener locks, and joined cleanup        | pending                      | pending                               | pending                       | pending |
| Feedback/source/evidence, browser validation, toolbar bundle, and CSP                 | pending                      | pending                               | pending                       | pending |
| Bounded subprocess buffers, typed-nil/CSR errors, parsers, and fuzz targets           | pending                      | pending                               | pending                       | pending |
| Telemetry vocabulary, safe failures, trace carriers, and benchmark aggregates         | pending                      | pending                               | pending                       | pending |
| SDK browser/Node/Bun/framework exports and installed native consumers                 | pending                      | pending                               | pending                       | pending |
| Python ASGI/fork/cleanup/wheel and action OIDC/workflow/cleanup                       | pending                      | pending                               | pending                       | pending |
| Linux CLI/binary/Compose/install/DNS, real lease cycles, and optional artifacts       | pending                      | pending                               | pending                       | pending |
| Task discovery/shards, generated drift, package legal files, and script callers       | pending                      | pending                               | pending                       | pending |

## completion and delivery record

| Deliverable                                                         | Evidence | Status  |
| ------------------------------------------------------------------- | -------- | ------- |
| Domain-boundaries implementation and first PR URL                   | pending  | pending |
| Exact first-PR base used for role organization                      | pending  | pending |
| Role-organization implementation and stacked PR URL                 | pending  | pending |
| Final generated-source/public compatibility review                  | pending  | pending |
| Unique assertions preserved and required checks passed              | pending  | pending |
| Base updated and final second-PR diff reviewed after first PR lands | pending  | pending |

Complete this plan only after the parent execution supplies both implementations,
their required validation, and confirmed PR URLs. Keep planned work, implemented
work, skipped checks, and remaining qualification visible as distinct evidence.
