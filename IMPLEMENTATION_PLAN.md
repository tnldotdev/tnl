# Team-First tnl Server Implementation Plan

This plan replaces identity-owned hostnames with team-owned domains and routes across the public `tnl` repository and the peer `../tnl.dev` hosted-service repository. The runtime topology, process coordination, data path, and implementation sequence in [Replicated Control, Ingress, And Relay Implementation Plan](https://md.cormo-turtle.ts.net/git/personal/tnl/QUIC.md) are authoritative.

The product and architecture model is:

- Every identity has a personal team.
- A team owns its domains and routes.
- A membership determines where an identity may publish.
- A route is durable; a route session is one running publisher attachment and owns one route version.
- Control owns the control API, durable PostgreSQL state, placement, certificates, administration, and coordination.
- Ingress accepts visitor connections, applies route policy, and forwards each connection to one connected relay.
- Relay processes maintain publisher connections without durable state.
- Each route session maintains two publisher connections assigned to distinct relay services.
- QUIC with TLS 1.3 is the primary transport; raw TLS/TCP with yamux is the fallback transport.
- Both transports implement identical `tunnelv1` control and visitor-stream semantics.
- Route TLS private keys remain with the publisher, and route TLS terminates in the publisher.
- Hosted and self-hosted deployments use the same CLI, policy, route, and tunnel semantics.
- Standalone composes control, ingress, and two logical relay services in one `tnld` process but requires PostgreSQL.
- Solo self-hosting requires neither OIDC nor DNS automation.

This is a destructive clean replacement. Build only the final schemas, contracts, configuration, and behavior. Existing server SQLite state, hosted authority data, client state, routes, hostnames, credentials, certificates, and live sessions need not survive. Do not add importers, compatibility endpoints, aliases, dual writes, mixed-version operation, feature flags, or fallback to replaced behavior. Do not add migration or breaking-change documentation.

## Repository Responsibilities

| Repository   | Responsibility                                                                                                                                                                               |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tnl`        | Canonical terminology, shared contracts, CLI, control, ingress, and relay roles, PostgreSQL state, placement, routes, certificates, DNS automation, `tunnelv1`, client state, and frameworks |
| `../tnl.dev` | Hosted authority API, hosted team and domain policy, invitations, beta entitlement policy, signed authorizations, and hosted application data                                                |

The public `tnl/api` sources are authoritative for shared wire contracts and conformance fixtures. The hosted repository generates its protocol types from the peer checkout. The Go control implementation is authoritative for PostgreSQL runtime state, DNS execution, certificate coordination, placement, and process coordination. The hosted TypeScript application does not mirror runtime route or certificate state.

## Canonical Terms

`AGENTS.md` is the only canonical runtime vocabulary. Use its terms and machine field names directly rather than maintaining a second terminology table here.

Product-specific terms retained by this plan include personal team, organization team, team role, member slug, invitation, default domain, team policy revision, DNS controller, DNS automation provider, certificate plan, certificate scope, certificate cache key, and worktree rendezvous.

## Engineering Rules

1. Implement the final model directly rather than wrapping obsolete types with new names.
2. Delete replaced tables, queries, endpoints, flags, adapters, transports, tests, dependencies, and documentation in the milestone that supersedes them.
3. Keep one PostgreSQL transaction or durable state machine responsible for each mutation.
4. Add an interface only for a real implementation boundary. Required boundaries are DNS automation providers, ACME challenge behavior, publisher-connection transports, and internal forwarding.
5. Keep provider-specific DNS values behind the DNS controller.
6. Keep transport-specific QUIC, TLS/TCP, and yamux details beneath `tunnelv1`.
7. Change OpenAPI, PostgreSQL SQL, client-state SQL, and Drizzle sources rather than generated output. `pkg/protocol/tunnelv1` is handwritten source, not generated output.
8. Keep hosted and self-hosted policy equivalent through shared conformance fixtures rather than duplicated prose or copied schemas.
9. Do not give ingress or relay processes PostgreSQL, Route 53, ACME account, authority, or server-administration credentials.
10. Make every route and publisher-connection decision safe across control replicas and stateless ingress or relay restarts.
11. Preserve the exact route version through placement, publisher connections, internal forwarding, `tunnelv1`, readiness, usage, and closure.
12. Do not add feature flags for behavior required from every final control, ingress, relay, standalone process, or publisher.

The five HTTP OpenAPI sources under `tnl/api` own their HTTP boundaries, handwritten `pkg/protocol/tunnelv1` alone owns tunnel semantics, `AGENTS.md` owns vocabulary, and `internal/naming` plus `@tnl/hosted-protocol` own language-specific hostname syntax checked against shared fixtures. `api/shared/v1/components.yaml` may hold byte-identical referenced schemas but generates no Go package. Each authority has one policy module. Route mutation, placement, DNS behavior, ACME issuance, publish option precedence, local certificate state, and each publisher-connection transport have one implementation path.

## Runtime Architecture

`QUIC.md` exclusively defines the control service, ingress service, relay services, publisher connections, internal forwarding, transports, standalone composition, scaling, draining, and failure behavior. Product behavior below assumes those runtime contracts and must not redefine them.

## Product Behavior

### Identity And Teams

First authentication creates or confirms, in one authority transaction:

- The authenticated identity.
- Its personal team.
- Its owner membership.
- One generated friendly DNS label used as both its managed-domain label and immutable member slug.
- The managed deployment domain as the team's default domain.

After login succeeds, the client stores the personal team as its selected team for that server origin. If a selected organization membership later disappears, the client falls back to the personal team and reports that change once.

A personal team is permanent, cannot have invitations, and cannot gain additional members. An organization team is created with:

```console
tnl team create resend --slug chase
```

The creator becomes its owner. The authority allocates a globally unique managed-domain label and reserves `chase` as the creator's immutable member slug.

For the current hosted beta, an entitled personal-team owner may create an organization team. The new team receives the same `early_waitlist_permanent` beta grant. This remains private `tnl.dev` policy.

### Roles And Memberships

| Team role | Permissions                                                                                                                                    |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `member`  | Read team metadata and publish only within their member namespaces                                                                             |
| `admin`   | Member permissions plus invitations, ordinary-member removal, domain management, shared routes, and administrative management of member routes |
| `owner`   | Admin permissions plus owner/admin management, domain release, and destructive team operations                                                 |

Enforce authority-state invariants transactionally. Runtime effects occur through the resulting team policy revision:

- Every team retains at least one owner.
- An admin cannot remove or demote an owner.
- Only an owner grants or removes owner status.
- Only an owner releases a claimed domain.
- Admins and owners cannot publish inside another member's namespace or obtain its namespace certificate.
- Removing a membership prevents new authorization and closes its route sessions through control.
- Removed member-scoped routes remain disabled until a team admin deletes them; shared routes remain team-owned.
- Membership, role, domain, and destructive policy changes advance the team policy revision.
- A server administrator is not implicitly a member of an organization team.

The built-in self-hosted identity is both server administrator and owner of its personal team. That personal team alone receives deployment-root route access.

Member slugs do not change while a membership is active. A future product requirement may add an explicit replacement workflow.

### Invitations And Slug Reservations

An invitation records its ID, team, reserved member slug, initial role, expiration, inviting identity, hashed one-time secret, optional normalized verified-email restriction, and lifecycle timestamps.

Only the secret hash is stored. An email-restricted invitation may be accepted only by an authenticated identity whose authority-verified normalized email matches.

Acceptance atomically consumes the invitation, activates its slug reservation, creates the membership, allocates a managed-domain label, and advances the team policy revision. Failed acceptance consumes nothing. Expired or revoked invitations release unused slug reservations immediately.

Removing a member changes the slug reservation to quarantined. It becomes reusable only after the latest reported certificate covering that slug's member namespaces has expired.

Invitation state has one source of truth:

| Deployment  | Authority                         |
| ----------- | --------------------------------- |
| Self-hosted | Control PostgreSQL                |
| Hosted      | `tnl.dev` authorization authority |

Ingress and relay processes do not store invitations or membership policy.

### Domains And Namespaces

The initial model has one managed deployment domain and any number of claimed domains.

| Domain type               | Ownership                                     | Example                          |
| ------------------------- | --------------------------------------------- | -------------------------------- |
| Managed deployment domain | Server-controlled and available to every team | `tnl.dev`, `tunnels.example.com` |
| Claimed domain            | Assigned exclusively to one team              | `dev.resend.com`                 |

Member namespaces are derived rather than stored:

```text
<membership.managed_label>.<managed-deployment-domain>
<membership.member_slug>.<claimed-domain>
```

For example:

```text
busy-toast.tnl.dev
chase.dev.resend.com
```

Adding a claimed domain does not create one namespace row per member. The authority derives namespace ownership from the domain and membership whenever it authorizes a route.

The hosted deployment root is reserved. Ordinary hosted teams cannot publish `api.tnl.dev`. The self-hosted bootstrap personal team may publish exact hosts directly beneath its managed deployment domain, such as `api.tunnels.example.com`. OIDC-created teams do not receive this exception.

A domain claim must not equal, contain, or be contained by another managed deployment domain or claimed domain controlled by the deployment.

The team's default domain affects only future implicit routes, `--subdomain` routes, automatically named `tnl dev` routes, and framework routes. Existing routes retain their complete hostnames.

The default domain cannot be released. A claimed domain cannot complete release while it has retained routes, live route sessions, ACME work, or an unexpired certificate reuse deadline.

### DNS Automation

The DNS controller runs in control and exposes idempotent service operations to bind provider state, create a delegated zone, return and verify NS records, manage exact route records, manage issuance-owned TXT values, and release a zone after its reuse deadlines expire.

Route 53 is the only initial provider and is implemented once in Go. Hosted `tnl.dev` calls the service-authenticated DNS controller on control rather than implementing a Route 53 client in TypeScript or calling ingress or a relay.

The managed deployment domain uses an operator-configured existing Route 53 hosted zone when DNS automation is enabled. This configured deployment zone is not arbitrary zone adoption. Control may manage only explicitly owned route and ACME records within it.

For each claimed domain, the provider creates and tags a dedicated hosted zone, returns the required NS delegation, verifies NS and SOA authoritatively, and creates exact route records that target the ingress address. It preserves concurrent TXT values, deletes only state owned by the corresponding route or ACME authorization, and retains the zone until route state and certificate reuse deadlines permit release.

The first implementation does not adopt an existing hosted zone for a claimed domain and does not manage CAA records.

Without a configured provider, arbitrary domain claims fail. The managed deployment domain remains usable through operator-provisioned static control and wildcard DNS. Provider-free self-hosting uses exact TLS-ALPN-01 certificates.

Only control has DNS credentials. Certificate code invokes the DNS controller and never receives a Route 53 client. Ingress, relays, and publishers have no DNS credentials.

In hosted deployments, the authority stores domain policy and an opaque DNS authority reference. Control stores only the provider execution state needed to resolve that reference. This is DNS execution state, not a mirror of domain policy.

Public route DNS targets the ingress address. Relay placement changes do not require DNS changes.

### Hostname Input

| Input                       | Meaning                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| No hostname option          | The current membership's namespace under the team's default domain |
| `--subdomain api`           | One canonical DNS label beneath that member namespace              |
| `--host api.dev.resend.com` | One exact canonical complete hostname                              |

The same meanings apply to `TNL_HOST`, `TNL_SUBDOMAIN`, and framework `host` and `subdomain` options.

Rules:

- `--host` and `--subdomain` are mutually exclusive.
- CLI values override framework configuration.
- `--subdomain` accepts exactly one canonical DNS label.
- `--host` accepts one canonical hostname without a trailing dot.
- A member route is limited to its namespace or one label beneath it.
- A deeper exact member hostname is rejected rather than silently changing certificate policy.
- A shared exact route may be at a claimed-domain apex or elsewhere under it, but never inside another member's namespace.
- A complete `--host` remains pinned when selected-team or default-domain state changes.
- The authority API validates hostname policy even when the client already resolved the hostname.

There is no `TNLD_BOOTSTRAP_MEMBER_SLUG`. A generated namespace is the fallback. A solo operator chooses a preferred route with `--host`, `TNL_HOST`, or framework `host`.

### Durable Routes And Route Sessions

A route is the durable team-owned mapping for one complete hostname. A route session is one publisher attachment, owns one route version, and maintains two publisher connections assigned to distinct relay services.

Publisher startup:

1. Loads the selected membership.
2. Resolves the complete hostname.
3. Obtains local or signed team authorization.
4. Creates or resumes the durable route through control.
5. Creates a route session and receives its two connection assignments, publisher connection credentials, and certificate plan.
6. Provisions exact route DNS when required.
7. Establishes each publisher connection with QUIC or falls back to TLS/TCP with yamux.
8. Waits for both publisher connections to become ready.
9. Installs or reuses the authorized certificate.
10. Completes the publisher ready transition through control.

Only one unexpired route session may exist for a route. A competing publisher fails immediately:

```text
tnl: api.dev.resend.com is already being published
```

An idempotent retry of the original route-session request returns the same committed route session, route version, connection assignments, publisher connection credentials, and certificate plan. Remove list-and-guess recovery and route takeover.

Route credentials and `routeAuth` are removed. The authenticated identity or signed team authorization controls durable route operations. Route-session tokens authenticate readiness, heartbeat, certificate operations, and session closure. Publisher connection credentials authorize one assigned publisher connection. Service mTLS authenticates ingress and relay operations.

A relay reports publisher-connection loss to control. Control removes that connected relay from the ingress routing table and supplies a current or replacement connection assignment. The publisher reconnects without changing the route session or route version. Zero ready publisher connections temporarily makes the route version unroutable.

Publisher shutdown closes the route session through control and drains its publisher connections. It does not delete the route, DNS policy, certificate material, or renewal state.

Explicit deletion is:

```console
tnl route list
tnl route delete <hostname-or-route-id>
```

A member may delete their member-scoped routes. An admin or owner may delete any team route. Deletion closes an attached route session in PostgreSQL, tells connected relays to reject and drain its publisher connections, removes exact public route DNS when managed by control, deletes the durable route, and rejects stale retries by route version and connection assignment revision.

### Ingress And Internal Forwarding

Visitor connections arrive over TCP at the ingress address. Ingress inspects SNI without terminating route TLS, enforces current source and route limits, resolves the exact routable route version, selects a connected relay from its ingress routing table, and forwards the visitor connection once over service mTLS.

Ingress creates the canonical PROXY v2 metadata from trusted outer connection information. The selected relay validates the current publisher connection, then preserves the metadata and route TLS bytes unchanged on one `tunnelv1` visitor stream. The publisher terminates route TLS and forwards plain HTTP to the local service.

Ingress aggregates bounded per-connection usage and reports route ID, route version, team attribution, timestamps, counters, and histograms to control. An ingress restart may lose only unreported in-memory telemetry, never route or authorization state. Relay attempts do not multiply usage.

### Certificates And ACME

Route TLS continues through ingress, one relay, and the publisher connection before terminating in the publisher. Ingress and relays never receive route TLS private keys.

| Route type                                               | Certificate identifiers      | Challenge method |
| -------------------------------------------------------- | ---------------------------- | ---------------- |
| Managed member namespace with DNS automation             | Namespace apex plus wildcard | DNS-01           |
| Claimed-domain member namespace                          | Namespace apex plus wildcard | DNS-01           |
| Shared route                                             | Exact route hostname         | DNS-01           |
| Managed route without DNS automation                     | Exact route hostname         | TLS-ALPN-01      |
| Self-hosted deployment-root route without DNS automation | Exact route hostname         | TLS-ALPN-01      |

No membership receives a domain-wide wildcard such as `*.dev.resend.com`.

A certificate plan contains only a certificate cache key, certificate scope, canonical DNS identifier set, and challenge method.

The authority API derives the plan from team, domain, membership, and route policy. The authenticated route session binds it to the route and route version; it is not a separate durable product resource.

The publisher sends a P-256 CSR whose DNS SAN set exactly matches the plan after canonical sorting. Reject missing, extra, duplicate, non-DNS, or malformed identifiers, but do not reject a semantically identical SAN order.

Private keys remain installation-local. Certificate cache identity is:

```text
server origin + certificate cache key
```

Routes under one member namespace reuse its namespace certificate on one installation. Shared exact routes and provider-free exact routes use separate certificate scopes.

Replace route-certificate client state and `RouteCertificateHandle` with certificate-scope state and locks. Secret-protection context uses the certificate cache key rather than a route ID.

Use one PostgreSQL-backed durable ACME state machine in control. Persist an ACME order and one authorization record per identifier. Each authorization record holds its selected challenge, presentation ownership, status, retry time, and cleanup state.

DNS-01 processing authenticates the route session, validates the CSR, creates one order for all identifiers, and persists every authorization before DNS mutation. It presents owned TXT values without replacing concurrent values, checks authoritative propagation, accepts each challenge, finalizes with the publisher CSR, validates the chain, records installation acknowledgement and `not_after`, and cleans up only its own TXT values.

Control reconciliation resumes nonterminal presentation, validation, finalization, acknowledgement, and cleanup across process restarts and control replicas. Cleanup remains safe after route-session closure or policy revocation. PostgreSQL work revisions and lease checks ensure one reconciler owns each side effect at a time.

Exact TLS-ALPN-01 uses the same order, CSR, validation, finalization, and acknowledgement flow. Its challenge behavior coordinates the publisher challenge certificate and routes the validation probe through ingress, a connected relay, and the authenticated publisher connection.

The initial implementation uses renewal jitter and persists CA `Retry-After` values. Persisted issuance budgets and ACME Renewal Information are follow-up work, not part of this replacement. Hosted rollout still requires explicit CA-capacity planning because code cannot remove registered-domain limits.

Before a certificate makes a route routable, control records its `not_after`. For hosted policy, control reports only the maximum validity needed to update the relevant member-slug and domain reuse deadlines.

Control automatically obtains and renews the public control-hostname certificate through ACME. It also transactionally initializes a durable private service CA in PostgreSQL. Split ingress and relay processes generate their service private keys locally and enroll through the public control HTTPS endpoint with reusable, revocable, role-scoped enrollment tokens. Control issues one-hour service certificates, and processes re-enroll after approximately thirty minutes using the same token.

Relay transport TLS is private PKI rather than WebPKI. Control uses the service CA to issue a one-hour server certificate for each relay service's derived public hostname and stores the shared relay-service certificate/key as durable control state. Relay enrollment returns that material only to processes presenting the unrevoked token scoped to the relay service. Authenticated route-session setup gives publishers the service CA certificate for a relay-only TLS trust configuration. Service mTLS, relay transport TLS, and route TLS remain separate certificate profiles and uses.

### Hosted Authorization And Revocation

There is one policy authority, one durable runtime owner, and one stateless data plane:

| Responsibility                                | Self-hosted          | Hosted               |
| --------------------------------------------- | -------------------- | -------------------- |
| Identity, team, invitation, and domain policy | Control PostgreSQL   | `tnl.dev` PostgreSQL |
| Route and route-session state                 | Control PostgreSQL   | Control PostgreSQL   |
| Placement, ingress leases, and relay leases   | Control PostgreSQL   | Control PostgreSQL   |
| DNS and certificate coordination              | Control PostgreSQL   | Control PostgreSQL   |
| Visitor handling and publisher connections    | Ingress/relay memory | Ingress/relay memory |
| Browser TLS private keys                      | Publisher            | Publisher            |
| Selected team                                 | Client state         | Client state         |

The hosted authority does not mirror route registration, placement, attachment, or deletion state. Route listing and deletion always use the control API. The authority receives only certificate-validity facts required for safe slug and domain reuse.

Signed authorizations reuse the signed envelope and bind at least:

```text
operation
team ID
identity ID
membership ID and role
team policy revision
domain ID
route hostname and scope
certificate plan
request and retry identity
issuer, receiver, issued time, and expiry
```

Team policy revocation is team-wide:

1. The authority advances `teams.policy_revision` in the policy-change transaction.
2. The hosted transactional outbox records the revision event.
3. The dispatcher pushes the monotonic revision to control and retries idempotently.
4. Control persists the revision floor in shared PostgreSQL before acknowledging it.
5. Every control replica rejects older signed authorizations from the shared floor.
6. Revision application transactionally closes older route sessions for that team and records publisher-connection removal work.
7. Connected relays reject or drain affected publisher connections using the resulting route version and connection assignment revisions.
8. Control startup synchronization restores revision floors before any replica accepts signed route mutations.

This deliberately favors monotonic policy revisions over fine-grained revocation. Unaffected publishers may obtain current authorization and open new route sessions.

### Solo And Multi-User Self-Hosting

Solo setup requires a server domain, an independent managed deployment domain, PostgreSQL, persistent PostgreSQL backups, an ACME email with accepted terms, public TCP and UDP, public DNS, and a bootstrap management token. It does not require certificate files, static service-mTLS configuration, OIDC, DNS automation, or separate ingress and relay processes. From `TNLD_SERVER_DOMAIN=tnl.example.com`, standalone derives `control.tnl.example.com`, `ingress.tnl.example.com`, and the physical relay address `relay.tnl.example.com`.

Login-token authentication resolves to the built-in identity and personal team. Daily use is:

```console
tnl publish 3000
# busy-toast.tunnels.example.com

tnl publish 3000 --host api.tunnels.example.com
# api.tunnels.example.com
```

Multi-user self-hosting uses OIDC so each issuer/subject pair becomes a distinct identity and personal team. Retain normalized email only when the provider marks it verified. Verified email is required only for an email-restricted invitation.

Sharing the bootstrap login token is not a multi-user mechanism because every holder is the same built-in identity.

### Development Workflow

`tnl dev` derives a stable one-label hostname from canonical project and worktree identity, for example:

```text
dashboard-main-a31f92.chase.dev.resend.com
dashboard-login-f82c10.chase.dev.resend.com
```

Define one derivation specification and shared Go and TypeScript vectors. The suffix prevents collisions and remains stable for the same canonical worktree root.

Support four modes:

| Command                           | Behavior                                                                    |
| --------------------------------- | --------------------------------------------------------------------------- |
| `tnl dev`                         | Wait for a framework integration started separately in the current worktree |
| `tnl dev --port 3000`             | Attach to a fixed loopback port without owning a child                      |
| `tnl dev -- pnpm dev`             | Start and supervise a child and wait for framework registration             |
| `tnl dev --port 3000 -- pnpm dev` | Start and supervise a child with a fixed target port                        |

Model optional child supervision and fixed or framework-discovered target as independent choices.

The worktree rendezvous uses one deterministic socket and one exclusive lock beneath a `0700` user-owned runtime directory. A supervised child receives the socket path through inherited `TNL_DEV_*` configuration. A separately launched framework integration derives the same socket path. Unix socket and directory permissions provide the local security boundary; do not add a manifest or bearer token.

A second `tnl dev` in the same worktree fails immediately. A supervised child receives graceful termination and then forced termination after the existing deadline. Separately launched framework processes remain running when the CLI exits.

Supported flags are `--port`, `--open`, `--startup-timeout`, `--server`, `--access-token`, `--state-dir`, `--host`, `--subdomain`, `--allow-ip`, and `--public`. `--output=ndjson` remains unsupported for `tnl dev`.

## CLI Surface

- Teams: `tnl team current`, `tnl team list`, `tnl team use`, `tnl team create`, and `tnl team members`.
- Invitations: `tnl team invite create`, `tnl team invite list`, `tnl team invite revoke`, and `tnl team join`.
- Memberships: `tnl team member set-role` and `tnl team member remove`.
- Domains: `tnl domain claim`, `tnl domain default`, `tnl domain list`, and `tnl domain release`.
- Routes: `tnl route list` and `tnl route delete`.
- Publishing: `tnl publish <port>`, with optional `--subdomain` or `--host`.
- Service enrollment: `tnl admin enrollment-tokens create`, `tnl admin enrollment-tokens list`, and `tnl admin enrollment-tokens revoke`.

API resources use stable IDs. CLI commands accept a team ID or an unambiguous team display name among the identity's memberships. Ambiguous names report the matching IDs.

`tnl domain claim --default` commits the default change only after domain authority and DNS readiness checks succeed.

Remove `tnl host`, its API endpoints, adapters, tests, and documentation when this surface replaces it.

## Minimal State Model

### Control PostgreSQL

The final control PostgreSQL schema contains only the state required by the final model:

| State                        | Purpose                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| `identities`                 | Self-hosted authorization principals and verified identity metadata                                   |
| `teams`                      | Self-hosted personal or organization kind, default domain, lifecycle, and policy revision             |
| `team_memberships`           | Self-hosted role, slug-reservation reference, generated managed label, and lifecycle                  |
| `member_slug_reservations`   | Self-hosted invited, active, or quarantined team-local slugs and reuse times                          |
| `team_invitations`           | Self-hosted hashed expiring invitation secrets and restrictions                                       |
| `domains`                    | Self-hosted managed or claimed domain policy, provider reference, progress, and reuse time            |
| `control_sessions`           | Revocable user control sessions                                                                       |
| service CA state             | Durable private CA certificate and key initialized transactionally                                    |
| service enrollment tokens    | Reusable role-scoped token lookup IDs, digests, audit metadata, and revocation                        |
| relay transport certificates | One-hour shared relay-service certificate and key material                                            |
| `routes`                     | Durable team-owned hostname, scope, policy, DNS state, and lifecycle                                  |
| `route_sessions`             | Publisher attachment lifecycle, route versions, readiness, and expiry                                 |
| relay-service state          | Stable relay service identities, relay addresses, and availability                                    |
| publisher-connection state   | Two connection slots, assignments, credentials, connected relays, state, and revisions                |
| `relay_leases`               | Relay service, relay identity, process run, internal address, capacity, drain state, and expiry       |
| `ingress_leases`             | Ingress identity, process run, routing-table revision, load, drain state, and expiry                  |
| `dns_authorities`            | Provider execution state behind an authority-issued opaque reference                                  |
| `authority_revision_floors`  | Latest accepted hosted authority revision per team                                                    |
| `acme_accounts`              | Durable CA account and directory state                                                                |
| `acme_orders`                | Durable certificate plan snapshot, CSR, status, retry, finalization, and acknowledgement state        |
| `acme_authorizations`        | Per-identifier challenge, presentation ownership, retry, validation, and cleanup state                |
| route usage state            | Route-version usage aggregation and reliable hosted reports with team and acting-identity attribution |
| administrative audit state   | Server administration and maintenance-control attribution                                             |

Retain no separate namespace, team-domain join, domain-operation, certificate-plan, certificate-replacement, or hosted route-shadow table. The route session owns its two connection slots and their durable assignment lifecycle. Live publisher connections remain in relay memory.

For self-hosting, authority rows and runtime rows share control PostgreSQL. For hosted deployments, authority policy lives only in `tnl.dev` PostgreSQL while runtime rows live only in control PostgreSQL.

The managed deployment domain is one authority-owned domain row available to every team. Claimed domains carry a `team_id`. A team's `default_domain_id` points to either the managed domain or one of its claimed domains.

Domain claim and release progress belongs on the domain row. Exact route DNS progress belongs on the route row. Certificate plans are derived and snapshotted by the ACME order when issuance begins.

Create a new final PostgreSQL baseline. Do not import or translate server SQLite state.

### Hosted Authority PostgreSQL

Replace hosted personal-team, hostname, domain-verification, authorization, route-shadow, and associated projection schemas with the final identity, team, membership, slug-reservation, invitation, domain, entitlement, outbox, and certificate-validity model.

Keep billing, email, recovery, waitlist, and beta entitlement behavior private to `tnl.dev`, but initialize them in the new final schema. Reuse the transactional outbox for revision pushes. Do not add hosted route, route-session, relay placement, ACME, certificate, or DNS-provider execution state.

Create a new final Drizzle baseline and reset hosted data. Do not backfill existing users, personal teams, grants, hostnames, routes, or authorizations.

### Client State

Client state needs only:

| State                           | Purpose                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------- |
| Selected team per server origin | Stable CLI context                                                              |
| Certificate scopes              | Local pending and current key/certificate state keyed by origin and cache key   |
| Certificate-scope locks         | Cross-process issuance serialization                                            |
| Hostname locks                  | Immediate local duplicate-publisher rejection                                   |
| Local tunnels                   | Existing process status with team, route, route version, and transport metadata |

Create a new final client-state baseline. Existing client state need not open or migrate. The server remains authoritative. Worktree rendezvous files are ephemeral runtime state, not database records.

### Ingress And Relay State

Ingress and relay processes have no database schema, state directory, durable volume, backup process, or migration lifecycle. Each process starts empty and becomes ready only after control confirms its service identity, process run ID, lease revision, and protocol version. Only ingress receives the ingress routing table.

## API And Protocol Boundaries

### Authorization Authority

The authority API is the sole HTTP owner of identities, authentication, teams, memberships, invitations, domains, and signed authorizations. The self-hosted authority and hosted `tnl.dev` authority expose equivalent authenticated behavior for:

```text
create and list teams
read memberships
create, list, revoke, and accept invitations
list members
change roles and remove members
list, claim, default, and release domains
```

Self-hosted control implements the authority and control APIs at the same origin. Hosted control discovery advertises the external authority origin. The authority has no separate capabilities endpoint.

Use `api/shared/v1/components.yaml` only for byte-identical cross-contract schemas such as identifiers, problem details, certificate plans, and signed authorization structures. Each OpenAPI generation target emits its own Go models; there is no shared generated Go model package. Share policy and naming fixtures between Go and TypeScript.

### Control API

The control API owns:

```text
deployment discovery, route operations, and server administration
durable route creation, listing, lookup, and deletion
route-session creation, relay-service placement, heartbeat, and closure
publisher readiness
certificate issuance and installation acknowledgement
DNS controller service operations
hosted policy-revision application and startup synchronization
hosted certificate-validity reporting
relay-service and relay-process administration and placement visibility
service-enrollment token administration and public service enrollment
```

Route-session setup returns two connection assignments for distinct relay services. Each assignment includes the connection slot, publisher connection ID, connection assignment revision, relay service ID, relay address, TLS server name, expiry, and publisher connection credential. QUIC and TLS/TCP with yamux are required transports rather than optional capabilities.

The one public control discovery response always includes the authority endpoint and authentication facts. Keep hosted service, ingress service, relay service, user, administrator, route-session, and enrollment-token authentication distinct.

The control HTTP contract also owns:

```text
POST /v1/admin/service-enrollment-tokens
GET /v1/admin/service-enrollment-tokens
DELETE /v1/admin/service-enrollment-tokens/{id}
POST /v1/service-enrollments
```

The administrative endpoints create, list, and revoke reusable tokens. The raw `tnl_enrollment_...` value is returned exactly once. Enrollment accepts a token, role, process identity, and CSR over public control HTTPS and returns a one-hour service certificate, service CA trust bundle, the role's internal API endpoint, and stable role facts. Relay enrollment also returns relay-service identity, derived relay address, TLS server name, and current shared relay transport certificate/key.

### Ingress Service API

The private ingress/control contract owns ingress registration, lease renewal, draining, ingress routing-table snapshots and events, usage reports, and recovery observations. Every request binds the ingress ID, ingress process run ID, and ingress lease revision.

### Relay Service API

The private relay/control contract owns relay-process registration, lease renewal, capacity, draining, publisher-connection claims, and connection-state reports. Every request binds the relay service ID, relay ID, relay process run ID, and relay lease revision. Connection operations also bind the route session, route version, publisher connection ID, connection slot, and connection assignment revision.

The ingress and relay APIs use separate listeners, handlers, server certificate profiles, permissions, and generated clients. They use the control hostname on fixed TCP ports 9443 and 9444 respectively. Requests are idempotent, stale identity or revision checks fail closed, and neither ingress nor relay is authoritative for a durable mutation.

### Internal Forwarding

Internal forwarding is an ingress-to-relay service protocol. Each request binds the ingress identity, concrete connected relay, route session, route version, publisher connection, connection assignment revision, visitor connection ID, and expiration bounds. Relay accepts only a current local publisher connection and never forwards to another relay.

The internal transport must provide bounded buffering, cancellation, half-close, service mTLS, and the same retry-boundary behavior regardless of the selected connected relay. Usage remains at ingress.

### `tunnelv1`

The `tunnelv1` contract owns:

```text
publisher-connection authentication
connection acknowledgement
publisher connection drain notifications
one bidirectional stream per visitor connection
PROXY v2 metadata and route TLS payload ordering
stream cancellation and half-close behavior
protocol errors and close reasons
```

`pkg/protocol/tunnelv1` is handwritten and is the only source of truth. Define golden JSON and framed-wire fixtures, invalid-message fixtures, unknown-field, missing-field, bounds, truncated-frame, and decoder fuzz coverage. Run shared behavior tests unchanged against QUIC and TLS/TCP with yamux. Remove standalone tunnel JSON Schemas, schema synchronization, parity tests, and old worker and transport schemas rather than adapting them.

### HTTP OpenAPI Layout

Keep exactly these five HTTP OpenAPI sources and generated packages:

| Source                            | Generated package      |
| --------------------------------- | ---------------------- |
| `api/control/v1/openapi.yaml`     | `pkg/api/controlv1`    |
| `api/authority/v1/openapi.yaml`   | `pkg/api/authorityv1`  |
| `api/ingress/v1/openapi.yaml`     | `pkg/api/ingressv1`    |
| `api/relay/v1/openapi.yaml`       | `pkg/api/relayv1`      |
| `api/route-usage/v1/openapi.yaml` | `pkg/api/routeusagev1` |

Generate models, clients, and strict server interfaces for each. Generated server adapters own route registration and request decoding; handwritten handlers retain authorization, semantic validation, and state transitions. Do not merge ingress and relay contracts or listeners.

### Deployment Facts

The server advertises only facts that vary by deployment:

```text
managed deployment domain
DNS automation availability
authority endpoint
authentication methods and authority-specific login facts
```

Do not advertise team, invitation, route, certificate, QUIC, TLS/TCP, ingress, or relay behavior as optional capabilities.

### Problem Codes

Use standard HTTP problem details. Add stable codes only where a client needs distinct behavior:

```text
name_unavailable
route_attached
policy_revision_stale
dns_setup_pending
placement_unavailable
issuance_retry
```

`dns_setup_pending`, `placement_unavailable`, and `issuance_retry` include `retry_at` when known. Transport fallback is local publisher behavior and does not require a control API problem code.

## Implementation Milestones

Each milestone includes focused tests, generated output, and deletion of the path it replaces. Intermediate commits may be implementation scaffolding on the working branch, but no compatibility surface is part of the completed milestone.

### 1. Terminology, Contracts, And Final Schemas

- Update `AGENTS.md` for control, ingress, relay services, publisher connections, internal forwarding, and `tunnelv1`.
- Remove canonical edge, worker, backend, Tailcat, DERP, and server-SQLite terminology.
- Define final team, invitation, domain, route, route-session, certificate-plan, ingress-service, relay-service, revision-push, certificate-validity, and problem contracts.
- Make handwritten `tunnelv1` the only tunnel contract and define golden and invalid wire fixtures for QUIC, TLS/TCP with yamux, and internal forwarding.
- Version signed authorization claims for team and certificate-plan bindings.
- Add shared policy, naming, and transport fixtures used by Go and TypeScript.
- Add the final control PostgreSQL baseline, hosted Drizzle baseline, and client-state baseline.
- Regenerate outputs.
- Split authority ownership from control, establish the five HTTP OpenAPI sources under `pkg/api/*`, and generate strict server interfaces.
- Remove legacy hostname, temporary-name, gateway, worker, Tailcat descriptor, relay-map, and tunnel schema contracts.

### 2. Control, Ingress, Relay, And Publisher Connections

- Replace `tnld` modes with control, ingress, relay, and standalone.
- Replace legacy flags with the minimal mode configuration. Derive role hostnames from `TNLD_SERVER_DOMAIN`; use hostname-only `TNLD_CONTROL_HOSTNAME` for split processes.
- Require `TNLD_LOGIN_TOKEN` for control and standalone and obtain public control TLS automatically through ACME.
- Add durable service CA initialization, reusable scoped enrollment tokens, service enrollment and renewal, and private relay transport PKI.
- Implement PostgreSQL connection, migration, readiness, transaction, retention, and backup integration for control.
- Implement replicated-control-safe route coordination without process-local authority.
- Implement ingress and relay registration, leases, capacity, draining, and placement.
- Implement the versioned ingress routing table from control to ingress.
- Implement publisher-initiated QUIC with TLS 1.3.
- Implement raw TLS/TCP with yamux fallback using identical `tunnelv1` semantics.
- Implement publisher-connection claims, loss reporting, replacement, draining, and closure.
- Implement authenticated internal forwarding from ingress to a connected relay.
- Preserve SNI passthrough, PROXY v2 metadata, limits, and usage accounting.
- Make standalone compose the same control, ingress, and logical relay-service implementations against PostgreSQL.
- Remove server SQLite, state-directory locks, SQLite backup, edge and worker modes, worker coordination, Tailcat, DERP, Tailscale dependencies, and split edge/worker deployment files.

### 3. Teams, Memberships, And Selection

- Implement final hosted and self-hosted authority schemas directly without data backfill.
- Make first authentication create personal-team resources atomically.
- Reuse one generated friendly label as a personal membership's managed label and member slug.
- Persist selected team per server origin.
- Add organization-team creation, invitations, joining, role changes, removal, slug reservations, and owner protection.
- Preserve verified OIDC email only when asserted by the provider.
- Apply hosted beta grants through copy-on-team-create policy for newly created state.
- Add the `tnl team` CLI without mutable member slugs.

### 4. Domains And DNS

- Add the managed deployment domain and team-owned claimed domains.
- Derive member namespaces from membership and domain state.
- Add default-domain changes and certificate-backed slug/domain reuse times.
- Implement the control DNS controller and configured managed Route 53 zone.
- Implement dedicated Route 53 delegated zones for claimed domains.
- Point managed route records at the ingress address.
- Add domain claim, delegation verification, release, and the `tnl domain` CLI.
- Remove identity-owned hostname claims and old domain-verification services.

### 5. Durable Team Routes, Placement, And Revocation

- Resolve implicit, one-label subdomain, and exact hosts from selected-team state.
- Refactor local and signed creation into one authorized PostgreSQL route mutation.
- Remove route credentials, takeover, automatic deletion, and list-and-guess recovery.
- Add explicit route-session closure, route listing, and route deletion.
- Bind each route session and route version to two publisher connections assigned to distinct relay services.
- Return deterministic idempotent session setup including both connection assignments and the certificate plan.
- Add hosted revision outbox events, shared control revision floors, startup synchronization, and immediate stale-route-session rejection.
- Deliver publisher-connection closure to relays and reject stale route versions or assignments at ingress and connection establishment.
- Remove `tnl host`, temporary allocations, and old publisher hostname resolution.

### 6. Certificate Scopes And ACME

- Derive and authorize the four-field certificate plan.
- Replace route-scoped client state with certificate-scope state and locks.
- Implement the ACME service as one PostgreSQL-backed multi-identifier order flow with per-authorization DNS-01 or TLS-ALPN-01 behavior.
- Add replica-safe ownership and restart-safe TXT presentation, propagation, validation, cleanup, finalization, acknowledgement, and `Retry-After` handling.
- Route TLS-ALPN-01 probes through ingress and a connected relay.
- Coordinate control, ingress, and relay service certificates separately from publisher-held route certificates.
- Report certificate `not_after` from control for hosted slug/domain reuse deadlines.
- Remove route-scoped certificate tables, handles, and issuance paths.

### 7. `tnl dev` And Frameworks

- Refactor child supervision and target discovery into independent choices.
- Add deterministic per-worktree socket discovery and locking.
- Add stable project/worktree hostname derivation.
- Add framework `subdomain` and exact option-precedence parity.
- Keep child processes isolated from control and route-session credentials.
- Exercise both publisher-connection transports through the same framework behavior.
- Update Next.js, Vite, and private protocol tests.

### 8. Operations, Documentation, And Final Cleanup

- Add least-privilege Route 53, hosted authority/control synchronization, enrollment, ingress, relay, internal-forwarding, and certificate-validity credentials.
- Add PostgreSQL provisioning, connection security, migrations, pooling, backups, restore, and replicated-control operating procedures.
- Keep ingress and relay process configuration to control hostname, enrollment token, process identity, and the relay's internal address. Derive or enroll all other stable facts and apply defaults for listeners, capacity, timing, and metrics.
- Add hosted CA-capacity planning and rollout limits without a new application budget subsystem.
- Replace standalone and split Compose with PostgreSQL-backed standalone and control, ingress, and relay deployments.
- Update local and integration fixtures for PostgreSQL, QUIC, TLS/yamux fallback, and internal forwarding.
- Update public CLI, self-hosting, hosted deployment, DNS, security, backup, recovery, observability, and architecture documentation for only the final system.
- Do not add migration guides, compatibility notes, or breaking-change documentation.
- Remove all remaining obsolete terms, old deployment manifests, identity-owned assumptions, server SQLite code, and legacy transport dependencies.

## Verification

Focused coverage must prove:

- A fresh control PostgreSQL database creates the complete final schema and bootstrap state.
- A fresh hosted database creates the complete final authority state without backfill paths.
- Concurrent replicated controls preserve route, session, policy-revision, ACME, DNS, audit, and idempotency invariants.
- Control restart and replica loss do not invalidate committed routes, sessions, placement, or reconciliation work.
- Ingress and relay registration, lease renewal, expiry, capacity, draining, and protocol-version rejection work transactionally.
- An ingress or relay restart requires no local recovery and cannot resurrect stale state.
- Placement excludes relay services without sufficient healthy, compatible, non-draining capacity.
- Each route session receives exactly two connection assignments for distinct relay services.
- Multiple relay processes in one service claim assignments atomically, and only the winning process becomes the connected relay.
- Internal forwarding is service authenticated, checked against the current route version and connection assignment, and always terminates on a local publisher connection.
- QUIC and TLS/TCP with yamux pass the same `tunnelv1` conformance vectors.
- The publisher attempts QUIC first and uses TLS/TCP with yamux when UDP is blocked or times out.
- Publisher-connection loss preserves the route session and route version while the publisher reconnects.
- PROXY v2 metadata, the replayed ClientHello, route TLS, half-close, cancellation, and byte ordering survive internal forwarding.
- Route TLS always terminates in the publisher and plain HTTP reaches the local service.
- Standalone uses PostgreSQL and the same ingress lease, relay lease, placement, transports, and readiness behavior as split deployment.
- No ingress or relay process can access PostgreSQL, Route 53, ACME account, authority, or administrator credentials.
- One reusable ingress token and one token per relay service enroll arbitrary replica counts; token digests, scoping, revocation, and exact-once raw-token return are enforced.
- Service certificate renewal succeeds around thirty minutes; expiration removes readiness and prevents lease renewal.
- Cross-role, cross-service, and revoked-token enrollment fail closed.
- Standalone starts with its seven required settings and no certificate files; control obtains and renews its public certificate through ACME.
- Self-hosted and hosted clients use the same authority contract and one control discovery response.
- Exactly five HTTP OpenAPI sources remain, all generating `pkg/api/*` strict server interfaces.
- No tunnel JSON Schemas, `pkg/protocol/serverv1`, gateway API, gateway generated package, legacy gateway configuration, or static service-mTLS configuration remains.
- Atomic personal-team bootstrap and concurrent first login.
- Organization-team creation, hosted beta grant copying, and selected-team fallback.
- Role enforcement, last-owner protection, invitation secrecy, verified-email restrictions, and slug reservation lifecycle.
- Derived namespaces, domain overlap rejection, default changes, managed-zone operation, claimed-zone delegation, and safe release.
- Hosted deployment-root rejection and self-hosted bootstrap-root access.
- Implicit, subdomain, and exact host resolution with member/shared isolation.
- Durable route reuse, attached-route contention, idempotent retries, session closure, and explicit deletion.
- Hosted revision push, replay rejection, control restart synchronization, and publisher-connection eviction.
- Certificate-plan tamper resistance and order-independent exact CSR SAN validation.
- Namespace cache reuse, exact shared/provider-free certificates, multi-value TXT preservation, and restart-safe ACME cleanup.
- TLS-ALPN-01 validation through ingress and a connected relay.
- Certificate-validity reporting and slug/domain reuse deadlines.
- All four `tnl dev` modes, per-worktree exclusion, framework restart, and process ownership.
- Next.js and Vite option and hostname parity.
- The repository contains no server SQLite, edge, worker, Tailcat, DERP, Tailscale, worker protocol, or relay-map runtime path.

Run the complete `tnl` sequence from the repository root:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task generate-check
mise exec -- task format-check
mise exec -- task lint
mise exec -- task test
mise exec -- task go:test-race
mise exec -- task go:test-integration
mise exec -- task build
```

PostgreSQL, QUIC, TLS/yamux, internal-forwarding, DNS, and ACME integration services must be available to the tasks that exercise them.

Run the complete hosted sequence from `../tnl.dev`:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task generate-check
mise exec -- task format-check
mise exec -- task check-types
mise exec -- task lint
mise exec -- task test
mise exec -- pnpm --filter @tnl/accounts test:db
mise exec -- task build
```

## Explicit Non-Goals

- Compatibility modes for any replaced API, schema, role, transport, configuration, hostname, route, credential, or certificate behavior.
- Importing or preserving existing server SQLite, hosted authority, client, route, hostname, credential, certificate, or session data.
- Migration guides or documentation of the replacement as a breaking change.
- Edge, worker, worker-backend, Tailcat, DERP, or Tailscale compatibility.
- A durable ingress or relay database, state directory, backup, or direct PostgreSQL access.
- Transparent replay or migration of visitor streams after relay or transport loss.
- A second semantic model for the TLS/TCP with yamux fallback transport.
- HTTP/3 or WebTransport for visitor traffic.
- Route-specific DNS changes for relay placement.
- Relay-to-relay forwarding.
- Mutable member slugs in the initial implementation.
- Custom roles or a general RBAC framework.
- Multiple managed deployment domains.
- Dynamic DNS plugins, existing claimed-zone adoption, or automatic CAA management.
- Mirrored hosted route, placement, attachment, ACME, or certificate state.
- Persisted CA budget accounting or ACME Renewal Information in this replacement.
- Member routes deeper than one label beneath a member namespace.
- A manifest or bearer token for same-user worktree discovery.
