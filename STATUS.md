# tnl Status And Implementation Plan

Status: active implementation plan
Last reconciled: 2026-08-31
Core repository: `github.com/0xcadams/tnl`
Hosted repository: `github.com/0xcadams/tnl.dev`

## Status And Purpose

This document describes the implemented system, the target hosted architecture,
and the remaining delivery order. It is the source of truth for
architecture and roadmap decisions across the core and hosted repositories.

Current checkpoints:

- Core HEAD is signed commit `616e869`.
- The latest signed release is `v0.1.0-rc.5` at `b7e6873`.
- Hosted HEAD is signed commit `abfb670`.
- Hosted `api/server.ref` pins core commit `b7e6873`.
- Standalone `tnld` is the supported core preview.
- Split edge and worker modes are implemented but not yet qualified for private
  alpha.
- Hosted staging infrastructure is operational, but it still uses temporary
  core-local hostname claims and is not a complete hosted product.
- Hosted production has not launched.

The post-release core commits add an OIDC public-client fix and release, copy,
and Homebrew work. The hosted compatibility pin remains the release commit until
an intentional contract update moves it forward.

Completed behavior and target behavior are kept separate below. A target design
must not be described as implemented until its verification and exit criteria
have passed.

## Product

The authoritative tagline is:

```text
public urls for localhost.
```

The primary operation is:

```console
$ tnl public 3000

https://quiet-lantern.tnl.dev
```

The hosted split request path is:

```text
browser
   |
   | public application TLS
   v
stateful tnl edge
   |
   | assignment to a stateless worker
   v
Tailcat client on worker
   |
   | encrypted Tailcat path
   v
local tnl
   |
   | application TLS terminates here
   v
127.0.0.1:3000
```

Standalone mode combines the edge and worker responsibilities in one `tnld`
process. In both modes:

- Core inspects bounded TLS ClientHello data and routes by exact SNI.
- Core does not terminate or decrypt application TLS.
- Every application key is generated and retained by local `tnl`.
- Local `tnl` terminates application TLS and connects only to one explicitly
  configured literal-loopback HTTP target.
- Application certificates are exact-host certificates, never wildcard
  certificates.

Core can observe SNI, source and destination addresses, TLS handshake metadata,
connection timing and duration, encrypted byte counts, Tailcat identities, and
route connectivity. Product copy must not imply that this metadata is hidden.

## Implemented Core

The core repository currently provides:

- `tnl` for login, publication, hostname administration, and local certificate
  and route lifecycle management.
- `tnld` in standalone, stateful edge, and stateless worker modes.
- SQLite migrations, durable state, and exclusive state-directory ownership.
- Operator login-token exchange and generic OIDC authentication.
- Saved server selection and revocable access credentials with a maximum
  30-day lifetime.
- Durable, principal-owned exact hostname claims.
- Durable routes and monotonically increasing RouteLease generations.
- Lease-scoped Tailcat endpoints, relay discovery, worker assignment, and
  route-specific transport isolation.
- Bounded ClientHello parsing with exact SNI and ALPN routing.
- Optional trusted outer PROXY v2 validation and regenerated inner PROXY v2
  metadata.
- Literal-loopback HTTP proxying with bounded headers, timeouts, connections,
  and copy buffers.
- Durable ACME account, order, challenge, and application-certificate state.
- TLS-ALPN-01 validation through the actual routed path.
- Local application-key generation, certificate validation, renewal, and key
  rotation.
- Prometheus metrics and explicit process, route, worker, stream, and queue
  limits.
- Signed release archives, checksums, SBOMs, provenance, container images, and
  Homebrew release automation.
- Durable route lifecycle and usage export through a SQLite outbox.

The current lifecycle export contains ordered, generation-scoped transitions:

```text
generation_started
ready
disconnected
deleted
```

The current usage export contains revisioned minute and hour buckets for:

```text
connections opened
connection duration
ingress bytes
egress bytes
```

### Current Standalone Flow

The implemented standalone path works as follows:

1. The operator starts one state-owning `tnld` and configures control DNS,
   wildcard route DNS, ACME, and a relay profile.
2. `tnl login` uses the server's OIDC device flow when advertised or exchanges
   its operator login token.
3. `tnl public` requests an exact local hostname claim and creates a durable
   Route with generation 1.
4. Local `tnl` starts a lease-specific Tailcat server pre-authorized for the
   exact ingress key.
5. `tnld` or an assigned worker starts the matching Tailcat client and exposes
   the route to the SNI router.
6. Local `tnl` generates the application key and CSR.
7. Core coordinates TLS-ALPN-01 through the route and returns the exact-host
   certificate for local validation and installation.
8. Local `tnl` proves the normal certificate is installed and marks the current
   generation ready.
9. Public TLS is relayed unchanged to local `tnl`, which terminates it and
   proxies the HTTP request to loopback.
10. Core records lifecycle and cumulative usage facts and exports them through
    its durable outbox when configured.

Current automatic hostname behavior is intentionally temporary: omitting
`--host` creates a lower-case base32 label, and the client remembers that claim
for the local target. Explicit `--host` accepts one label under the configured
route suffix. Both claims are durable until released and tombstoned.

The target removes `--host` in favor of `--name` and changes automatic
publication to an ephemeral two-word name. The product has not launched, so no
flag alias, state migration, or compatibility path is required for this
prelaunch behavior.

## Implemented Hosted Foundation

The hosted repository currently provides:

- A TanStack Start and React application for marketing, documentation,
  waitlist, login, device approval, and account pages.
- GitHub login through Better Auth.
- An OIDC provider and device authorization flow used by the current CLI.
- PlanetScale PostgreSQL schemas separated into Better Auth, private
  application, and display-safe public data.
- Rocicorp Zero queries and mutations with host-only account sessions, scoped
  Zero cookies, exact Origin checks, and user-switch isolation.
- Hosted route, lifecycle, interval, and minute/hour usage schemas.
- Service-authenticated lifecycle and usage ingestion endpoints.
- PostgreSQL triggers that project lifecycle intervals and public usage
  metrics.
- Minute usage retained for 30 days and hour usage retained for 365 days.
- Account route-usage queries and UI.
- Vercel accounts, Fly edge, Fly worker, worker autoscaler, and Zero deployment
  configuration for staging and production.
- CI for formatting, linting, types, generated drift, tests, builds, database
  migrations, and deployment smoke checks.

Staging currently uses:

```text
staging.tnl.dev
account.staging.tnl.dev
sync.account.staging.tnl.dev
tnl.staging.tnl.dev
*.apps.staging.tnl.dev
```

Its core path still uses local OIDC principals and local exact hostname claims.
The hosted route registration function exists, but no production workflow calls
it.

The hosted product remains incomplete because:

- Login does not create a personal team.
- Waitlist eligibility is not projected into an enforceable team allowance.
- Generated-name and DNS authority do not exist.
- Persistent bases and child authorization do not exist.
- Hosted external assertions do not exist.
- Route registration is not exported from core or bound to a hosted
  authorization.
- Normal user flows do not register hosted routes before lifecycle and usage
  ingestion.
- Hosted limits, renewal, suspension, and anonymous admission do not exist.
- Production services are described by manifests but are not launched.

## Architecture And Security Invariants

The following decisions are mandatory across all phases.

### Trust Boundaries

- Every exact route has a distinct application key generated by local `tnl`.
- Application private keys never enter `tnld`, hosted services, databases,
  logs, metrics, API responses, environment variables, or backups by default.
- `tnld` terminates TLS only for its configured control hostname.
- A provisioning route forwards only exact-SNI traffic offering
  `acme-tls/1`.
- A ready route forwards the original TLS bytes without terminating them.
- The local proxy dials only one explicitly configured literal-loopback HTTP
  target.
- Hostname authorization completes before route creation or ACME provisioning.
- Exact active hostname acquisition is atomic.
- Anonymous callers receive only server-assigned ephemeral names.
- Unknown and unauthorized private resources are indistinguishable when
  revealing existence would leak information.
- Authorization expiry or revocation removes a route from lookup and closes
  its streams. An older revision cannot reactivate it.
- Hosted identity, team, pricing, quota, and entitlement policy never enter
  portable core domain logic.
- Every parser, queue, buffer, connection class, and response has an explicit
  bound and fails closed.
- Logs and metrics exclude credentials, assertions, private keys, HTTP paths,
  headers, bodies, cookies, and application responses.
- Request inspection data, when implemented, remains on the user's machine.

### Authority

Each concern has one authority:

| Concern | Authority |
| --- | --- |
| Self-hosted identity and name admission | Core `tnld` |
| Hosted users, teams, names, DNS, eligibility, and limits | Hosted accounts |
| Durable routes, leases, generations, and active occupancy | Core `tnld` |
| Route and lease credentials | Core `tnld` |
| Tailcat sessions, assignments, streams, and readiness | Core `tnld` |
| ACME account, order, challenge, and issuance mechanics | Core `tnld` |
| Application TLS private key | Local `tnl` |
| Raw monotonic lifecycle and usage facts | Core `tnld` |
| Hosted authorization and suspension decisions | Hosted accounts |
| Assertion verification and enforcement | Core `tnld` |
| Hosted route and usage UI state | Rebuildable accounts projection |

Core and accounts do not share a database. Core contains no hosted user, team,
pricing, or entitlement model. Accounts never becomes the authority for route
generations, transport state, certificates, or active routing.

### Credential Separation

Credential classes are not interchangeable:

| Credential | Binding | Persistence |
| --- | --- | --- |
| Login token | Deployment and auth exchange | Operator input/state |
| Access token | Self-hosted principal and core API | Restricted client state |
| External assertion | Core, operation, hostname, revision, route/generation | Memory |
| Route credential | One route across generations | Restricted client state |
| Lease secret | Exact route, lease, and generation | Memory |
| Tailcat key | Exact lease generation | Memory |
| Application key | Exact hostname | Restricted local state |
| Workload credential | Exact service and audience | Deployment secret |

Opaque credentials use class-specific prefixes, at least 256 bits of secret
material, server-side verifiers, constant-time comparison, and endpoint-specific
acceptance. A route credential never authorizes a lease by itself.

### Hostname Equality

Go and TypeScript use one canonicalization algorithm and shared fixtures:

1. Accept ASCII DNS A-labels only.
2. Remove at most one terminal dot and lowercase ASCII letters.
3. Reject Unicode, wildcards, IP literals, underscores, empty labels, URL
   syntax, embedded ports, and invalid A-labels.
4. Validate `xn--` input as already encoded A-labels; do not convert Unicode.
5. Enforce 63-byte label and 253-byte full-name limits.
6. Apply the deployment's reserved infrastructure names before authorization.
7. Store and compare canonical values with binary uniqueness.

HTTP authority parsing may remove one valid numeric port before canonicalization.
The ClientHello parser only extracts bounded framing, SNI, ALPN, and exact bytes;
it does not own normalization or authorization. It accepts at most 64 KiB across
eight TLS records within five seconds and rejects missing or duplicate SNI,
multiple host names, malformed input, truncation, and ECH. Every buffered byte
is replayed exactly once in its original order.

### Lease And Tailcat Fencing

Every route has a persisted monotonically increasing generation. Generation
checks apply to lease acquisition, heartbeat, worker assignment, Tailcat
registration, stream acceptance, certificate work, readiness, authorization
renewal, and suspension.

Activating generation `N+1`:

1. Removes generation `N` from the serving snapshot.
2. Rejects future generation `N` activity.
3. Closes its public and Tailcat streams.
4. Destroys its Tailcat endpoints and keys.
5. Creates new lease-specific endpoints for `N+1`.
6. Publishes `N+1` only after its own readiness checks pass.

Each lease has one Tailcat server at local `tnl` and one Tailcat client at the
serving core worker. The server is restricted before startup to one nonzero
generation-scoped ingress key and one fixed internal TCP port. Raw
agent-controlled Tailcat connection blobs are forbidden. Both sides resolve an
operator-approved relay profile locally.

The control plane accepts only a versioned descriptor containing the server
public key and an operator-approved relay-profile identifier. It cannot carry
relay hosts, insecure flags, or other connection settings. Production pins an
exact Tailcat revision, builds without Tailcat SSH support, prefers direct UDP,
and treats public DERP as a monitored best-effort fallback.

Tailcat lifecycle states are explicit and teardown releases streams,
transports, netstack resources, sockets, keys, and registry entries. Draining
rejects new streams and has a force-close deadline. Partial startup rolls back
completely. A new server boot epoch invalidates old live sessions; durable route
state survives restart, but the client must acquire the next fenced generation.

### ACME And Application TLS

Core owns a durable, forward-only ACME state machine; local `tnl` owns
application keys. Known remote URLs are reconciled before repeating mutations,
ambiguous outcomes have bounded retry and reconciliation, and changed terms are
never accepted silently. Orders bind route, lease generation, exact hostname,
CSR hash, and SPKI hash.

- Initial application keys are ECDSA P-256.
- CSRs contain exactly one exact DNS SAN and no wildcard or unexpected subject.
- TLS-ALPN-01 challenges are generated locally and served only for exact SNI
  plus `acme-tls/1`.
- Core probes the challenge through Tailcat before requesting validation.
- Downloaded certificates are treated as untrusted and checked for exact SAN,
  SPKI, validity, EKU, chain, size, and selected profile.
- Local `tnl` repeats hostname, SPKI, and validity checks before installation.
- Stale-generation completion cannot install a certificate or make a route
  ready.
- Renewal creates a new local key and swaps it only after installation and
  readiness probing succeed.
- The control-host certificate has an independent lifecycle.

## Hostname Model

Friendly two-word generation applies to every automatically generated public
name. Hosted and self-hosted deployments use the same pinned corpus and product
format, but each self-hosted suffix has an independent allocator.

### Hosted Classes

Hosted names share one atomic global namespace:

| Class | Example | Ownership and lifecycle |
| --- | --- | --- |
| Ephemeral exact route | `quiet-lantern.tnl.dev` | One route lifecycle, no children, permanently burned after possible exposure |
| Persistent generated base | `silver-maple.tnl.dev` | Permanently bound to one team; may serve its apex and authorize children |
| Persistent child route | `api.silver-maple.tnl.dev` | Exact temporary route inside the base's team and browser trust boundary |

A two-word label can be either ephemeral or a persistent base, never both.
Persistent bases may serve both:

```text
silver-maple.tnl.dev
api.silver-maple.tnl.dev
demo.silver-maple.tnl.dev
```

Persistent-base release may free active team quota, but the base is never
assigned to another team. Child reuse stays within the original team.

### Self-Hosted Classes

The operator owns a control hostname and wildcard route suffix. With the current
convenience derivation for `TNLD_DOMAIN=example.com`:

```text
control: tnl.example.com
routes:  *.apps.example.com
```

Target behavior is consistent with hosted publication:

```console
$ tnl public 3000

https://quiet-lantern.apps.example.com
```

The stateful `tnld` allocator reserves and burns the name in local SQLite. In
split mode, workers never allocate names.

An explicit self-hosted name is durable:

```console
$ tnl public 3000 --name demo

https://demo.apps.example.com
```

`--name` replaces `--host`; no compatibility alias is retained. Generated
persistent bases and child-name authority remain hosted accounts features. Core
self-hosting initially supports ephemeral generated exact names and durable
explicit exact names, not local team bases.

Hosted `--name` accepts an exact hostname already authorized by an owned
persistent base:

```console
$ tnl public 3000 --name silver-maple.tnl.dev
$ tnl public 3000 --name api.silver-maple.tnl.dev
```

Self-hosted sibling routes remain one browser site unless the operator uses an
appropriate private suffix boundary. Documentation must state that an ordinary
self-hosted route suffix is one browser trust domain.

### Word Corpus And Allocation

Use a reviewed snapshot of Glitch's MIT-licensed `friendly-words` corpus at
`https://github.com/glitchdotcom/friendly-words` as the initial source:

```text
1,450 predicates
3,062 objects
4,439,900 raw pairs
```

The implementation must:

- Vendor the reviewed words and license instead of depending on a live package
  at runtime.
- Record the upstream revision and a corpus manifest hash.
- Keep core and hosted corpus fixtures consistent through compatibility tests.
- Allow only lowercase ASCII words joined by one hyphen.
- Exclude offensive, confusing, reserved, infrastructure-related, and
  trademark-sensitive words or pairs.
- Maintain emergency word and pair quarantine lists.
- Select each component with cryptographic randomness.
- Use the authoritative SQLite or PostgreSQL uniqueness constraint to arbitrate
  collisions and retry a bounded number of times.
- Never add numeric suffixes or opaque identifiers to public hostnames.
- Treat names as discoverable identifiers, not secrets; Certificate
  Transparency may expose issued names.

Ephemeral creation allocates one candidate immediately. Persistent-base
creation may show several candidates and allow rerolling before commitment.

Allocation states must distinguish held, safely unexposed, committing, active,
burned, quarantined, and released-but-still-owned names. A failed allocation may
return to the pool only when no certificate, precertificate, DNS exposure, or
public traffic could have occurred. Ambiguous outcomes remain quarantined.

Permanent ephemeral burns make capacity an operational resource. At the raw
initial corpus size, 1,000 allocations per day consume the namespace in roughly
12 years, while 10,000 per day consume it in roughly 1.2 years. Public beta
therefore requires remaining-capacity metrics, allocation rate limits, a global
stop, and an additive corpus-expansion procedure. Capacity pressure never
weakens burn rules.

## Target Hosted Topology

Production names are:

| Purpose | Hostname |
| --- | --- |
| Marketing and route suffix | `tnl.dev` |
| Accounts and hosted API | `account.tnl.dev` |
| Core control API | `control.tnl.dev` |
| Zero cache | `sync.account.tnl.dev` |
| Ephemeral route or persistent base | `quiet-lantern.tnl.dev` |
| Persistent child route | `api.silver-maple.tnl.dev` |

Staging mirrors that hierarchy:

```text
staging.tnl.dev
account.staging.tnl.dev
control.staging.tnl.dev
sync.account.staging.tnl.dev
quiet-lantern.staging.tnl.dev
api.silver-maple.staging.tnl.dev
```

Exact infrastructure records override public route routing. DNS reconciliation
creates the records needed for persistent child namespaces. DNS wildcards may
route traffic to ingress, but wildcard certificates are never used.

The current core configuration derives `tnl.<domain>` and `apps.<domain>` from
one value. Hosted composition must instead configure the control hostname and
route suffix independently. Self-hosting may retain `TNLD_DOMAIN` as a
convenience shorthand, but explicit control-host and route-suffix settings take
precedence.

Before public beta, `tnl.dev` must be effective in the PRIVATE section of the
Public Suffix List. Staging also needs an effective `staging.tnl.dev` boundary
before it is used to validate browser isolation. This makes unrelated generated
bases separate browser sites while keeping a persistent base and its children
in one site and team boundary.

## Target Hosted Authorization Flow

Hosted accounts is the name and policy authority. Core verifies its decisions
without synchronous policy calls or hosted identity data.

1. The CLI authenticates to accounts through the device flow.
2. Accounts creates or loads the user's personal team.
3. Accounts verifies eligibility, suspension, allocation rate, and resource
   policy.
4. Accounts atomically reserves an ephemeral exact name or validates an owned
   persistent base or child.
5. Accounts issues a short-lived asymmetric JOSE `route.create` assertion.
6. The CLI presents the assertion directly to `control.tnl.dev`.
7. Core verifies and consumes its `jti` transactionally while creating the
   durable Route and generation 1.
8. Core durably exports a route-registration record.
9. Accounts binds the core route ID to the existing authorization and team.
10. Core exports ordered lifecycle events and monotonic usage snapshots only
    after registration.
11. The CLI obtains and presents `authorization.renew` every 15 minutes.
12. Core stops serving when the one-hour authorization expires or a newer
    revision suspends it.

The signed operations are:

```text
route.create
lease.acquire
authorization.renew
```

Assertions bind issuer, audience, operation, authorization ID, canonical exact
hostname, revision, validity, and unique `jti`. Route and exact generation are
included when applicable. Assertions contain no hosted user, team, pricing,
provider, DNS-observation, or entitlement data.

Core persists only the external issuer, authorization ID, canonical hostname,
revision, validity deadline, and minimum replay and suspension state required
for enforcement.

Core verifies an explicit algorithm allowlist and configured public keys with a
rotation overlap. It consumes `jti` in the same transaction as the authorized
state change, rejects stale revisions, and records the highest suspended
revision. Expiration is the reliable revocation bound; no invalidation feed or
synchronous core-to-accounts policy call is required.

## Route Registration And Usage

The existing lifecycle and usage exports assume that accounts already knows the
route. Target hosted projection adds a durable `RouteRegistration` event before
them.

Registration contains only the core route ID, issuer, authorization ID,
canonical hostname, creation time, and idempotency identity. It does not contain
a team ID. Accounts derives the team from the authorization it issued and
rejects any mismatch or unknown authorization.

The core outbox preserves this ordering for each route:

```text
route registration
generation lifecycle
minute/hour usage snapshots
```

Accounts ingestion is idempotent and monotonic. Hosted projections can lag and
can be rebuilt from authoritative facts; they never decide routing state.

Current usage measures encrypted transport facts only:

- Connections opened.
- Connection duration.
- Ingress bytes.
- Egress bytes.

Core does not export HTTP methods, paths, headers, bodies, cookies, status codes,
or application responses.

## Hosted Process Topology

Private alpha uses the implemented split boundary:

```text
public traffic
      |
      v
one stateful edge
SQLite, control API, SNI ingress, route authority
      |
      | authenticated WSS/yamux assignment
      v
stateless workers
Tailcat clients and routed streams
      |
      v
local tnl
```

This topology scales worker route and stream processing horizontally, but it is
not highly available:

- The edge and its SQLite volume remain a single state authority and point of
  failure.
- Worker loss removes assignments and requires generation-fenced route
  reacquisition.
- The autoscaler may create or start workers from authoritative route demand.
- Automated scale-in remains disabled until graceful drain is proven under
  continuous traffic.
- Backups, restoration, restart, deployment, rollback, and state replacement
  are explicit private-alpha exercises.

The initial worker target is 400 routes with a hard limit of 500 on a
two-performance-CPU, 4 GiB worker. These values are qualification starting
points, not promises. Measured memory, churn, stream count, and forced-relay
behavior determine production limits.

## Delivery Phases

Phases are sequential launch gates. Local control work may proceed in parallel,
but its required subset must finish before Phase 7.

| Phase | Outcome |
| --- | --- |
| 1 | Baseline qualification and contract discipline |
| 2 | Account, eligibility, name, and DNS authority |
| 3 | External authorization and route registration |
| 4 | Complete hosted staging vertical slice |
| 5 | Limits, authorization lifecycle, and usage enforcement |
| 6 | Split-topology private alpha |
| 7 | Public beta and anonymous routes |

### Phase 1: Baseline Qualification

Goal: establish one verified release pairing and remove temporary public
contracts before building hosted authority.

Deliverables:

- Qualify current core HEAD and decide the next signed release used by hosted.
- Update `api/server.ref`, generated TypeScript, fixtures, deployment image
  digest, and compatibility tests together.
- Keep core contracts authoritative and changes additive across deployment
  boundaries.
- Replace the `--host` CLI flag with `--name` everywhere, with no alias.
- Set the product tagline everywhere to `public urls for localhost.`
- Add independent control-hostname and route-suffix configuration while keeping
  `TNLD_DOMAIN` only as self-hosted shorthand.
- Move staging configuration and DNS from `tnl.staging.tnl.dev` and
  `*.apps.staging.tnl.dev` to the target hierarchy.
- Add or refresh shared hostname canonicalization fixtures in Go and
  TypeScript.
- Verify OIDC login, hostname claim, route publication, certificate issuance,
  restart, lease reacquisition, export, release artifacts, and installed CLI
  behavior.

Exit criteria:

- Both repositories pass their complete required checks from clean installs.
- Hosted generated artifacts match the pinned core contract.
- Staging control and route suffixes are independently configurable.
- A current self-hosted route survives sequential client and server restart
  tests before the ephemeral behavior replaces it in Phase 2.

### Phase 2: Account, Name, And DNS Authority

Goal: make accounts authoritative for hosted teams and names, and implement the
consistent friendly ephemeral behavior in self-hosted core.

Deliverables:

- Create one personal team transactionally during first successful hosted
  account projection.
- Claim early-waitlist eligibility once and attach the permanent included
  allowance to that team.
- Implement the global hosted name ledger and the local self-hosted name ledger.
- Vendor and validate the pinned friendly-word corpus in both repositories.
- Implement cryptographic candidate generation, bounded collision retries,
  state transitions, burns, quarantine, and capacity metrics.
- Make plain `tnl public` allocate an ephemeral two-word exact name on every
  server.
- Make self-hosted `--name LABEL` create or use a durable exact claim.
- Remove sticky automatic target-to-hostname selection and old base32 automatic
  generation without a compatibility layer.
- Bind an ephemeral claim to exactly one route lifecycle and burn abandoned or
  crashed routes through bounded server-side cleanup.
- Implement hosted persistent-base allocation, candidate reroll, permanent
  team binding, apex authorization, and child-name validation.
- Enforce three active persistent bases per eligible personal team.
- Reserve all production and staging infrastructure names.
- Add a durable DNS outbox, provider adapter, retries, reconciliation, and
  operator repair tools.
- Add account UI for access state, bases, allocation history, security, and
  DNS state.

Exit criteria:

- Concurrent allocators cannot duplicate a name or cross ownership classes.
- Exposure, issuance, timeout, ambiguous provider results, and release exercise
  the correct burn or quarantine behavior.
- Self-hosted publication returns a friendly ephemeral URL and tombstones it at
  the end of its route lifecycle.
- Persistent bases and child DNS reconcile after worker and process restarts.
- Corpus validation and namespace-capacity alarms run in CI and operations.

### Phase 3: External Authorization And Registration

Goal: connect accounts authority to core without shared identity, storage, or
synchronous policy calls.

Deliverables:

- Define and implement asymmetric JOSE assertions for `route.create`,
  `lease.acquire`, and `authorization.renew`.
- Add explicit algorithm, issuer, audience, key ID, validity, hostname,
  operation, route, generation, revision, and `jti` validation.
- Consume replay IDs atomically with route and lease state transitions.
- Persist only the opaque external authorization reference and enforcement
  state in core.
- Add overlap-safe signing-key rotation.
- Add revisioned idempotent suspension and in-memory stream teardown.
- Add durable core `RouteRegistration` export ahead of lifecycle and usage.
- Change hosted registration to derive team ownership from the authorization,
  not from a team ID supplied by core.
- Implement the hosted CLI adapter that pairs accounts credentials with the
  selected core server.
- Add cross-repository compatibility fixtures for success, replay, expiry,
  wrong audience, wrong operation, wrong hostname, wrong route/generation,
  stale revision, unknown key, and key rotation.

Exit criteria:

- Core creates an external route without storing hosted identity or policy.
- Every assertion substitution and replay case fails closed.
- Registration is durable and always precedes lifecycle or usage for a route.
- Accounts outage does not affect current traffic until renewal can no longer
  complete and authorization expires.

### Phase 4: Hosted Staging Vertical Slice

Goal: replace temporary local claims with the complete external-authority flow
in staging.

Deliverables:

- Plain authenticated `tnl public 3000` creates an ephemeral generated exact
  URL under `staging.tnl.dev`.
- `--name` can select an owned persistent base apex or exact child.
- Normal login creates the personal team and enforces eligibility.
- Accounts reserves the hostname, reconciles DNS, and issues the assertion.
- Core creates the route, exports registration, and then exports lifecycle and
  usage.
- Accounts projects the route and displays minute/hour usage from the normal
  user flow.
- The current `*.apps.staging.tnl.dev` local-claim path is removed.
- Restart and recovery exercises cover accounts, edge, worker, Zero, CLI, and
  delayed export delivery.

Exit criteria:

- One automated smoke test proves login, name allocation, DNS, route creation,
  Tailcat readiness, exact certificate issuance, public traffic, restart,
  registration, lifecycle, usage, and cleanup end to end.
- No hosted route uses a core-local hostname claim.
- No production workflow manually inserts hosted route ownership.

### Phase 5: Limits And Authorization Lifecycle

Goal: enforce the private-alpha product policy from authoritative data.

Initial policy:

```text
3 active persistent bases per eligible personal team
5 concurrent routes per eligible personal team
5 GB transferred per UTC day
1 hour authorization lifetime
15 minute authorization renewal
```

Deliverables:

- Count ephemeral, persistent-apex, and child routes consistently against the
  concurrent-route limit.
- Calculate transfer from accepted monotonic usage snapshots.
- Stop renewal after suspension or transfer exhaustion.
- Keep expiry as the reliable serving cutoff and support higher-revision urgent
  suspension.
- Add account credential, route, name, and session administration.
- Monitor registration, lifecycle, usage, retention, retry age, idempotency
  conflicts, and projection lag.
- Define behavior for delayed exports, accounts outage, clock skew, retries,
  and day-boundary calculations.
- Preserve the non-transferable early-waitlist allowance independently from
  future pricing.

Exit criteria:

- Concurrency, transfer, renewal, expiry, and suspension pass boundary and race
  tests.
- Hosted policy changes do not require core identity or pricing changes.
- Operators can identify and repair delayed or conflicting projections without
  making the projection authoritative.

### Phase 6: Split-Topology Private Alpha

Goal: qualify one stateful edge plus stateless workers for a trusted cohort.

Deliverables:

- Deploy the immutable, compatible edge and worker image pairing.
- Derive worker scale-out from authoritative route demand with explicit floor,
  ceiling, target, and hard capacity.
- Keep scale-in manual until drain is qualified.
- Exercise worker disconnect, replacement, capacity rejection, route
  reacquisition, generation fencing, and continuous traffic during scale-out.
- Prove graceful drain reaches zero routes and streams before worker removal.
- Exercise cold edge backup, restoration, deployment, rollback, and replacement.
- Add ACME issuance controls, CAA, CT monitoring, relay health, export health,
  disk, SQLite, worker, stream, and capacity alerts.
- Document the edge and SQLite single point of failure in product and operator
  expectations.
- Admit only a manually controlled trusted cohort.

Exit criteria:

- Worker loss cannot leave a stale generation serving.
- Scale-out works under continuous routed traffic without ownership ambiguity.
- Recovery exercises meet the documented single-edge recovery objective.
- Private-alpha routes complete sustained direct and forced-relay tests within
  measured resource limits.

### Phase 7: Public Beta

Goal: add bounded anonymous admission and complete all public launch gates.

Deliverables:

- Confirm an effective PRIVATE Public Suffix List entry for `tnl.dev`.
- Confirm CA account, profile, exact-identifier, and aggregate issuance capacity.
- Narrow CAA and operate Certificate Transparency monitoring.
- Add a locally generated anonymous installation key and proof of possession.
- Limit anonymous installations to one concurrent route.
- Allocate only server-generated ephemeral names to anonymous callers.
- Use the approved short-lived certificate profile.
- Enforce source, prefix, ASN, installation, allocation, issuance, transfer,
  concurrency, and global limits.
- Add abuse reporting, failure breakers, namespace capacity alerts, and a global
  allocation and issuance stop.
- Complete public load, churn, restart, and abuse simulations.
- Complete the required local control and diagnostics workstream.

Exit criteria:

- Every public launch gate has recorded evidence and an accountable owner.
- Anonymous state deletion does not bypass source, ASN, issuance, or global
  controls.
- A global stop prevents new allocation and issuance without disrupting
  operator access to current state.
- Local diagnostics can distinguish target, route, certificate, worker,
  Tailcat, and relay failures without inspecting hosted HTTP content.

## Local Control Workstream

Local control and request inspection are separate projects.

Required before public beta:

```text
tnl public list --json
tnl status --json
tnl doctor --json
```

This work includes:

- Stable finite JSON schemas and categorized exit codes.
- Stable NDJSON for long-running publication state changes.
- A private Unix-domain control socket in the restricted client state directory.
- Running-tunnel discovery without starting duplicate state owners.
- Separate local-target, route, lease, certificate, Tailcat, worker, and relay
  health.
- Stale-socket, crash, restart, and concurrent-command handling.
- Secret-free diagnostics and no request-content capture.

Human output remains on stderr when structured output uses stdout. JSON and exit
codes are versioned product contracts.

The following inspection work does not block private alpha or public beta:

```text
tnl inspect list
tnl inspect get REQUEST_ID
tnl inspect replay REQUEST_ID
```

Later inspection is opt-in and local, with strict count, size, and retention
bounds, password protection, replay to the configured loopback target, and a
local web inspector backed by the same control socket. Request content never
enters core, accounts, hosted persistence, or hosted telemetry.

## Verification

### Core

Required core verification includes:

- Unit, integration, and race tests.
- Fuzzing for ClientHello and PROXY v2 parsing.
- SQLite migration, transaction, lock, restart, and concurrency tests.
- Hostname allocation, collision, burn, quarantine, and namespace exhaustion.
- Credential confusion, assertion substitution, replay, revision, and expiry.
- Lease generation fencing at every persisted and in-memory entry point.
- Tailcat startup rollback, key isolation, stream half-close, drain, and teardown.
- ACME restart, ambiguous result, exact-SAN, SPKI, stale generation, renewal, and
  rotation tests.
- Public route tests through SNI, PROXY v2, Tailcat, local TLS, and loopback HTTP.
- Structured CLI schema, socket, exit-code, and crash-recovery tests.
- Signed archive, checksum, SBOM, provenance, image, and installed-binary tests.

The normal core check is:

```console
mise exec -- task format-check lint test build package
```

### Hosted

Required hosted verification includes:

- Formatting, linting, type checking, generation drift, tests, and production
  builds.
- PostgreSQL migration, trigger, transaction, idempotency, and retention tests.
- Publication secrecy and private/public schema separation.
- Account, personal-team, eligibility, name, and route isolation.
- OIDC device authorization and account-host cookie boundaries.
- Assertion issuance, replay, revision, expiry, rotation, and suspension.
- Name allocation, corpus filtering, permanent burns, quarantine, and DNS
  reconciliation.
- Route registration ordering before lifecycle and usage.
- Lifecycle interval and usage projection idempotency.
- Zero query authorization, Origin validation, cookie scope, and user switching.
- Staging and production deployment smoke tests.

The normal hosted check is:

```console
mise exec -- task format-check generate-check check-types lint test build
```

### Cross-Repository And Operations

- Hosted generation resolves the exact commit in `api/server.ref` and fails on
  drift.
- Canonical hostname and external-assertion fixtures run independently in Go
  and TypeScript.
- Additive contracts deploy consumers before producers require new fields.
- Edge and workers use one immutable core image digest.
- Worker disconnect, capacity rejection, replacement, and graceful drain run
  under continuous traffic.
- Edge restart and state restoration preserve durable authority while fencing
  old live sessions.
- Launch evidence records actual CA, DNS, PSL, relay, resource, and recovery
  results rather than relying on configuration alone.

## Deferred Work

The active plan explicitly defers:

- BYO domains.
- Shared teams, membership, and invitations.
- Dedicated private DERP.
- Generic TCP tunnels.
- HTTP/3, QUIC routing, and ECH.
- gRPC/h2c upstreams.
- Multiple local targets per route.
- Windows client support.
- Active-active edge and state authority.
- Hosted request inspection or WAF behavior.
- Long-term Fly service-metric replication into PlanetScale.
- Request capture, replay, and the local web inspector as launch requirements.
- MCP and editor integrations.

Deferred work must preserve the authority, credential, generation, key custody,
bounded-input, and no-hosted-content-inspection invariants in this document.
