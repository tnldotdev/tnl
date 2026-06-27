# Replicated Control, Ingress, And Relay Implementation Plan

## Status

This document is the implementation contract and runtime architecture source of
truth for the tnl server. When runtime topology in another document conflicts
with this document, this document wins.

The product and ownership model in
[Team-First Ownership Implementation Plan](https://md.cormo-turtle.ts.net/git/personal/tnl/IMPLEMENTATION_PLAN.md)
remains authoritative for identities, teams, memberships, domains, routes, and
authorization policy.

The replacement architecture has:

- A control service backed by PostgreSQL.
- An ingress service behind one health-aware ingress address.
- At least two independent relay services.
- Any number of relay processes within each relay service.
- Exactly two publisher connections per route session, assigned to distinct
  relay services.
- QUIC with TLS 1.3 as the primary publisher-connection transport.
- Raw TLS/TCP plus yamux as the fallback publisher-connection transport.
- Authenticated internal forwarding from ingress to the concrete connected
  relay process.
- A clean cutover with no compatibility mode for the replaced runtime.

Use the canonical terms and machine field names in `AGENTS.md` throughout code,
wire contracts, SQL, configuration, metrics, tests, and documentation.

## Goals

1. Control, ingress, and relay services scale independently.
2. A route session maintains exactly two publisher connections assigned to
   distinct relay services.
3. Initial routability requires an installed certificate and both publisher
   connections ready.
4. After its first routable transition, a route version remains routable with
   one ready publisher connection and replenishes toward two.
5. Zero ready publisher connections makes a route version temporarily
   unroutable without ending the route session or changing the route version.
6. An individual relay-process failure affects only publisher connections held
   by that process.
7. A complete relay-service failure leaves the publisher connection through the
   other relay service available for new visitor connections.
8. Ingress applies policy and accounting once, selects a connected relay, and
   forwards each visitor connection once.
9. Route TLS terminates at the publisher. Ingress creates exactly one PROXY v2
   metadata header, and relay preserves it unchanged.
10. Correctness across control processes comes from PostgreSQL transactions,
    constraints, revisions, leases, and durable job claims rather than an
    elected application leader.
11. Ingress and relay processes own no durable product state and never connect
    to PostgreSQL.
12. Standalone uses the same contracts and state transitions by composing
    control, ingress, and two logical relay services in one `tnld` process.
13. Control and standalone start without required certificate files, obtain the
    public control certificate through ACME, and require a bootstrap management
    token.
14. Split ingress and relay processes start from one role-scoped enrollment
    token and minimal identity configuration rather than static service-mTLS
    files.

## Non-Goals

- HTTP/3 visitor ingress.
- Migration of established visitor streams after a process or transport
  failure.
- Replay after the retry boundary.
- Relay-to-relay forwarding.
- Direct PostgreSQL, DNS-provider, ACME-account, authority, or
  administrator access from ingress or relay processes.
- Durable disks for ingress or relay processes.
- Compatibility aliases for replaced APIs, configuration, fields, or wire
  values.
- Publicly trusted relay transport certificates. Publishers use the scoped
  service-CA trust returned by control for relay connections.
- Importing the replaced server SQLite state into PostgreSQL.

## Target Topology

```text
                              PostgreSQL
                                  |
                      +-----------------------+
                      |    control service    |
                      | control A, B, ...     |
                      +-----------+-----------+
                                  |
               +------------------+------------------+
               |                                     |
     +---------v----------+               +----------v----------+
     |  ingress service   |               |     relay services  |
     | ingress A, B, ...  |               |                     |
     +---------+----------+               | A: relay 1, 2, ...  |
               |                          | B: relay 3, 4, ...  |
               +------------------------->+---------------------+
                                                    ^
                                                    |
                                      two publisher connections
```

Public route DNS sends visitor connections only to the ingress address.
Publishers connect to stable relay addresses returned by control. Each relay
address sends a publisher connection to one process in its relay service.
Ingress uses the internal relay address of the concrete process that claimed a
publisher connection.

At least two relay services are required for split deployments:

```text
relay-a.tnl.example.com -> relay service A
relay-b.tnl.example.com -> relay service B
```

The two connection slots for a route session are assigned to different relay
services. Multiple relay processes in one service improve capacity and
process-level availability but share the service's intended failure boundary.

## Role Boundaries

### Control

Control owns:

- The control API.
- Durable identity, team, membership, domain, route, and route-session state.
- Route-version allocation.
- Relay-service configuration and placement.
- Ingress and relay leases.
- Publisher-connection assignments, credentials, claims, and state.
- The ingress routing table.
- DNS and certificate coordination.
- Usage ingestion, aggregation, and delivery.
- Recovery episodes and durable recovery histograms.
- The durable private service CA, service enrollment tokens, service
  certificate issuance, and relay-service transport certificate material.
- Administration, maintenance controls, auditing, retention, and background
  jobs.

All control processes in a control service are interchangeable. Any process may
serve public or internal requests. PostgreSQL is authoritative, and no
process-local cache may authorize a stale mutation.

### Ingress

Ingress owns:

- Public visitor TCP acceptance.
- ClientHello inspection and route-hostname selection without terminating route
  TLS.
- IP policy and source, route, and connection limits.
- Selection among connected relays from the ingress routing table.
- The retry boundary and bounded pre-boundary retries.
- Creation of the sole PROXY v2 metadata header.
- Internal forwarding to one connected relay per attempt.
- Visitor connection usage accounting.
- Reporting successful public recovery.
- Health and readiness for the ingress address.

Ingress does not accept publisher connections. It has no PostgreSQL access and
no durable route state. It fails closed when its ingress lease or routing table
expires.

### Relay

A relay process owns:

- Its relay lease and drain state.
- QUIC and TLS/TCP with yamux publisher-connection listeners.
- Atomic claims for publisher connections received through its relay service.
- Locally connected publishers.
- Per-process publisher-connection and visitor-stream capacity.
- Authenticated internal forwarding from ingress.
- Validation that every forwarded visitor targets a current local publisher
  connection.
- Preservation of PROXY v2 metadata and route TLS bytes.

A relay process receives no global ingress routing table. It knows only its own
lease, relay-service membership, connection claims, and locally connected
publishers.

### Standalone

Standalone composes one control, one ingress, and two logical relay services in
one `tnld` process against PostgreSQL. Each logical relay service has a distinct
`relay_service_id`, and its logical relay process has a distinct `relay_id`,
while both share physical listeners, memory, and failure fate.

Standalone preserves the two-connection and distinct-relay-service contracts.
It does not claim process-level or service-level redundancy. In-process calls
may avoid serialization only behind the same authorization, stale-state check,
and state-transition boundaries used by split deployments.

Standalone bypasses service enrollment because its internal calls remain in
process. It still uses control-owned certificate state for its public control
and relay listeners and requires the bootstrap management token.

## Addresses And Listeners

`TNLD_SERVER_DOMAIN` is the infrastructure DNS suffix and is independent from
`TNLD_MANAGED_DEPLOYMENT_DOMAIN`, which owns public route namespaces. For:

```text
TNLD_SERVER_DOMAIN=tnl.example.com
```

derive:

```text
control.tnl.example.com
ingress.tnl.example.com
relay.tnl.example.com       # standalone physical relay address
relay-a.tnl.example.com     # split relay service A
relay-b.tnl.example.com     # split relay service B
```

`TNLD_CONTROL_HOSTNAME` contains only a canonical hostname. HTTPS and public
port 443 are implied; schemes, paths, and explicit ports are rejected.

The deployment surfaces are separate:

- The control hostname serves the public control API.
- The ingress address accepts public route TLS over TCP.
- Each relay address accepts publisher connections over UDP and TCP.
- Each concrete relay process advertises an internal relay address for ingress.
- Control exposes the ingress API at the control hostname on TCP 9443 and the
  relay API at the control hostname on TCP 9444. Enrollment returns the exact
  endpoint for the enrolling role.

For each relay address:

- UDP terminates QUIC with TLS 1.3 and ALPN `tnl-tunnel/1`.
- TCP terminates TLS 1.3 with ALPN `tnl-tunnel/1` and starts yamux.
- QUIC 0-RTT is disabled.
- A short-lived service-CA certificate belongs to the relay service address.
- A service load balancer distributes new publisher connections among healthy,
  non-draining relay processes.

Public route hostnames are never sent to relay addresses. Route TLS arrives at
ingress, passes through one relay, and terminates at the publisher.

Standalone may share a physical TCP listener by exact SNI while preserving the
logical listener boundaries. Exact control-hostname SNI selects the control API,
exact relay-address SNI selects TLS/yamux, and route SNI selects ingress.

## Service mTLS

Control initializes one private service CA transactionally on first startup and
persists it as durable PostgreSQL state. Concurrent control startups converge on
the same CA. Service private keys are generated locally and never sent to
control.

An administrator creates reusable enrollment tokens through the authenticated
control API:

```console
tnl admin enrollment-tokens create --role ingress
tnl admin enrollment-tokens create --role relay --relay-service relay-a
tnl admin enrollment-tokens create --role relay --relay-service relay-b
```

One ingress token may enroll any number of ingress replicas. Each relay service
has one token shared only by replicas in that service. Tokens remain valid until
revoked so autoscaling does not require a token broker. Control stores only the
token lookup ID, digest, role, optional relay-service scope, creation and use
audit metadata, and revocation state. The raw `tnl_enrollment_...` token is
returned exactly once.

Enrollment uses `POST /v1/service-enrollments` on the public control HTTPS
endpoint. A process sends its token, role, process identity, and locally
generated CSR. Control rejects revoked tokens, cross-role use, a relay-service
scope mismatch, and invalid identities or CSRs. A successful response contains:

- A one-hour service certificate.
- The service CA trust bundle.
- The role's internal control API endpoint.
- Stable role facts required to register and renew a lease.

Relay enrollment additionally returns the relay service ID, relay address, TLS
server name, and the current shared relay-service transport certificate and
private key. Control issues that one-hour server certificate from the
service CA for the derived relay hostname. Publishers receive the service CA
certificate through authenticated route-session setup and use it only as the
trust root for publisher connections to relays.

Ingress and relay processes re-enroll with the same token after approximately
thirty minutes. An expired service certificate makes a process unready and
prevents lease renewal. Revoking a token blocks subsequent enrollment; already
issued certificates remain bounded by their one-hour lifetime.

Control's internal ingress and relay APIs use separate:

- Network listeners.
- OpenAPI contracts.
- HTTP handlers.
- Role-constrained server certificate profiles.
- Client authorization policies.
- Authorization middleware.

An ingress identity is rejected by the relay API. A relay identity is rejected
by the ingress API. Public control API credentials and enrollment tokens are
rejected by both.

Ingress-to-relay connections also use service mTLS. A relay accepts only an
ingress identity trusted for internal forwarding. The relay server identity and
internal relay address are checked before any visitor stream is opened.

## Publisher-Connection Transport

`internal/muxsession` remains the transport implementation boundary. It exposes
reliable multiplexed bidirectional streams over:

- QUIC with TLS 1.3.
- Raw TLS/TCP with yamux.

Transport-specific code is limited to socket creation, TLS configuration,
stream adaptation, flow control, resets, timeouts, and transport-labeled
diagnostics. These behaviors are transport-independent:

- Publisher authentication.
- Connection assignment claims.
- Route-version and assignment-revision checks.
- Publisher-connection liveness and draining.
- Visitor-stream headers.
- PROXY v2 handling.
- Usage accounting.

The publisher prefers QUIC and starts TLS/TCP with yamux after a bounded delay.
A candidate wins only after the shared application handshake is accepted.
Authentication, authorization, protocol, and stale-state failures are terminal
and are not retried through another transport.

An established publisher connection never changes transport. On failure, the
publisher reconnects under the current or replacement connection assignment.
Established visitor streams are not migrated.

## `tunnelv1` Protocol

The handwritten `pkg/protocol/tunnelv1` package is the sole source of truth and
is independent of QUIC, TCP, TLS, yamux, HTTP, OpenAPI, and PostgreSQL. There are
no standalone tunnel JSON Schemas or generated tunnel models.

The protocol retains:

- Four-byte big-endian frame lengths.
- Strict JSON decoding with unknown-field rejection.
- Closed tagged unions.
- A 1 KiB maximum stream header.
- A 64 KiB maximum control frame.
- An explicit protocol version in ALPN and messages.
- Stable semantic error codes.

Golden JSON and framed-wire fixtures define valid encoding. Invalid-message
fixtures and focused tests cover unknown fields, missing fields, bounds, and
truncated frames. Fuzz tests exercise frame and control-message decoding, and
the same transport behavior suite runs against QUIC and TLS/TCP with yamux.

Each multiplexed connection opens one control stream before visitor streams.
The handshake identifies the peer role and authenticates either a publisher
connection credential or an ingress service identity. Publisher and ingress
connections use separate stream-header variants.

A publisher visitor-stream header carries:

```text
protocol_version
kind = visitor
visitor_connection_id
route_id
route_session_id
route_version
publisher_connection_id
connection_assignment_revision
```

An ingress internal-forwarding header carries:

```text
protocol_version
kind = internal_forward
visitor_connection_id
route_id
route_session_id
route_version
publisher_connection_id
connection_slot
connection_assignment_revision
relay_service_id
relay_id
relay_run_id
relay_lease_revision
route_expires_at
lease_expires_at
```

Relay validates that the requested publisher connection is current and local,
opens the publisher visitor stream, and acknowledges setup before ingress sends
visitor bytes. The removed multi-hop field is not replaced because relay never
forwards to another relay.

## Placement And Publisher-Connection Lifecycle

Each route session owns connection slots `0` and `1`.

1. Route-session creation selects two eligible relay services with distinct
   `relay_service_id` values.
2. Control atomically creates both connection assignments.
3. Setup returns each slot's relay service ID, relay address, TLS server name,
   publisher connection ID, connection assignment revision, expiration, and
   opaque publisher connection credential.
4. The publisher establishes each connection through the assigned relay
   service address.
5. Any healthy process in that relay service may receive the connection.
6. The process authenticates to control and atomically claims the assignment
   using its relay ID, process run ID, and relay lease revision.
7. First valid claim wins. Concurrent transport candidates or relay processes
   lose the compare-and-set and close.
8. Control publishes the concrete connected relay and internal relay address to
   the ingress routing table.
9. Once both publisher connections are ready and the route certificate is
   installed, the route version may complete its first routable transition.
10. An unexpected connection loss affects only that connection and does not end
    the route session or increment the route version.
11. The publisher receives current or replacement assignments through route
    session heartbeat responses and reconnects toward two.
12. After first routability, one ready publisher connection remains routable;
    zero removes ordinary routing until a connection returns.

A connection assignment is checked against:

- Route session ID and route version.
- Publisher connection ID and connection slot.
- Connection assignment revision.
- Relay service ID.
- Relay ID, relay process run ID, and relay lease revision after claim.
- Route-session, assignment, and relay-lease expiration.

Draining a relay process prevents new claims and removes its publisher
connections from selection for new visitor traffic. Publishers establish
replacement connections through another process in the same relay service when
possible. Control may replace the relay-service assignment when needed while
preserving distinct services across the two slots.

## Ingress Routing Table

Control sends only ingress the short-lived state required to serve visitors.
Each routable or challenge entry includes:

- Route ID, route session ID, and route version.
- Canonical hostname and IP policy.
- Route and source limit inputs.
- Route-session and entry expiration.
- Certificate challenge state when applicable.
- An ordered set of ready publisher connections.
- For each connection, the publisher connection ID, connection slot,
  connection assignment revision, relay service ID, relay ID, relay process run
  ID, relay lease revision, internal relay address, TLS server name, and
  expiration bounds.

Ingress registers, obtains an ingress lease, loads a consistent snapshot and
`routing_table_revision`, then receives ordered changes after that revision.
Every lease renewal reports its applied revision. A retention gap requires a
new snapshot.

Ingress readiness requires:

- A current ingress lease.
- A complete routing-table snapshot.
- No revision gap.
- An unexpired routing table.
- A live public visitor listener.

Relays do not receive or cache this table.

## Visitor Data Path

1. The ingress address sends a visitor connection to a ready ingress process.
2. Ingress inspects ClientHello SNI without terminating route TLS.
3. Ingress applies IP policy and connection limits.
4. Ingress resolves the current route version and ordered connected relays.
5. Ingress creates one visitor connection ID and one PROXY v2 metadata header.
6. Ingress opens an authenticated connection to a selected connected relay and
   sends the internal-forwarding header.
7. Relay validates its current identity, lease, and local publisher connection.
8. Relay opens a publisher visitor stream and returns setup acceptance.
9. Ingress sends the PROXY v2 metadata followed by untouched route TLS bytes.
10. Relay preserves the byte stream unchanged to the publisher.
11. The publisher terminates route TLS and forwards plain HTTP to the target.

All attempts share one bounded setup deadline. Ingress may select another
connected relay after connection failure or setup rejection only before sending
the first visitor byte to a relay. After that retry boundary, any failure closes
the visitor connection without replay.

Usage is attributed once to the visitor connection, not once per relay attempt.

## Relay-Service Scaling

### Scale Out

1. Start another relay process with the same `relay_service_id` and relay
   address configuration.
2. Give it a unique relay ID and process run ID.
3. Register it with control and obtain a relay lease.
4. Add it to the relay service's public load balancer.
5. New and replacement publisher connections begin reaching it.
6. Existing publisher connections remain on their current processes.

Control calculates service-level capacity from healthy, non-draining relay
processes. Each relay process independently enforces its own connection and
stream capacity.

### Scale In

1. Mark the relay process as draining.
2. Stop sending it new publisher connections.
3. Stop selecting its publisher connections for new visitor traffic.
4. Have publishers establish replacement connections on other relay processes.
5. Allow established visitor streams to finish until the drain deadline.
6. Stop the relay process.

No durable state moves during either operation. Replacing a publisher
connection does not change the route session or route version.

### Failure Behavior

A relay-process failure invalidates only claims held by its relay ID, process
run ID, and lease revision. Publishers reconnect through the same relay service
or receive replacement assignments.

A complete relay-service failure removes one of each affected route session's
two publisher connections. The connection through the other relay service
remains available:

```text
connection slot 0 -> relay service A -> unavailable
connection slot 1 -> relay service B -> ready
```

Established visitor connections through a failed process may close. New visitor
connections use the surviving connected relay.

## Ingress Scaling

Scaling out ingress requires starting a process, registering it, loading the
current ingress routing table, becoming ready, and adding it to the ingress
address's load balancer.

Scaling in requires removing the process from public load balancing, marking it
draining, rejecting new visitor connections, allowing existing connections to
finish, and stopping it after the deadline.

Ingress scaling does not move durable state or reconnect publishers.

## Control Scaling

A new control process uses the same PostgreSQL database and configuration and
joins the control service load balancer. It may immediately serve public and
internal requests after passing schema and dependency readiness checks.

The eventual scaling limit is PostgreSQL transaction and connection capacity,
not an application leader. Benchmarks must measure connection pooling,
transaction cost, durable job contention, and routing-table delivery.

## PostgreSQL State

The final baseline includes:

- `control.relay_services` for stable relay-service identity, relay address,
  TLS server name, enabled state, and intended failure boundary.
- `control.relay_leases` for concrete relay identity, relay service membership,
  process run ID, lease revision, internal relay address, capacity, drain state,
  and expiration.
- `control.ingress_leases` for ingress identity, process run ID, lease revision,
  load, routing-table cursor, drain state, and expiration.
- `control.route_session_connections` for two connection slots, publisher
  connection IDs, assignment revisions, assigned relay service, credential
  digest, connected relay identity, state, and timestamps.
- `control.ingress_routing_table_clock` and
  `control.ingress_routing_table_events` for durable ordered projections.
- `control.ingress_usage_runs`, `control.ingress_usage_reports`,
  `control.route_usage_buckets`, and `control.route_usage_deliveries`.
- `control.route_recovery_episodes` and the durable recovery histogram.
- `control.service_ca` for the durable private CA certificate and key.
- `control.service_enrollment_tokens` for role-scoped token digests, relay
  service scope, audit metadata, and revocation.
- `control.relay_transport_certificates` for short-lived shared relay-service
  server certificate and key material.

Required constraints include:

- One nonterminal route session per route.
- Unique `(route_session_id, connection_slot)` with slots limited to `0..1`.
- Distinct relay service IDs for a route session's two slots.
- One current claim for a publisher connection.
- Monotonic route versions, connection assignment revisions, ingress and relay
  lease revisions, routing-table revisions, and usage report revisions.
- One open recovery episode per route version.

The publisher connection credential is stored only as a digest. A claim locks
the assignment and current relay lease, verifies relay-service membership and
all stale-state checks, and commits the concrete connected relay atomically.

## Route Usage

Ingress aggregates cumulative route usage in memory and sends revisioned
reports at a bounded interval. Reports are keyed by ingress ID, ingress process
run ID, route ID, route version, bucket, and report revision.

Control deduplicates cumulative reports transactionally, updates route usage
buckets, and delivers external route usage bucket reports through a durable
outbox. Graceful drain sends and acknowledges a final report. An abrupt ingress
failure records incomplete coverage for only the unreported interval.

Relay attempts never multiply usage. Relays do not report route usage.

## Public Recovery SLI

Expose `tnl_route_ingress_failure_public_recovery_seconds` without route,
hostname, ingress, relay, or episode labels and with buckets:

```text
0.25, 0.5, 1, 2, 5, 10, 20, 30, 45, 60, 120
```

Any unexpected ready publisher-connection loss for an already-routable route
opens one recovery episode transactionally before the updated ingress routing
table is emitted. This includes a `2 -> 1` transition.

The first publisher byte successfully written to a visitor after the failure
completes the episode once through the ingress API. Completion updates the
durable cumulative histogram in the same transaction. Route-session closure,
expiration, replacement, suspension, or deletion cancels an open episode.

## Certificates And ACME

Route TLS private keys remain publisher-local. Control retains the restart-safe
PostgreSQL ACME state machine and replicated certificate workers.

The control hostname always has automatic public TLS. Control and standalone
obtain and renew that certificate through ACME using `TNLD_ACME_EMAIL` and
explicit terms acceptance. The ACME directory has a production default and may
be overridden for private or test directories. Static public certificates are
optional advanced overrides, never required bootstrap inputs.

Relay transport TLS does not use ACME. Control issues one-hour relay-service
server certificates from the durable service CA and distributes the shared
certificate/key only to relay processes presenting that service's unrevoked
enrollment token. Route TLS remains publicly trusted and publisher-local.

TLS-ALPN-01 uses the same visitor path as ordinary traffic:

1. Control publishes a challenge entry to the ingress routing table.
2. Ingress selects a connected relay.
3. Relay opens a visitor stream on the local publisher connection.
4. The publisher terminates the challenge TLS connection.

Challenge routing may precede ordinary routability. Ordinary first routability
still requires the installed route certificate and both publisher connections
ready on distinct relay services.

## Configuration

The final server modes are:

```text
TNLD_MODE=standalone|control|ingress|relay
```

Required settings are:

| Mode       | Required settings                                                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standalone | `TNLD_MODE`, `TNLD_DATABASE_URL`, `TNLD_SERVER_DOMAIN`, `TNLD_MANAGED_DEPLOYMENT_DOMAIN`, `TNLD_ACME_EMAIL`, `TNLD_ACME_ACCEPT_TERMS`, `TNLD_LOGIN_TOKEN` |
| Control    | The same control-owned settings as standalone                                                                                                             |
| Ingress    | `TNLD_MODE`, `TNLD_CONTROL_HOSTNAME`, `TNLD_SERVICE_ENROLLMENT_TOKEN`, `TNLD_INGRESS_ID`                                                                  |
| Relay      | `TNLD_MODE`, `TNLD_CONTROL_HOSTNAME`, `TNLD_SERVICE_ENROLLMENT_TOKEN`, `TNLD_RELAY_ID`, `TNLD_INTERNAL_RELAY_ADDRESS`                                     |

Control and standalone require `TNLD_LOGIN_TOKEN`. The server domain derives
the public control and ingress hostnames plus standalone and split relay
hostnames. The managed deployment domain remains independent and derives route
namespaces.

Ingress and relay generate a new process run ID and service private key on each
start. Enrollment supplies internal API endpoints, role facts, certificates,
and trust. Relay service identity and public relay address come from the token's
scope rather than relay environment variables.

Listen addresses, limits, timing, metrics, an alternate ACME directory, and
static public certificate overrides remain optional advanced settings with safe
defaults. Static service-mTLS certificate, key, and trust-bundle settings do not
exist. Ingress and relay modes reject database, ACME account, login, authority,
and administrator settings. Replaced configuration is deleted rather than
aliased.

## Implementation Sequence

### 1. Architecture Sources

- Replace canonical terminology in `AGENTS.md`.
- Rewrite this document around control, ingress, and relay services.
- Make `IMPLEMENTATION_PLAN.md` defer runtime topology here and remove
  conflicting runtime claims.

### 2. HTTP Ownership And Generated Contracts

- Keep exactly five HTTP OpenAPI sources for control, authority, ingress, relay,
  and route usage.
- Generate models, clients, and strict server interfaces under `pkg/api/*`.
- Make authority the sole owner of identity, team, membership, invitation,
  domain, authentication, and signed-authorization paths and models.
- Keep one control discovery response with the authority endpoint and
  authentication facts; remove authority capabilities.
- Add enrollment-token administration and public service enrollment to control.
- Reference only byte-identical schemas through `api/shared/v1/components.yaml`
  without generating a shared Go model package.

### 3. Tunnel Contract

- Keep `pkg/protocol/tunnelv1` handwritten as the only source of truth.
- Remove `api/tunnel/v1`, schema synchronization, and schema-parity tests.
- Add golden JSON and wire fixtures, invalid fixtures, bounds and truncation
  coverage, decoder fuzzing, and shared QUIC/yamux behavior tests.
- Retain separate internal-forwarding and publisher visitor-stream headers with
  no relay peer role or multi-hop forwarding field.

### 4. PostgreSQL Model

- Add relay services, relay leases, ingress leases, publisher connections, and
  ingress routing-table state.
- Constrain slots to `0..1` and assignments to distinct relay services.
- Add atomic process claims and service-level capacity calculations.
- Move usage ownership to ingress and complete usage ingestion and delivery.
- Correct recovery episode creation and cancellation.
- Add the transactionally initialized service CA, reusable enrollment-token
  digests and audit state, and relay-service transport certificate material.
- Regenerate control-state code from SQL sources.

### 5. Enrollment And Internal Service APIs

- Add separate ingress and relay handlers and listeners.
- Implement enrollment-token create, list, revoke, and service enrollment.
- Generate process-local service keys, issue one-hour certificates, re-enroll
  around thirty minutes, and fail readiness when certificates expire.
- Enforce role-specific service mTLS in both directions.
- Implement exact lease and publisher-connection stale-state checks.
- Add cross-role rejection tests.

### 6. Runtime Roles

- Move routing-table ownership into ingress.
- Implement concrete relay-process claims and local publisher registries.
- Implement authenticated internal forwarding from ingress to relay.
- Preserve one PROXY v2 metadata header, retry-boundary behavior, usage once,
  and recovery once.
- Delete the replaced mesh and global-routing behavior from relay.

### 7. Process Composition And Scaling

- Add explicit control, ingress, relay, and standalone startup paths.
- Implement independent readiness and graceful draining.
- Implement multiple relay processes per relay service.
- Compose two logical relay services in standalone.
- Derive all public role hostnames from the server domain and use the fixed
  ingress and relay control API ports.
- Obtain the public control certificate automatically and distribute
  service-CA relay transport material through enrollment.

### 8. Deployment And Documentation

- Update split deployment to at least two control processes, two ingress
  processes, and two relay services.
- Give relay services stable public addresses and relay processes concrete
  internal addresses.
- Keep PostgreSQL credentials out of ingress and relay environments.
- Reduce each mode to its documented minimal settings and remove static service
  mTLS and required standalone certificate files.
- Update local, standalone, self-hosted, observability, and benchmark guidance.
- Change publisher-connection capacity formulas from division by three to
  division by two.

### 9. Verification

- Test two-connection placement across distinct relay services.
- Test atomic claims by multiple relay processes in one service.
- Test per-process and aggregate service capacity.
- Test ingress and relay process scaling and draining.
- Test individual relay-process and complete relay-service failures.
- Test route-version preservation, temporary zero-connection unroutability,
  TLS-ALPN-01, stale-state rejection, one PROXY header, usage once, and recovery
  once.
- Test reusable token enrollment across replicas, relay-service scope,
  revocation, cross-role rejection, certificate renewal, and expiration.
- Assert that exactly five HTTP OpenAPI sources and no tunnel JSON Schemas or
  active gateway configuration remain.
- Run a real-process topology with PostgreSQL, two controls, two ingress
  processes, two relay services, publisher, and visitor.

## Verification Commands

Run the repository sequence from the root:

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

`task generate-check` runs generation before checking the generated-directory
diff. Until the existing generated migration work is committed, evaluate its
generation results separately from the expected final dirty-tree failure.

Do not execute a Fly benchmark without its separate approval and environment
gates.

## Completion Criteria

The rearchitecture is complete when:

- Control, ingress, and relay services scale independently.
- Split deployments have at least two independent relay services and allow any
  number of relay processes in each.
- Every route session maintains two publisher connections assigned to distinct
  relay services.
- Concrete relay processes claim publisher connections atomically.
- Ingress routing identifies exact connected relay processes.
- Individual process and complete service failure tests pass.
- Publisher reconnection does not change the route session or route version.
- QUIC and TLS/TCP with yamux satisfy the same publisher-connection contract.
- Relay-to-relay forwarding and all replaced runtime terminology are absent.
- Ingress and relay processes have no direct durable-state access.
- The public recovery SLI is durable and observed once per episode.
- The complete verification sequence passes.
- Standalone starts from the documented minimum settings without certificate
  files, and control obtains and renews its public ACME certificate.
- Three scoped enrollment tokens support arbitrary ingress replicas and two
  independently scalable relay services.
- Expired service certificates make processes unready and unable to renew
  leases; revoked and cross-role tokens cannot enroll.
- Exactly five HTTP OpenAPI sources generate `pkg/api/*`, and handwritten
  `pkg/protocol/tunnelv1` is the only tunnel contract.
- No active gateway API, package, configuration, or behavior remains.
