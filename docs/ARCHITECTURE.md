# Architecture

This document describes runtime guarantees and the boundaries between packages
and APIs. See [Self-Hosting](SELF-HOSTING.md) for deployment settings and current
limitations. Each source contract documents its own wire fields. Use the
vocabulary in [AGENTS.md](../AGENTS.md).

## Processes And State

| Component                          | Owns                                                                       |
| ---------------------------------- | -------------------------------------------------------------------------- |
| `cmd/tnl`, `internal/publisher`    | Local tunnel lifecycle, publisher connections, and route TLS termination   |
| `cmd/tnld`, `internal/tnldruntime` | Server configuration, role composition, listeners, and shutdown            |
| Control                            | Stored state, placement, certificate coordination, and administration      |
| Ingress                            | Visitor acceptance, route policy, relay selection, usage, and forwarding   |
| Relay                              | Publisher connections and visitor streams for locally connected publishers |

A standalone `tnld` process composes control, ingress, and two logical relay
services against PostgreSQL. Split deployments run a control service, an ingress
service, and at least two independently addressable relay services.

Only control and standalone connect to PostgreSQL. `internal/controlstate`
changes persistent runtime state. Ingress receives a short-lived routing table.
Each relay knows only its own lease and the publishers connected to it.

The authority API manages identities, teams, memberships, invitations, domains,
authentication, and authorization decisions. Control or standalone can serve
the built-in authority, or use an external authority maintained outside this
repository.

`TNLD_SERVER_DOMAIN` is the infrastructure suffix for control, ingress, and relay
hostnames. It is independent of `TNLD_MANAGED_DEPLOYMENT_DOMAIN`, which supplies
public route namespaces.

## Database Lock Scope

Shared-parent guards in `internal/controlstate` document the invariant they
protect, required conflicts, allowed concurrency, and transaction lifetime next
to their SQL. Choose the lock mode for the whole transaction, including implicit
writes and foreign-key checks. Lock ordering and lock strength are separate
decisions.

Session creation shares the team authorization guard before locking its route;
authority mutations take a conflicting guard. These guards acquire a keyed
transaction advisory lock before the team row so incoming readers cannot starve
a waiting authority writer. Publisher-connection claims and
readiness similarly share a keyed transaction advisory guard and a relay-service
row guard. Claims use `NO KEY UPDATE` on the selected relay lease to serialize
capacity checks; readiness uses compatible `KEY SHARE` because the connection
already consumes capacity. Readiness retains the service guard through routing
publication, excluding process registration while allowing claims and renewal.
Drain may overlap readiness; lease validation and routing projection reads each
use their current statement view. Blocking service
writers queue exclusively before taking service and lease row locks. Maintenance
using `SKIP LOCKED` remains opportunistic and must not wait for a service guard
after acquiring its row.
Concurrency tests must prove both that conflicting operations wait and that
independent operations finish while a controlled blocker remains held.

Relay-service reservation totals are maintained transactionally by PostgreSQL
triggers. Counted assignments belong to open sessions and have state `assigned`,
`connected`, `ready`, or `draining`; an eligibility foreign key propagates session
closure to its assignments. Placement reads these totals while deriving current
capacity from eligible relay leases. Reservation-changing transactions acquire
the assignment-total advisory guard before service guards and lease locks, after
locking their complete affected route set. Trigger updates use the same guard;
zero-delta claim/readiness transitions avoid counter writes and that guard.
Recovery can atomically replace a failed ready connection in its existing relay
service without releasing its reservation. The statement checks failed lease
identity and current eligible capacity; route/session guards protect the slot,
and the zero-delta transition needs no reservation/service/lease locks. Concurrent
lease changes can invalidate the returned assignment, so claims still check the
exact current process identity, lease, and capacity. Unavailable or over-capacity
services, closed/expired slots, and service changes use guarded placement.
Routing publication remains the final transaction phase.
For a single event, its insert acquires the routing clock before allocating the
revision in the same SQL command. Multi-event publications acquire it before the
first insert. Both retain the clock through commit, preserving revision visibility
order without a separate round trip inside the common single-event clock window.

Session operations use `NO KEY UPDATE` route guards: the route identity is
immutable, and usage's `KEY SHARE` references must coexist with heartbeats.
Route mutations still conflict, while overlapping usage pages cannot starve a
heartbeat waiting for a stronger route-row lock.

Usage pages hold the ingress/run guards while prefetching bounded latest-report
metadata, then process reports in route/version/bucket/revision order. The
page-local history advances after each successful fresh report, so multiple
revisions of one key retain cumulative and replay semantics. Histogram payloads
are fetched only for exact replay or the aggregate being updated.

Fresh usage combines its route reference and session guards in one statement,
with the route guard materialized first. The bucket read remains a later statement
so it sees a bucket created by another ingress while the session lock was awaited.
The immutable report insert, aggregate delta, and optional session denial update
use one dependent write statement; rejected writes roll back the whole page.

## Routing History

Control publishes a monotonic retained-after revision before removing routing
history. Incremental readers below this boundary must resnapshot; a reader at
the boundary can consume the complete later suffix. Floor selection preserves
every recent committed event even when event timestamps are out of revision
order. Repeatable-read snapshots pair the clock with the same view of events.

Cleanup preserves the latest event for each hostname and route/challenge category,
including tombstones and expired entries, plus each route version's latest event
for entry-revision continuity. Choosing the latest event before filtering its
expiry or kind prevents an older route or challenge from reappearing.

The floor update commits separately from bounded deletion batches. Each batch
visits at most 1,000 candidates and takes only a cleanup-specific, nonblocking
advisory lock; it does not take the publication clock or route/placement guards.
Concurrent publications can make an anchor redundant but cannot make an already
superseded event current. Failed batches retain their scan cursor for retry,
and sweeps advance past anchors even when no rows can be deleted.

## Connections And Trust

Publishers maintain two connections through different relay services. A route
version becomes routable after its certificate is installed and both connections
are ready. It can then remain routable with one connection while the publisher
replaces the other.

Before starting TLS-ALPN validation, control requires at least one live,
non-draining ingress and acknowledgement from every such ingress of the latest
challenge projection for the order's route version. Unrelated routing publications
do not move that barrier. The latest challenge event is selected before checking
its kind and expiration, so a tombstone or expired projection cannot expose an
older upsert. Changes to the challenge's own forwarding projection require fresh
acknowledgement; routing retention preserves the current challenge event.

Publishers try QUIC first. After a short delay, they also try TLS/TCP with yamux
and use the first transport accepted by the relay. Control manages the relay
transport certificates. Publishers verify those certificates with system trust
roots. Relays authenticate publishers with short-lived publisher connection
credentials.

The visitor path is `visitor -> ingress -> relay -> publisher -> local service`.
Ingress creates exactly one PROXY v2 metadata header. Relay preserves that
header and route TLS bytes unchanged; route TLS terminates at the publisher.
Ingress may try another relay before sending the first visitor byte, never
afterward. Live visitor connections are not replayed or migrated.

Split ingress and relay processes use `TNLD_CLUSTER_SECRET` to authenticate to
control. Requests are accepted only while the process run ID and lease revision
match the current lease. Standalone calls the same operations in process and
does not use a cluster secret.

The standalone adapters implement controller operations without HTTP
authentication or request editors. Role controllers receive API errors rather
than database-specific errors.

Control and standalone using the built-in authority require a login token. An
external authority instead requires an authority endpoint, OIDC configuration,
and the hosted secret shared with control. Control and standalone obtain public
control certificates through ACME unless static certificates are configured.
Only these roles receive the storage key, PostgreSQL credentials, DNS
credentials, or ACME account keys. A relay can retrieve its relay transport
certificate and private key while its lease is current. It keeps them only in
memory.

## API Ownership

| Source contract                                   | Implementer                                   | Caller and authentication                                                                             |
| ------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [Control](../api/control/v1/openapi.yaml)         | `internal/controlapi` on control              | CLI/publisher; access or route-session credential according to operation                              |
| [Authority](../api/authority/v1/openapi.yaml)     | `internal/authorityapi` or external authority | CLI login/session and team/domain operations; control uses the hosted secret for hosted authorization |
| [Ingress](../api/ingress/v1/openapi.yaml)         | `internal/ingressapi` on control              | Ingress; cluster authentication, or standalone direct calls                                           |
| [Relay](../api/relay/v1/openapi.yaml)             | `internal/relayapi` on control                | Relay; cluster authentication, or standalone direct calls                                             |
| [Route usage](../api/route-usage/v1/openapi.yaml) | External receiver                             | Control's `internal/routeusageworker`; configured receiver bearer token                               |

OpenAPI describes the wire contract. It does not guarantee that every reserved
operation is implemented; see the self-hosting capability table. Shared OpenAPI
components contain only identical referenced schemas and do not generate a Go
package.

`pkg/protocol/tunnelv1` is the handwritten tunnel protocol source of truth.
`internal/muxsession` provides multiplexed byte streams. `internal/tunnel`
implements handshakes and acknowledgments. `internal/streamcopy` copies bytes in
both directions. Test the protocol with golden JSON and wire frames, invalid and
size-bound cases, fuzzing, and shared transport tests. Do not add a separate
tunnel schema.

## Local Package Boundaries

| Package                  | Responsibility                                                                           |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| `internal/config`        | Serialized configuration and schema validation                                           |
| `internal/projectconfig` | Discovery, trusted TypeScript evaluation, worktrees, and effective service configuration |
| `internal/tnldconfig`    | Server-role configuration and environment resolution                                     |
| `internal/clientstate`   | Client SQLite state and local ownership locks                                            |
| `internal/projectmeta`   | Generated project metadata and TypeScript augmentation                                   |
| `internal/clioutput`     | Shared ASCII rendering; command handlers provide semantic content only                   |
| `packages/tnl`           | Browser-safe project runtime and Node-only framework integrations                        |

The npm public subpaths are the root, `/config`, `/next`, and `/vite`. The private
development socket is shipped implementation, not a public extension API.
During development, framework integrations load project metadata and connect to
the matching `tnl dev` process through explicit setup or socket discovery. They
do nothing during builds and previews. Never expose access tokens to child
development processes or browser metadata.

Keep each role's lifecycle, retry, and authorization rules with that role. Share
reusable mechanics and identical contracts, not code that only looks similar.
Generation and verification instructions belong in [Contributing](../CONTRIBUTING.md).
