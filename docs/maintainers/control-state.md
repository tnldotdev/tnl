# control-state invariants

Audience: tnl maintainers working on `internal/controlstate`, routing
publication, usage aggregation, or recovery. Product and operator documentation
does not depend on these implementation details.

## keep migrations backward compatible

`tnld migrate` applies migrations through the direct database URL before the
new control release rolls out. Each migration must preserve the reads and
writes of control and standalone processes still serving traffic. Add new
schema first; remove old schema only after all its users have been replaced.
The runtime checks a minimum schema version and accepts newer versions; an
older `tnld migrate` still rejects databases newer than its embedded migrations.
Runtime v4 also accepts v3 because the v4 migration only changes an index.

## acquire locks in one order

Every transaction must choose its complete lock order before it starts taking
locks. Lock mode and lock order are separate decisions.

```text
affected routes
      |
      v
assignment-total guard
      |
      v
relay-service guards
      |
      v
lease rows
      |
      v
routing publication
```

Shared-parent guards document the invariant they protect, conflicting work,
allowed concurrency, and transaction lifetime next to their SQL.

Session creation shares the team authorization guard before locking its route.
Authority mutations take a conflicting guard. A keyed transaction advisory lock
comes before the team row so new readers cannot starve a waiting authority
writer.

Publisher-connection claim and readiness operations share a keyed advisory guard
and relay-service row guard. Claims use `NO KEY UPDATE` on the selected relay
lease to serialize capacity checks. Readiness uses compatible `KEY SHARE`
because the connection already consumes capacity.

Readiness retains the service guard through routing publication. Process
registration cannot cross that boundary, while claims and renewal can continue.
Drain may overlap readiness; each statement uses its current database view.

Blocking service writers queue before taking service and lease row locks.
Maintenance using `SKIP LOCKED` remains opportunistic and must not wait for a
service guard after acquiring a row.

Concurrency tests must show both sides of the contract: conflicting work waits,
and unrelated work finishes while a controlled blocker remains held.

## maintain reservation totals

PostgreSQL triggers maintain relay-service reservation totals. Counted
assignments belong to open sessions and have state `assigned`, `connected`,
`ready`, or `draining`.

An eligibility foreign key propagates session closure to assignments. Placement
reads the totals together with capacity from eligible relay leases.

Transactions that change reservations lock their complete affected route set,
then take the assignment-total guard, service guards, and lease locks. Trigger
updates use the same guard. Claim and readiness transitions with no count change
avoid the counter write and guard.

Recovery can replace a failed ready connection inside the same relay service
without releasing its reservation. The statement checks the failed lease and
current capacity while route and session guards protect the slot. A later claim
still verifies the exact current process, lease, and capacity.

Unavailable or full services, closed or expired slots, and service changes use
the full guarded placement path. Routing publication remains the final
transaction phase.

## publish routing revisions in commit order

For one event, insertion acquires the routing clock before allocating the
revision in the same SQL command. A multi-event publication acquires the clock
before its first insertion.

Both retain the clock through commit. Revision visibility therefore follows
commit order without another round trip in the common single-event path.

Session operations use `NO KEY UPDATE` route guards. Route identity is
immutable, and usage's `KEY SHARE` references can coexist with heartbeats. Public URL
mutations still conflict.

## retain routing history safely

Control publishes a monotonic retained-after revision before deleting routing
history. An incremental reader below this floor must request a new snapshot. A
reader at the floor can consume the complete later suffix.

Cleanup keeps:

- every recent committed event, even when timestamps are out of revision order;
- the latest event for each hostname and route or challenge category;
- tombstones and expired latest events;
- each publish run number's latest event for entry-revision continuity.

Selecting the latest event before filtering its kind or expiration prevents an
older route or challenge from reappearing.

The floor update commits separately from deletion batches. Each batch visits at
most 1,000 candidates and takes only a cleanup-specific nonblocking advisory
lock. It does not take the publication clock or route and placement guards.

Concurrent publication can make an anchor unnecessary, but cannot make a
superseded event current again. Failed batches retain their scan cursor. Sweeps
advance past anchors even when a batch deletes nothing.

## process usage in stable order

Usage pages hold ingress and process-run guards while prefetching bounded latest
report metadata. Reports are processed in route, version, bucket, and revision
order.

Page-local history advances after each successful fresh report. Multiple
revisions for one key therefore preserve cumulative and replay behavior.
Histogram payloads are loaded only for an exact replay or for the aggregate
being updated.

Fresh usage combines its route reference and session guards in one statement,
with the route guard materialized first. The later bucket read can see a bucket
created by another ingress while the session lock was waiting.

The immutable report insertion, aggregate delta, and optional session denial
update use one dependent write statement. A rejected write rolls back the whole
page.

## coordinate certificate challenges

Before TLS-ALPN validation starts, control requires at least one live,
non-draining ingress. Every such ingress must acknowledge the latest challenge
projection for the order's publish run number.

Unrelated routing events do not move this barrier. Changes to the challenge's
own forwarding projection require a new acknowledgement. Selecting the latest
challenge event before checking kind and expiration prevents a tombstone or
expired challenge from exposing an older upsert.

Routing retention must preserve the current challenge event until it is safely
superseded.

## advance certificate work

`internal/controlstate` owns the saved order and authorization states. A worker
claims one order, advances it, and saves it only while its lease, work epoch,
and order revision still match. Each saved authorization has its own revision.
The Go state types name the same values that PostgreSQL stores.

Public URL certificate work has two stages that can advance independently:

| Work          | Progression                                                                                          | Other outcomes                      |
| ------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Order         | `pending` → `authorizing` → `ready_to_finalize` → `finalizing` → `waiting_for_install` → `installed` | `failed` or `canceled`              |
| Authorization | `presenting` → `presented` → `validating` → `valid` → `complete`                                     | `cleaning`, `failed`, or `canceled` |

An ACME response may skip or revisit the intermediate order stages. The worker
checks the complete authorization set before saving discovery. It presents all
pending challenges before checking propagation or asking the CA to validate
any one of them. Control changes TLS-ALPN authorizations from `presenting` to
`presented` only after publishing their challenge; the worker checks ingress
routing readiness again before accepting the challenge at the CA.

An issued public URL certificate becomes available at `waiting_for_install`,
even when DNS cleanup remains. For a DNS authorization, `valid` → `cleaning`
persists cleanup intent before the provider call; `cleaning` → `complete`
records its completion. A retry can repeat cleanup. Wildcard and exact-name
authorizations sharing one DNS name are reconciled together. Reused valid
authorizations with no new challenge start at `complete`.

Relay certificate work has one authorization per order. It advances through
`pending`, `authorizing`, `presenting`, `presented`, `validating`,
`ready_to_finalize`, and `finalizing`. Successful issuance enters `cleaning`
before `complete`; a failed issuance with a presented challenge enters
`failed_cleaning` before `failed`. Control installs relay transport material
only when the order reaches `complete`.
