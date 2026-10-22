# control-state invariants

Audience: tnl maintainers working on `internal/controlstate`, routing
publication, usage aggregation, or recovery. Product and operator documentation
does not depend on these implementation details.

## start from a fresh baseline

The current baseline requires a fresh PostgreSQL database and a coordinated
stop/start of control, ingress, and relay roles. `tnld migrate` uses the direct
database URL. Serving processes require the exact embedded migration version
and the stored baseline identity; another version-1 database cannot be reused.
Later compatible changes must add schema before switching serving code to it.

The baseline creates ingress pools before teams and public URLs. It seeds
`ingress-a` disabled until the operator verifies its addresses and ports. A
team's ingress pool is pinned while it owns saved public URLs; each new URL
inherits that pool. Private services use authenticated ingress assignments,
not service-specific public TCP ports or port claims.

Public and private publisher connection slots share
`control.publisher_service_connection_slots`. The typed
`control.publish_run_connection_slots` and
`control.private_service_connection_slots` views enforce their service-kind
boundaries on reads and writes. A slot keeps its `id` and
`(run_id, connection_slot)` identity when its assignment is replaced;
`publisher_connection_id` changes. Trigger-maintained relay-service reservations
count open, assigned slots and use an advisory guard during placement. Historical
process-run IDs do not require live ingress or relay lease rows.

Control stores the guest retry key in `control.guest_retry_keys` and the visitor
network hash key in `control.visitor_network_hash_keys`. Both are encrypted with
the storage key and must participate in key rotation. IP-policy and request
digests elsewhere retain their own ciphertext and storage-key IDs.

storage-key rotation claims every recoverable encrypted row, including visitor
IP grants, device logins, browser login verifiers, handoffs, and session tokens.
expired or revoked rows still participate while stored. both browser session
tokens rotate together because they share one key ID. the completion count
includes locked rows, so a skipped claim cannot report that the old key is safe
to remove. test the underlying grant or credential after removing the old key;
reading a public URL's encrypted policy projection alone is insufficient.

Applied projects store the source fingerprint, expected/current revision,
encrypted normalized configuration, group scopes, and service assignments.
Enrollment stores group membership and public signing keys; private signing
keys stay with each member. Group leases permit only assigned configuration
reads and exact-revision acknowledgements. Applying local declarations retains
metadata without allocating shared worktree URLs. Named group services use
publisher pools with independent member runs. See
[applied project boundaries](applied-projects.md).

Management audit facts commit with the mutation they describe. Visitor
observations arrive in bounded, authenticated batches from ingress or an exact
publisher run and are independently deduplicated. The service-audit clock
preserves cursor commit order. A process crash can lose queued visitor
observations; this does not undo a committed management fact or relax an
authorization decision.

`CleanupWorkloads` owns workload assertion deletion and its 30-day history
retention after assertion expiry. `ExpireVisitorPermissions` expires browser
permissions and IP grants without pruning workload replay fences. run both
workers when checking retention: current credentials, retained assertions, and
dependent visitor records must continue to pin their workload session.

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

signed company-owner operations take the existing identity-bootstrap guard
before the team advisory guard and team row, including membership decisions.
signed service managers use that same team advisory-before-row order even when
their entry point already holds identity bootstrap. ordinary control-session
apply does not take identity bootstrap and can overlap work on another team.

apply and explicit publisher revocation choose their complete parent set under
the team guard: private service IDs in order, then public URL IDs in order.
apply includes named group services and existing local worktree realizations.
publisher revocation locks its affected parents before locking the publisher
identity; heartbeats already hold the public URL and run when checking that
identity. new grants, runs, and realizations cannot extend these sets while the
team guard is held.

acquire those parent locks before the first mutation, including mutations whose
triggers append audit facts. run closure and audit/routing publication must not
leave a later service parent to lock: expiration can own that parent while
waiting for the same audit or routing clock. unrelated service parents remain
unlocked. new service rows belong only to the creating transaction.

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

## publish member namespace dns

For a member public URL one label beneath a managed or custom namespace,
control's DNS worker ensures an A/AAAA wildcard at `*.member.example` rather
than exact address and `_tnl-owner` records for each public URL. One
`_tnl-wildcard.member.example` TXT record identifies the namespace wildcard;
it does not create a DNS node beneath a service hostname. The existing per-URL
DNS work still advances from `pending` to `published` after authoritative
nameservers confirm the wildcard. A publish run waits for that state before
becoming ready. Ingress still requires an exact saved public URL hostname.

The wildcard belongs to the member namespace. Deleting or suspending one
public URL advances its DNS work to `removed` without deleting that shared
record. On custom-domain release, control removes its owned namespace
wildcards before deleting the Route 53 zone. Member namespace apexes and
shared public URLs retain exact-name DNS. Old exact A/AAAA and `_tnl-owner`
records can coexist with the wildcard until they are removed together; an
owner TXT without the exact address record prevents wildcard resolution for
that hostname.

Route 53 lists a wildcard label as `\052`, not `*`. Normalize that name when
comparing listed records or pagination cursors, while retaining the returned
record set for an exact delete during custom-domain release.

For every DNS-managed public URL, publish run readiness waits for the DNS
worker's authoritative verification. `tnl publish --open` also
wait up to two minutes for the local resolver before opening a browser. URLs
whose DNS tnl does not manage do not wait for this verification.

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

Publisher certificate issuance uses DNS-01 only. Control reconciles the owned
TXT values under a record lock, waits for the provider change and authoritative
DNS verification, then asks the CA to validate. Ingress routing and publisher
connections have no certificate-challenge path. Each publisher keeps its own
private key; a saved-URL grant receives an exact-host certificate plan.

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
any one of them. The worker changes DNS authorizations from `presenting` to
`presented` after the provider write and verifies propagation before acceptance.

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
