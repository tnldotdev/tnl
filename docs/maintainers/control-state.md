# control-state invariants

Audience: tnl maintainers working on `internal/controlstate`, routing
publication, usage aggregation, or recovery. Product and operator documentation
does not depend on these implementation details.

## start from the baseline, then keep migrations compatible

The current baseline is for fresh databases; old staging and production schemas
must be reset before installing it. `tnld migrate` applies that baseline through
the direct database URL. For later changes, preserve the reads and writes of
control and standalone processes still serving traffic: add schema before
switching its users, and remove old schema after those users stop. The runtime
checks a minimum schema version and accepts newer versions; an older
`tnld migrate` rejects databases newer than its embedded migrations.

`schemaVersion` tracks the newest embedded migration and changes when a migration
is added. `minimumSchemaVersion` tracks the oldest schema the serving code can
use safely; it advances only when runtime reads or writes need a newer migration.
The values can differ while an additive migration is not yet used by serving code.

The guest-domain change requires migration 11 because managed guest trials store
an empty DNS authority reference that the old constraint rejected. Email delivery
requires migration 12's queue table, including for storage-key rotation. The
authority cleanup requires migration 13's renamed guest retry-key columns.

Migration 18 prepares nullable browser preview references, the publish run's
`browser_capable` flag, and the team's `feedback_require_sign_in` policy. Both
flags default to false. Browser writers use nullable preview references for
URL-only sessions, and generated reads require schema 18. Deploy the migration
and compatible serving processes before enabling these writers or sign-in policy
enforcement.

The two publisher connection slots are stored in
`control.publish_run_connection_slots`. A slot keeps its `id` and
`(publish_run_id, connection_slot)` identity when its connection assignment is
replaced; `publisher_connection_id` changes with that assignment. Tables use
`id` as their primary key and retain natural lookup keys as unique constraints.
Foreign keys cover saved control-owned relationships, including publish run
usage and certificate orders. guest trials retain their own ownership IDs;
historical process-run IDs do not require current-lease rows.

Control seals the visitor-network hash master key with `TNLD_STORAGE_KEY` when
an ingress first registers. The encryption migration discards earlier usage
reports, buckets, deliveries, ingress usage runs, and the old plaintext key;
the next ingress registration creates a new key. Storage-key rotation also
re-encrypts this master key.

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

Browser admission and reviewer feedback writes share that keyed team guard before
locking a public URL, publish run, or feedback thread. Guest previews use the
same advisory guard without a local team row. Browser-session refresh happens
before admission and outside the team guard.

## separate browser identity from visit permission

`browserIdentity` validates the host's session scope, browser-session expiry
and revocation, and its saved OIDC control credential inside the caller's
transaction. It shares the browser session, control session, and identity rows
through commit, so logout, rotation, and identity disable cannot cross a write's
authorization boundary. Attribution uses the identity's current saved name,
not a publisher-supplied name or the browser session's older name snapshot.

A session without a preview is scoped to its initial public URL ID. A session
with a preview follows that preview's current included public URL IDs. Lookup,
refresh, logout, and handoff redemption apply the same scope. A URL-only identity
can participate in feedback on that URL while feedback retains its own preview
association.

`browserVisitAllowed` makes the separate visit decision from the enabled public
URL and current membership. A member public URL admits its owning membership;
a shared public URL admits current team admins and owners. Other members need
the session preview's current team access grant. Team administration alone does
not admit someone to another member's public URL. The control response calls
this decision `visit_allowed`; a signed-in
identity without that permission may still visit through IP policy or a share.

Browser admission and capability registration are limited to public URLs with
purpose `app`. The publisher registers `browser_capable` on its exact live run
before marking it ready, independently of shares or preview configuration.
Login handoffs fan out only to ready, unexpired, browser-capable app runs in the
session preview. Their encrypted credentials bind each ticket to the receiving
run ID and publish run number; redemption rechecks that run and session scope.
`share_capable` never supplies browser capability.

Publisher browser admission calls `BrowserAuthorizationForRun` after authority
refresh and identity reads. It locks team, public URL, and the exact publish run
before browser and control identity rows, then checks readiness, expiry, browser
capability, identity, and visit permission through commit. A run that stops or
is replaced during authority I/O cannot use the earlier capability preflight to
admit a visitor. `BrowserAuthorization` remains a URL-scoped datastore helper.

`reviewerAccess` in `reviewer_access.go` composes those decisions for feedback.
An allowed IP or current share admits a signed-in nonmember with verified
attribution. Identity alone never admits a reviewer. Report creation and event
writes revalidate these boundaries under their write transaction; no caller
membership flag participates in authorization.

## coordinate publisher connections

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
worker's authoritative verification. `tnl dev` and `tnl publish --open` also
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
