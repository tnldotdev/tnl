# publisher egress observation

control saves the source address of each explicitly started remote publisher
runtime. `tnl publisher list` shows its latest evidence and lease status;
`tnl status --scope=server` includes the same record for each named-group replica.
the control API exposes it as `PublisherIdentity.runtime` and
`PublisherGroupMemberStatus.runtime`, behind their existing team and management
authorization. it is absent before a runtime has started.

## runtime ownership

`Runtime` in `internal/publisher/group` owns one observation for all of a replica's
assigned services. its existing lease-renewal loop calls the runtime interface;
control issues the group access lease in the same transaction as the observation.
the runtime joins its service workers before sending stop.

`Engine` in `internal/client/supervisor` owns the lifecycle for an installed non-group job,
whether supervised as a user or system service. its worker retains one runtime
owner across publication retries. the public URL and service heartbeat
adapters refresh that owner's observation after a successful authenticated
publication heartbeat. there is no additional heartbeat scheduler.

credential-scoped foreground `tnl publish` invocations also start this lifecycle
after preflight, including portable publisher files and exact service
grants. ordinary app-owned local publishers do not opt in. neither `installed`
identity kind nor team ownership identifies a process as remote: those properties
also occur in local setup. the actual runtime entrypoint calls the explicit
interface.

each independently running replica or installed job needs its own publisher
identity. a named-group replica may carry many services under its one identity.
the installed registry rejects assigning one identity to two independent jobs.
starting a replacement with the same identity advances its epoch and fences the
old owner; it does not create another replica.

provisioning, enrollment redemption, signing-key import, token exchange and
`/v1/publisher-groups/verify` never write observations. the older signed group
lease acquisition used by preflight still rotates its group token, but it cannot
change runtime evidence or the runtime epoch. only the actual runtime start and
renew paths record a source. selector and DNS namespace renames preserve the
record because it belongs to the immutable publisher identity and team.

## signed lifecycle contract

`POST /v1/publisher-runtime` accepts `publisher_identity_id`, `scope_id`,
`process_run_id`, `expected_epoch`, `action` and `assertion`. the scope is the
immutable group ID for a group replica or an exact live publisher grant ID for a
non-group runtime. it accepts no address claim.

the process generates a random 128-bit lowercase hexadecimal `process_run_id`.
its Ed25519 assertion uses the control URL plus `/v1/publisher-runtime` as the
audience and the following grant claim:

```text
runtime:<lowercase hex SHA-256 of:
  "tnl publisher runtime v1\0" + scope_id + "\0" + action + "\0" +
  process_run_id + "\0" + decimal(expected_epoch)>
```

`RuntimeScope` in `internal/security/publisherproof` owns this encoding. the existing
one-use assertion ledger rejects replay; a verification or publication assertion
cannot authorize a runtime action or be rebound to another run or epoch.

1. **inspect** authenticates the scope and reads its current epoch (zero before
   first start). it records no source and creates no runtime lease.
2. **start** compares that epoch under the identity/team transaction guard and
   advances it once. the runtime retains its expected epoch and run ID across a
   lost response. a retry uses a fresh assertion and returns the original run
   without replacing its observation or extending its lease.
3. **renew** authenticates the same key, scope, run ID and current epoch, updates
   the observation, and extends the two-minute lease. expiry makes status offline;
   the same still-current process may renew after a temporary outage. a stopped
   or replaced process cannot renew.
4. **stop** fences the same run and epoch, ends the lease and retains the last
   address and observation time. a stop retry is idempotent. a crash requires no
   cleanup write: status becomes offline when the lease expires.

clients do not inspect again after a confirmed start or a stale-epoch rejection.
an old owner cannot acquire a new epoch through automatic retries. authentication
failure rolls back the transaction, including any pending observation write.
possession of the long-lived signing key still permits an operator to start a
new runtime deliberately; this is process fencing, not proof of a physical host.

## evidence and storage

`control.publisher_runtimes` holds one bounded current/last record per publisher,
with the immutable team, signing key, scope, random process ID, epoch, address,
address family, `control_observed` evidence, start/observation/last-seen times,
lease expiry and optional stop time. renewals update that row. there is no
heartbeat history table. a new start replaces the previous run's evidence.

the fresh baseline adds this table and changes the exact baseline identity. the
earlier publisher identity and group lease tables had no process ID or current
epoch; their identity kind, key and short-lived group token were insufficient to
distinguish startup from operator preflight or to fence a replaced process.
the existing tables retain their roles; runtime ownership lives in the new table.

control reads the socket source in `RemoteAddr`. when `internal/control/proxy` is
installed, that middleware first validates the configured trusted peer, exact
external host, HTTPS metadata and one overwritten source header, then replaces
`RemoteAddr`. the observation handler never reads forwarding headers directly.

addresses are canonical hosts, never CIDRs. IPv4-mapped IPv6 becomes IPv4.
private, loopback, link-local, multicast, unspecified, documentation and reserved
sources produce `address_family: unknown` with no `address`. this is a successful
runtime observation and preserves local workflows. a renewal from such a source
clears an earlier public address rather than presenting it as current evidence.
only the family actually seen is reported.

`active` requires the current runtime lease and current identity, key, team and
scope authority. a group runtime must use its member's enrolled key. a non-group
runtime requires an available saved public URL, service or namespace,
including a ready domain when the resource has one. disabling or deleting the
resource or releasing its domain makes status offline even if the grant remains
live. suspending a creator's membership does not revoke a team-owned publisher.
the final address remains visible after stop, expiry or revocation, with its
timestamps and offline state. no observation is browser-safe project metadata,
a credential, or a visitor-access grant.

## future database allowlists

this supplies evidence for future PlanetScale or Neon egress allowlisting; it
does not change either provider or implement allowlist synchronization. the
address control sees may differ from the address a database sees because of
destination routing, IPv4/IPv6 selection, NAT or a proxy. an active observation
is not a promise of a permanent static address. future allowlisting must account
for that boundary and must not treat expired evidence as access authority.

## checks

`task go:test:integration:publisher-egress` uses digest-pinned disposable
PostgreSQL. it covers signed group and installed lifecycles, the actual trusted
proxy middleware, spoofed headers, operator preflight, NAT changes, restart
fencing, revocation and authorized status. fixture public addresses are parsed
as data; tests never dial a public IP service. routine runtime/engine tests cover
lost startup replies, retained retry identity, native heartbeat wiring and boot
replacement. the installed group supervisor blocks on a stale-runtime HTTP 409
without inspecting or starting a replacement. Linux CLI workflows check actual
foreground, group and installed-supervisor observations, including orderly stop
and provisioning without an observation.
