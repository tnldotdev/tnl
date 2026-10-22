# applied project boundaries

apply stores evaluated declarations, not executable configuration. control owns
the normalized revision, encrypted target metadata, grants, and assignments;
publishers own target discovery and execution. public setup lives in
[configuration](https://tnl.dev/docs/configuration) and
[publisher groups](https://tnl.dev/docs/publisher-groups).

## local publication identity

local apps and named local publishers use directory-bound
`LocalPublicationIdentity`; Git initialization and origin changes do not replace
their service IDs or worktree key. `SourceIdentity` separately identifies portable
apply and workload declarations using the normalized Git origin and config path.
it identifies the configuration source, not a signed commit.

one local owner retains one evaluated configuration. discovery and named leases
compare its digest before reuse. competing owners serialize preparation for one
service; unrelated services prepare independently. an app restart cannot silently
reuse an owner's older policy. see
[`client/project`](../../../internal/client/project) and
[`publisher/app`](../../../internal/publisher/app).

registered, routable, and app-ready are distinct. an automatic checker runs once
per routable run until success or its two-minute budget ends. `checkService`
returns the ready observation accepted by `Manager.Observe` against its captured
registration, run, and target. later invalidation cannot undo acceptance or rearm
that budget. shutdown cancels and joins the checker; an explicit wait may check
again.

## service endpoint ownership

groups capture a durable namespace beneath the team's existing namespace. the
readable project label is captured at first apply, so branch and checkout paths
do not rename it. endpoints retain their hostname and allocated port when
reachability changes. changing the team's default domain does not rename a
captured endpoint.

selector rename retains the group ID, namespace, services, grants, and ports.
historical selectors remain bound to that group; display names do not grant
authority. explicit namespace rename closes old runs and replaces their publisher
grants and certificate plans in the same mutation transaction. a retry retains
the exact revision, request ID, and encrypted original response.

namespace and port reuse wait for real certificate expiry, uncertain issuance,
DNS removal, forwarding retirement, and quarantine. a live namespace cannot be
adopted by another project. moving between named groups retains the service ID
and visitor grants while replacing publisher authority. crossing the local/group
boundary retires the previous resources and grants; local IDs are then allocated
per worktree. see
[`project_ownership.go`](../../../internal/control/state/project_ownership.go),
[`publisher_namespace_rename.go`](../../../internal/control/state/publisher_namespace_rename.go),
and [`service_endpoints.go`](../../../internal/control/state/service_endpoints.go).

## apply and reconcile

expected revision protects concurrent edits. normalization determines the stored
hash before the mutation transaction reconciles services, visitor grants, and
publisher assignments. root OAuth and webhook declarations remain local runtime
intent; applying them neither allocates integration URLs nor makes them group
assignments. AWS layout settings do not enter assignment hashes.

group configuration owns endpoint reachability. a named HTTP service's `http`
settings narrow access and request limits; `public_url` belongs to local public
URLs. browser metadata keeps public URL IDs and service IDs distinct and omits
target trust. see
[`resolve/declaration.go`](../../../internal/client/project/resolve/declaration.go),
[`applied_project.go`](../../../internal/control/state/applied_project.go), and
[`applied_project_validation.go`](../../../internal/control/state/applied_project_validation.go).

each enrolled member has its own signing identity, runtime lease, grants, runs,
and connections. a group lease reads only that group's assignments. replacement
cancels and joins the old workers before starting the next revision.
acknowledgement binds the exact current revision/hash; observed revision is not a
visitor success measurement. removing a group or revoking a member invalidates
its authority in the same transaction. stopping infrastructure alone does not
revoke its identity. see [`publisher/group`](../../../internal/publisher/group).

## recover publisher certificates

portable identity restoration proves the signing key and current immutable
membership. invalid or revoked input cannot fall back to enrollment. identity
import updates the member document and sealed-key context atomically.

TLS keys belong to the durable identity directory, not runtime SQLite or its
wrapping key. each certificate record binds the exact control/team/publisher and
approved plan, pending CSR, staged/current material, issuance, and renewal time.
file and directory sync precede external issuance or installation.

the group publisher holds its durable writer lock for its entire lifetime.
certificate transactions lock that same replica-private filesystem. task-local
locks cannot fence a replacement process; a shared NFSv4 mount must retain advisory
lock semantics. retryable write/sync failures block new external work while a
valid installed certificate may continue serving.

control permanently records submitted certificate plans. once issuance starts,
missing durable material fails closed instead of generating replacement keys.
recovered work may find its original order only within the same publisher,
account, domain, and exact plan. every new run still acknowledges its own
installation. a signing identity alone is not certificate recovery. see
[`client/state`](../../../internal/client/state),
[`certificate_work.go`](../../../internal/control/state/certificate_work.go), and
[publisher groups](../publisher/publisher-groups.md).
