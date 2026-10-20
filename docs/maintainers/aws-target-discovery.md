# publisher aws target discovery

`internal/targetdiscovery` resolves an assigned EKS or RDS selector inside the
publisher. `tnl apply` stores the declaration without calling AWS. The publisher
uses the normal AWS credential chain, including an ECS task role, and needs
network access to AWS APIs and the selected private endpoint.

Discovery returns a DNS address and verified TLS trust for a **new** target
connection. It never stores an IP answer, reconnects an admitted database
connection, replays a query, or reads database/Kubernetes credentials.

## resolve an assigned selector

The reusable boundary is independent of control's generated descriptor:

```go
request := targetdiscovery.Request{
    Type: "rds", Region: "us-east-1", Instance: "orders", Protocol: "postgres",
}
resolver, err := targetdiscovery.New(nil, targetdiscovery.Options{})
if err != nil { return err }
defer resolver.Close()
prepared, err := resolver.Prepare(ctx, request)
if err != nil { return err }
address, verifier, err := prepared.ResolveTarget(ctx)
```

`New(nil, ...)` selects the AWS SDK implementation. Tests can supply a `Provider`
with `Discover(context.Context, Request) (ResolvedTarget, error)` or an `AWS`
with an injected `LoadClients`. Production `Load` disables SDK service endpoint
overrides and raw SDK logging, retrieves credentials through the normal chain,
and limits metadata responses to 1 MiB before SDK deserialization. Each lookup
checks the credential account with STS and compares the returned resource ARN's
partition, region, account, service and selector. Optional `Request.Account`
additionally requires an exact declared account.

`FromServiceTarget(config.ServiceTarget, config.ProtocolName)` projects the
generation-123 source configuration into the same request without AWS I/O.
The only selected fields are `Type`, `Region`, `Cluster`, `Instance`, `Endpoint`,
and `Protocol`; an address, static TLS override, or local discovery field is
rejected. `Endpoint` defaults to `writer`; `reader` is valid only for an RDS
cluster. Endpoint choice does not grant database read permissions.

## consume the assigned control descriptor

Foreground and installed groups both enter `servePublisherGroup` in
`cmd/tnl/publisher_group.go`. It owns one shared resolver for the group lifetime
and closes it after `Runtime.Serve` has joined every assignment worker. Creating
the resolver does not load credentials or call AWS.

`publisherjob.GroupPublisher.Publish` is their common production callback. It
reads the exact service through the native publisher grant, compares the saved
service ID, protocol and trust revision with the assignment, and then selects
static-target publication or cloud preparation.

`grouppublisher.AssignmentDiscovery` projects the typed
`ProjectServiceConfiguration.TargetDiscovery` fields and assignment protocol
into `Request`. It rejects mixed address/static trust, local publisher settings,
empty selectors and incompatible protocols before discovery. The saved
`PrivateService` exposes protocol and trust revision, not another descriptor;
the authenticated group assignment owns the exact cloud selector. No project
checkout is evaluated on the publisher machine.

Cloud runs call `grouppublisher.PublishCloudAssignment` with that request and
their native control client, identity, state, metadata and readiness observer.
The control/authority transport uses the job's selected control CA; discovered
target trust remains independent of that transport and managed visitor TLS.

`PrepareCloudAssignment` is the equivalent thin adapter when the caller needs
to inspect the resulting `RunConfig` before calling `privatepublisher.Publish`.
It installs `Target` and `TargetResolver`, and selects privatepublisher's default
health check so every check includes discovery freshness and native target TLS.
Do not send this cloud run through `publisherjob.PublishPrivate`'s static-target
preflight: its job has neither the cloud descriptor nor its discovered trust.

`privatepublisher.TargetResolver` is a pure interface:

```go
ResolveTarget(context.Context) (string, *tls.Config, error)
```

The private publisher consumes it before preparation, on health checks, and
before a new managed visitor stream captures its target. An error prevents new
target connections and makes normal readiness checks fail. Existing streams
retain their captured address, TLS verifier and connection. A fenced publication
needs a fresh preparation; this adapter does not silently approve changed trust
or automatically restart active SQL sessions.

The Kubernetes transport receives the discovered verifier before validation;
it never evaluates `FromTrust(kubernetes, nil)` on this path. The same verified
snapshot is used by native preparation and new target captures. Changed
assignment definitions are joined before replacement workers prepare their own
publication; they do not reuse a different selector's resource pin.

## validate provider metadata

- EKS uses only `DescribeCluster` with the exact cluster name. It requires
  `ACTIVE` or `UPDATING`, a recognized authentication mode, an HTTPS origin
  without credentials/query/path, a DNS hostname, and bounded base64 CA data.
  Only CA certificates are accepted; the verifier uses those roots and the
  endpoint's exact TLS server name. The protocol must be `kubernetes`.
- RDS uses `DescribeDBInstances` or `DescribeDBClusters` with exactly one
  identifier. It rejects missing/multiple/paginated resources, invalid DNS
  endpoints or ports, and resources that are not available. PostgreSQL permits
  only `postgres` and `aurora-postgresql`; MySQL permits only `mysql` and
  `aurora-mysql`. DocumentDB and Neptune remain rejected even though the RDS
  Describe API can return them.
- RDS always uses the embedded official regional roots and the returned DNS
  hostname for TLS verification. PostgreSQL SSLRequest and MySQL server-first
  negotiation remain owned by `internal/targettransport`, not an HTTPS probe.

The discovery interfaces expose no Secrets Manager action, master user
credential read, database login, EKS token creation, resource mutation, or
resource enumeration. Backend Kubernetes/database authorization remains with
the native application credential presented by the visitor.

## pin identity and bound freshness

Each publication pins:

| target       | resource pin                                                           | trust pin                                                                         |
| ------------ | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| EKS          | exact ARN plus creation timestamp; regional EKS ARN/name can be reused | CA bytes' SHA-256                                                                 |
| RDS instance | exact ARN plus `DbiResourceId`                                         | regional root digest plus `CACertificateIdentifier`                               |
| RDS cluster  | exact ARN plus `DbClusterResourceId`                                   | regional root digest plus cluster `CertificateDetails.CAIdentifier`, when exposed |

Cluster Describe does not expose every Aurora member's CA identifier. The
cluster's approved trust is the pinned regional root set; ordinary leaf renewal
within that set does not change that trust. Discovery does not enumerate member
instances or assume additional member-Describe IAM grants. A member-specific CA
rotation qualification must account for this API boundary.

A changed resource/trust pin advances an internal mutation counter. Old
preparations remain fenced even if another lookup later observes the original
metadata again. A changed endpoint with the same resource and trust is captured
only by new connections; DNS is resolved by the normal network dialer each time.

Defaults are a one-minute metadata TTL, a five-minute maximum age since the last
successful lookup, a ten-second lookup deadline, a five-second failed-lookup
retry interval, and 128 distinct request entries/in-flight lookups. Options are
validated and capped at 1,024 entries, a five-minute TTL, fifteen-minute maximum
staleness and thirty-second deadline. Entries remain bounded for the resolver's
lifetime; capacity exhaustion fails closed. `Close` cancels and joins shared
work. One canceled waiter does not cancel other waiters' lookup.

Expired metadata is refreshed before capture. Only transient provider/network
unavailability can reuse a last success inside its freshness bound. Permission,
authentication, not-found, not-ready and malformed-metadata results immediately
block fallback; a later transient failure cannot resurrect that old target.
Only a successful response advances freshness. The SDK attempts at most twice
inside the shared lookup deadline.

## own rds roots and diagnostics

`internal/rdsroots` is the offline trust library. `source.pem` retains the
unmodified official global source; `bundles.json` records its URL, retrieval
time, SHA-256, and each regional selection's SHA-256. Tests check the source pin,
regional membership, certificate identity/signatures, validity horizon and
byte-identical membership in the official source. Preview/beta roots are never
selected. The current catalog covers the 36 commercial regions in that source;
an absent region fails closed instead of borrowing another region's roots.

To review an intentional root update from the repository root:

```console
mise exec -- go run ./internal/rdsroots/cmd/update
mise exec -- task go:test:target-discovery
```

The updater accepts no URL argument, fetches only the compiled official HTTPS
source, follows no redirects, and limits response size and time. It is never
part of runtime or routine generation. Review certificate changes and update
the source pin in `roots_test.go` with them. `NOTICE` and
`THIRD_PARTY_LICENSES.txt` attribute the public trust data and AWS SDK modules.

Owned errors retain typed SDK causes but format only authored text.
`ErrorKind` separates invalid selectors, denied access, authentication, missing
resources, not-ready resources, provider unavailability, invalid metadata,
changed pins and expired freshness. `FailureReason` supplies stable
`TNL_CLIENT_TARGET_DISCOVERY_*` diagnostics and retry guidance.

Discovery duration/outcomes and cache lookup health use only fixed AWS provider,
target type and protocol dimensions. The last-success timestamp describes the
target in the most recent lookup within that fixed class, not a per-resource
readiness guarantee. Resource ARN/ID correlation is trace-only; metrics never
include selectors, endpoints, AWS accounts, resource IDs or raw SDK text.

## qualify the boundary

```console
mise exec -- task go:test:target-discovery
mise exec -- task go:test:target-discovery:race
```

Routine fixtures verify real SDK SigV4 requests over local HTTPS, exact
selectors, JSON/XML parsing, engine rejection, metadata bounds, cancellation,
timeouts, cache coalescing, freshness and resource/CA fencing. The native
PostgreSQL fixture runs verified visitor and target TLS through privatepublisher,
changes a local DNS answer for new connections, and verifies that resource
replacement leaves an existing stream on its original connection.

The signed group-assignment fixture uses real control/authority clients, the
production callback, real SDK SigV4 HTTPS exchanges and verified EKS target TLS
preflight. It covers foreground and installed supervisor execution; separate
shutdown cases join an in-flight AWS request after cancellation. The fixture
stops at the first heartbeat rather than inventing a ready relay or certificate
issuer. Telemetry checks retain `kubernetes` within the fixed protocol budget.

Live AWS qualification still needs an approved account,
publisher task role and private network: exact-resource Describe allow/deny and
not-found checks; task-role refresh; EKS delete/recreate and CA change; RDS
instance/cluster writer and reader failover with real psql/mysql sessions; and
native authentication/authorization checks independent of discovery IAM. No
live IAM, cloud deployment or database access is exercised by these fixtures.
