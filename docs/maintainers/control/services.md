# service boundaries

services and public URLs have separate saved records, credentials, and lifecycles.
every service captures a control-owned hostname, port, ready team domain, and
certificate plan. public reachability changes where DNS points; it does not
change the port or make access anonymous.

for commands and configuration, use the public [services](https://tnl.dev/docs/services),
[publisher groups](https://tnl.dev/docs/publisher-groups), and
[service access](https://tnl.dev/docs/service-access) guides. the contracts live in
[`api/control/public/v1`](../../../api/control/public/v1/openapi.yaml).

## select an exact service

local selection uses the directory-bound project and worktree realization.
applied selection uses the portable source fingerprint and configuration key.
a visitor read never realizes a service or applies configuration. friendly names
cannot adopt a resource from another project, worktree, or group.

inventory includes accessible offline services; it does not prove readiness.
visitor summaries omit publisher-only target trust and request limits, and remain
bounded even when services have large CA bundles. publisher setup reads the exact
management record before comparing target trust. see
[`local_project_services.go`](../../../internal/control/state/local_project_services.go),
[`serviceaccess`](../../../internal/control/api/serviceaccess), and
[`connector/selection.go`](../../../internal/connector/selection.go).

## publisher-to-target trust

visitor TLS and target TLS end at different boundaries. a service certificate
authenticates its visitor endpoint; `target.tls` independently selects the
publisher's verified target connection. omitting target TLS permits a plaintext
backend without disabling visitor TLS.

apply captures bounded CA material and its digest. installed jobs retain that
snapshot rather than reopening a user's file at boot. changing the hostname or
bundle needs a new approved declaration. preflight sends no application login or
request, never falls back to plaintext, and cannot replay protocol bytes.

PostgreSQL and MySQL negotiate target TLS using their native setup protocols;
they are not HTTPS probes. PostgreSQL channel binding cannot span the distinct
visitor and target TLS connections. CancelRequests lack a bound original visitor
subject and are refused; see [database cancellation](../publisher/database-cancellation.md).
SSH host keys and Kubernetes cluster authentication remain application-owned.
see [`targettransport`](../../../internal/transport/targettransport) and
[`targettrust`](../../../internal/security/targettrust).

## authenticate the publisher run

preparation reserves a run ID and number under the selected publisher grant and
captures its endpoint and certificate plan. start rechecks the exact publisher,
grant, key, and preparation. response-loss recovery retries that preparation;
a start retry rotates the run token while retaining connection assignments.
service-run tokens cannot authorize public URL publish runs.

local namespaces remain bound to membership, project source, and worktree.
group namespaces remain bound to the group across selector renames. changing a
team's default domain does not rename a captured endpoint. namespace and port
reuse must wait for certificate, DNS, and forwarding retirement. service
certificate issuance never creates a public URL as an intermediate record.

initial routability requires both assigned relay connections and an installed
certificate. afterward one ready connection can sustain service. zero live slots
demotes the run but retains its first-ready fact for recovery.

the relay reserves local ownership before claiming with control and holds it
through final disconnect. only the same connection, assignment revision,
credential, process run, and lease may recover a lost claim response. duplicate
handshakes cannot close the owner. public URL and service claims share process
capacity under the selected relay lease lock. see
[`service_run_preparation.go`](../../../internal/control/state/service_run_preparation.go),
[`service_runs.go`](../../../internal/control/state/service_runs.go), and
[`relay`](../../../internal/relay).

## authenticate the connector and each stream

a connector establishes two independently assigned ingress paths. its signed
hello binds the service, subject, and nonce. ingress claims that hello against its
current lease and captures the socket's source or verified PROXY metadata. SNI
and client-supplied addresses do not select a service or visitor source.

each application stream needs a current ready run and a separate admission.
ingress and publisher check the exact subject, session, service/run, source,
grant, and connection assignment. ingress emits PROXY v2 once, after the relay
acknowledges its assignment. connector-admitted streams do not request an
application client certificate. direct HTTP uses its signed visitor permission;
direct database clients use mTLS. application authorization remains independent.

assignment retries retain one idempotency key until the outcome is known. changed
requests conflict; expired, revoked, bound, or stale assignments cannot replay.
the encrypted retry result is covered by storage-key rotation and bounded
retention. see [`connector/stream`](../../../internal/connector/stream),
[`tunnelv1`](../../../pkg/protocol/tunnelv1), and
[`http_permission.go`](../../../internal/publisher/http_permission.go).

## retain current authorization

inventory, a connector session, and a previously accepted credential are not
ongoing authorization. ingress normally rechecks active streams every 30 seconds,
bounded by the applicable grant, run, infrastructure lease, certificate, and
two-minute maximum decision deadline. denial closes both ends; unavailable
control cannot extend the deadline. stream workers join before capacity is released.

direct HTTP application requests use the publisher's shared local permission
verifier and ten-second policy lease. ingress admission checks transport and run
capacity; it does not authorize the HTTP credential. policy renewal happens
outside request admission, and stale policy closes guarded requests.

session expiry prevents new streams while admitted streams drain under their
own authorization. replacement joins the old runner before reopening the
reserved local port. it never replays admitted application bytes. workload
renewal may shorten its fixed expiry but cannot extend it. see
[workload sessions](workload-sessions.md) and
[transport boundaries](../transport/architecture.md).

## keep ownership explicit

control owns service state and authorization. ingress and relay consume checked
contracts without importing persistence. publishers own target trust; connectors
never receive it. infrastructure transport certificates, visitor service
certificates, and target trust are distinct.

split deployment needs two distinct live ingress identities for initial
connector slots; standalone supplies two logical identities. the infrastructure
certificate binds the ingress process run and lease, and visitors verify its
hostname and authenticated pin. see [self-hosting](https://tnl.dev/docs/self-hosting)
for deployment setup and [test tiers](../../../contributing.md#choose-a-test-tier)
for the smallest real boundary check.
