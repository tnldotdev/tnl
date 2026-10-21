# private service boundaries

A service ID is separate from a public URL record. Every private service has a
control-owned hostname, port, ready team domain and certificate plan. Visitor
TLS is mandatory for local, app-led, ad-hoc and named-group publications.
Connector admission authenticates private visitors without application client
certificates; direct PostgreSQL/MySQL visitors require mTLS.

```yaml
version: 1
tnl:
  team: shop
  publishers:
    production:
      description: services in the production network
  services:
    orders:
      publisher: production
      protocol: postgres
      target:
        type: address
        address: orders.internal:5432
        tls:
          server_name: orders.internal
          ca_file: certs/database-ca.pem
      access:
        team: true
```

This service is saved as `orders`; `name: database` would save it as
`database`. The protocol defaults to `http`. `tcp` carries opaque bytes;
`mysql` and `postgres` select private database handling. An explicit
`publicURL` block is valid only for HTTP. Root public URL defaults never make
another service public. `local` is the reserved built-in publisher and the
service default; declared groups accept `description`, `domain`, and `public`.
See [applied projects](applied-projects.md) for remote group assignments.

For a configured local private service, `tnl connect orders` reads the exact
source-bound worktree realization from control, then selects only that immutable
ID in the caller's visitor inventory. A unique `name` override also selects the
same declaration. Local saved names are worktree-scoped; the CLI does not derive
them or adopt another project's friendly name. Start the app or `tnl publish
orders` first if the worktree has no realization. This visitor read never applies
configuration or realizes a service and requires ordinary visitor access.
Remote declarations resolve the exact applied source fingerprint and
configuration key through the visitor-safe project-service API. They never
adopt a similarly named service from another project or group, and they do not
need manager permission to read a target-free endpoint. An explicit service ID,
including with `--no-config`, continues to select from visitor inventory.

## connect with the service's approved protocol

```console
tnl connect orders
tnl connect orders --output=json
ssh -o 'ProxyCommand=tnl connect shell --stdio' alice@shell.production.example.com
```

`tnl connect NAME` checks the current identity's access, binds a loopback listener,
establishes two authenticated ingress paths, verifies the publisher's managed
TLS, then prints the local address and native client instructions. it stays alive
until stopped. public endpoint reachability does not change this sequence or
cause certificate export. HTTP, PostgreSQL, MySQL, opaque TCP, and Kubernetes
all use connector admission without application client certificates.

the default listener is `127.0.0.1` at the allocated service port. `--listen`
overrides its loopback address and port; `--detach` runs the same connector
independently of the terminal. neither changes the approved managed hostname,
port, or public setting. readiness negotiates managed TLS without an application
request, database login, or SQL query. opaque TCP uses tnl's verified TLS helper;
other native clients negotiate TLS through the connector themselves.

the local dial address and managed TLS identity are separate:

- curl uses an HTTPS URL with the approved managed hostname and allocated port, plus
  `--connect-to` to dial the actual loopback listener and `--noproxy` to bypass
  configured proxies for that hostname. human output labels this a `curl url`.
  HTTP requires the allocated port in its authority, even with a `--listen`
  override. browser use requires a connector on the allocated port and an exact
  local hosts-file mapping from the managed hostname to that connector's loopback
  IP, including for public services. tnl prints these prerequisites and does not
  edit DNS or hosts files. the JSON `url` remains the managed HTTP origin used
  with the printed curl arguments; `host` and `port` describe the local listener.
- PostgreSQL uses the managed `host` and local port with loopback `hostaddr`,
  `sslmode=verify-full`, `sslrootcert=system`, `gssencmode=disable`, and
  `channel_binding=disable` across publisher TLS termination.
- MySQL uses the managed hostname with `VERIFY_IDENTITY` and an explicit server
  CA bundle. the instructions require an exact `/etc/hosts` mapping from that
  name to the listener before running standard `mysql`. `--host=localhost`
  cannot verify a certificate for the managed hostname. tnl does not edit hosts
  files. roots come from `SSL_CERT_FILE` or a standard system PEM bundle.
- Kubernetes writes a loopback `server` and the managed `tls-server-name` to its
  owned kubeconfig context. the cluster bearer token remains independent of tnl
  connector admission.

`--output=json` prints a schema-1 ready connection profile and retains the
foreground listener. `host` and `port` identify the listener; `hostname` is the
approved TLS identity, `managed_port` is its allocated port, and `public` preserves endpoint reachability. profiles include
`connector_required: true`, `authentication: "connector"`, client command argv,
and protocol-specific instructions. detached profiles also include `detached_id`
for `tnl detached stop ID`. stdio rejects JSON output and listener lifecycle
options. `--protocol` is only an equality constraint against approved metadata.

There are no `connect profile` or `connect setup` subcommands, or certificate
opt-in flags. `profile` and `setup` are ordinary service names. For names that
collide with remaining commands (`start`, `available`, `list`, `stop`, `remove`),
use `tnl connect start NAME` or the service ID. Extra arguments never select a
different service silently. All modes use the same source-bound project lookup.

`inventory`, `profile`, and `setup` are ordinary service names. named publishers'
`publicURL` blocks configure managed HTTP policy and remain eligible for connect;
local public URL declarations use their separate public URL workflow.

opaque clients such as OpenSSH can use `tnl connect NAME --stdio` for one stream
through the same authenticated connector paths, without a listener. OpenSSH
still verifies the target host key and authenticates the target account.

Stdio stdout contains only application bytes. Diagnostics use stderr. Sign in
explicitly with `tnl auth login` (and the selected team when needed) before using
ProxyCommand; missing or expired authentication fails without reading SSH stdin
for login. Input EOF half-closes the upstream stream; remote EOF, cancellation
and a closed SSH output pipe join the copying workers and transport owners.
Neither metadata changes nor transport failures replay an admitted stdio stream.

## publisher-to-target trust

`target.tls` selects verified TLS from the publisher to its target. Managed
visitor TLS is a separate, mandatory boundary: the visitor verifies the managed
service hostname, while the publisher verifies the target certificate hostname.
Neither certificate substitutes for the other. The same target configuration
applies to local, named-group, ad-hoc, and installed publishers.

| Protocol   | Target negotiation with `target.tls`                                           |
| ---------- | ------------------------------------------------------------------------------ |
| `http`     | Direct TLS to an HTTPS origin                                                  |
| `tcp`      | Direct TLS before forwarding opaque bytes                                      |
| `postgres` | PostgreSQL SSLRequest, then verified TLS before startup/login                  |
| `mysql`    | Read the server greeting once, send SSLRequest, then verified TLS before login |

An empty block uses the publisher's system roots. `target.tls.server_name`
overrides the target certificate hostname; `target.tls.ca_file` adds a
project-relative CA-only PEM file to system roots. TypeScript uses `serverName`
and `caFile`. These are the only supported fields; service-level `tls`,
`target.tls.mode`, and trust-bypass settings are rejected. The applying client
captures bounded CA material and a digest. Installed jobs retain that snapshot;
they do not reopen the source file at boot. A changed hostname or bundle requires
approval through the applied revision or saved service metadata.

Omitting `target.tls` permits a plaintext backend. It never turns off managed
visitor TLS. Private HTTPS targets require that block; HTTP targets with a TLS
block require an `https://` origin.
Docker/Compose HTTP targets select HTTPS from that block. App targets may declare
TLS too, but their reported listener must be HTTPS. Applying before the listener
exists requires `server_name` so the snapshot has a known certificate identity.
Preflight uses a disposable native connection without login or application
bytes. Certificate/name rejection requires a configuration change; unavailable
targets can be retried. Neither preflight nor forwarding retries in plaintext,
disables verification, or replays protocol bytes. MySQL is never probed as HTTPS.
PostgreSQL instructions retain `channel_binding=disable` because visitor and target
TLS end at different boundaries; ordinary SCRAM authentication remains intact.

For native `kubectl` access to an EKS private endpoint, use `protocol: tcp`, omit
`target.tls`, and
point the kubeconfig server at the connector's loopback HTTPS address. Keep the
EKS cluster's `certificate-authority-data` and set `tls-server-name` to its
original endpoint hostname. The Kubernetes client then verifies the EKS
certificate and sends its normal authentication end to end. Do not replace the
cluster CA with a tnl certificate or disable verification.

An existing sshd is an ordinary `protocol: tcp` target with `target.tls` omitted.
Connect OpenSSH to the loopback listener, preserving its host-key verification
and account login. tnl authorizes the private stream; sshd owns users, keys,
shells, forwarding permissions, and file transfer. There is no tnl-managed SSH
server or root SSH runtime.

## authenticate the publisher run

Control reserves a run ID and number under the authenticated publisher grant.
Preparation captures the exact hostname, port, domain and certificate plan.
Starting the run rechecks that snapshot and the publisher/grant/key tuple;
response-loss recovery retries the same preparation and start. A start retry
rotates only its run token and retains the connection assignments.

Local services use `SERVICE.WORKTREE.MEMBER.DOMAIN`. Control binds the namespace
claim to the membership and exact project source/worktree declaration. Ad-hoc
creation uses the current member/worktree namespace too. `--domain` selects a
ready team domain; otherwise control captures the team's default. Changing that
default does not rename an existing endpoint. Named groups retain their durable
`GROUP.PROJECT.OWNER.DOMAIN` namespace across group-key renames. Local plans cover
one exact hostname; group plans cover only their approved namespace.

The publisher uses the shared `CertificateCache` pending/current lifecycle and
control's existing ACME worker. DNS-01 work belongs to the captured domain;
private endpoints publish loopback DNS, and direct endpoints publish ingress
addresses. Readiness requires an installed, unexpired service certificate and a
healthy target. Control never creates a public URL to issue a service certificate.
Managed service certificates require DNS-01 automation and a ready team domain,
including when control, ingress and relays run in standalone.

The publisher maintains two independently assigned connections on different
relay services. Initial readiness requires both; afterward a surviving ready
connection can admit new visitors while the other slot is replaced. At zero
live slots control demotes the run and publishes a tombstone. It retains the
first-ready timestamp so one reconnected relay can restore availability. Relay
lease expiry excludes that relay without expiring another surviving slot or
replaying existing visitors.

## authenticate the connector and each stream

`internal/tcpconnect` enrolls a local device signing key for the signed-in
identity and maintains two independently authenticated ingress paths. Control
assigns each path an ingress endpoint and a one-use session credential.
`PrivateConnectorSessionHello` proves device-key possession and binds the
selected service, device, identity, and fresh nonce. Ingress claims it against
its current lease and binds the source IP observed on the socket or verified
PROXY metadata. The connector cannot choose a source IP or select a private
service through untrusted SNI. An authenticated session alone never authorizes
an application stream.

The connector keeps one client-generated idempotency key for startup's pair
and one per single-slot renewal until control returns a result. Ambiguous
failures retry that exact request, including the excluded sibling ingress.
Control stores the result with encrypted credentials and checks current access,
device, unbound sessions, and ingress leases before replaying it. A changed
request conflicts; an expired, revoked, bound, or stale assignment cannot replay.
The expiration worker removes expired results and keys in bounded batches after
a 24-hour retention window. Storage-key rotation includes these results.

For each local connection, the connector resolves a current ready publisher
run and sends `PrivateVisitorEntry` on one authenticated mux path. Ingress
checks the exact session, device, identity, source, service/run, and current
grant with control before forwarding. `PrivateVisitorAccepted` returns that
trusted identity plus the visitor connection ID, grant revision, and publisher
connection assignment. The relay acknowledges the exact private assignment
before ingress writes PROXY v2 once and releases visitor bytes.

Native HTTP and database clients verify the managed service certificate through
the connector; opaque clients use its verified TLS helper. The publisher
rechecks trusted connector admission against the exact service/run, session,
visitor, device, source and current grant before opening the target connection.
Application client certificates are not requested on connector-admitted streams.
Ingress and relay carry encrypted visitor bytes; `pkg/protocol/tunnelv1` owns
the bounded admission and forwarding frames.

Direct HTTP uses the default `publisher.ManagedHTTP` frontend after visitor TLS.
`privatepublisher` constructs it from the exact run token, service ID, allocated
hostname/port, and trusted forwarding header on every managed publisher path.
TLS requests an optional client certificate and proves possession of its key;
control verifies its issuer, exact service/identity/device binding, revocation,
and current visitor permission. A certificate grants no management or feedback
permission.

Each request chooses one credential: `Tnl-Access-Token`, `Tnl-Share-Token`, browser
cookie, share cookie, then the optional TLS certificate. A malformed, expired,
revoked, or inapplicable selected credential fails closed. `Authorization`
remains application-owned. Public reachability never grants anonymous access.
Control checks current membership, company session context, grants, IP policy,
and exact service/run/source/destination admission on every app request. The
publisher waits for ingress to promote pending capacity before opening the
target connection. Ingress rechecks the retained credential digest for long
responses and upgrades, with the same bounded authorization deadline as other
managed streams. Private HTTP instead uses connector admission, requests no
application client certificate, and rechecks it for every request.

Browser sign-in uses `/v1/browser/managed-login` and the shared
`/v1/browser/callback`. Company step-up selects the service's actual team and
requires the existing verified `tnl_team_contexts` proof. Login attempts capture
the ready run set; one-use handoffs and browser cookies cannot authorize a later
replacement run. Redirects retain the allocated non-443 port. The frontend
checks the exact Host including that port and checks logout's Origin against it.
Cookies are secure, HTTP-only, and host-only. Forwarded headers never select a
subject, source address, callback, or browser origin.

The frontend reuses `httpstream` for one lazily opened target connection and
`applicationlimits` for run-local HTTP budgets. Authorization precedes target
connection and bytes; a closed upstream is final, including for GETs. HTTP
streaming and upgrades do not replay requests. `target.tls` remains independent
of the managed service certificate and visitor authentication.

## manage exact-service access from the cli

Use `tnl share service` for a configured service key or an immutable `psvc_` ID:

```console
tnl share service invite create orders --email reviewer@example.com --expires-in 4h
tnl share service invite accept "$INVITATION_SECRET"
tnl share service list orders
tnl share service list psvc_SERVICE --output=json
tnl share service revoke orders psivt_INVITATION
tnl share service revoke orders psgr_GRANT
```

Creation requires exactly one explicit deadline: `--expires-in` accepts durations
such as `4h` or `7d`; `--expires-at` accepts an RFC3339 timestamp. Invitations last
at most 30 days. Acceptance keeps that deadline and requires the matching
signed-in verified email. It creates one identity grant for that service, never
a team membership, team grant, or publisher-group grant. Revoking an invitation
also revokes its accepted grant. Revoking a `psgr_` ID through this command checks
that it is an identity grant; declared team grants belong to project configuration.

For response-loss recovery across invocations, use `--idempotency-key` with
`--expires-at` and retain the exact command. An exact retry returns the original
invitation ID and current state without a secret. Explicitly revoke that ID,
then create a replacement with a new key. Changed email, service or deadline with
a used key conflicts; a retry does not extend access or issue another secret.
See [service access](service-access.md) for the API contract.

Configured keys select one entry from the current team's manager inventory by
exact project key, source fingerprint, configuration key, and worktree key.
Local services use the current worktree realization; applied services use an
empty worktree key. Selection does not require a visit grant. The CLI rechecks
the same source binding on its immutable-ID manager read before managing access.
Missing or ambiguous bindings fail instead of selecting a saved name or another
project's friendly name. `name` overrides do not change the configuration key
used here. Named publishers' HTTP `publicURL` policies still select managed
services. Local `publicURL` declarations use the existing `tnl share invite`,
`link`, and `token` commands with a public URL.
`--server` and `--team` retain their usual explicit selection rules; `--no-config`
with an exact service ID works outside the project.

All management operations use the current signed-in person's control session;
control checks current owner/admin permission. Accepting an invitation needs no
membership in the service's team. List returns exact-service grants and
invitations, including accepted, expired, and revoked records. The CLI follows all
100-record API pages before rendering or selecting a grant to revoke. Human output
includes identity and invitation IDs, states, and deadlines. JSON includes
`schema_version: 1`, `private_service_id`, `grants`, and `invitations`; it never
includes invitation secrets. Managed HTTP summaries appear in `http_grants`
without their token or share secret. The list covers stored grants, not an enumeration
of current team members or all effective access decisions.

New creation prints the one-time secret as a raw stdout value. An exact retry
prints revoke/reissue instructions. `--output=json` returns the invitation model,
with `secret` present only for a new creation. Acceptance, listing, and
revocation use the shared human renderer by default and support JSON. Finite
results go to stdout; authentication prompts and errors go to stderr.

## create managed http tokens and shares

For a publicly reachable managed HTTP service, the CLI exposes the existing
bounded HTTP credential operations:

```console
tnl share service token create web --expires-in 1h
tnl share service link create web --expires-at 2026-10-21T12:00:00Z
tnl share service revoke web mhg_GRANT
```

These commands require exactly one deadline and enforce the server's seven-day
maximum. They require `protocol: http` and a public managed endpoint; private
connector access uses identity invitations. Human-mode creation prints only the
raw token or share URL; `--output=json` returns the API creation model. The CLI
checks the exact `managed_service` subject, service ID, credential kind, and
deadline before printing it. Share URLs must retain the managed hostname and
allocated port. A public URL grant cannot substitute for this managed service.
`tnl share service list` includes managed HTTP credential IDs, kinds, deadlines,
and revocation state without returning their secrets. Use the exact `mhg_` ID
from creation or the list for revocation.

A current service manager can create a bounded credential through the control
API. These credentials use the explicit `managed_service` subject and `mhg_`
grant IDs. They never extend an existing public URL or preview share.

```http
POST /v1/private-services/psvc_SERVICE/http-grants
Authorization: Bearer CONTROL_ACCESS_TOKEN
Content-Type: application/json

{"kind":"token","expires_at":"2026-10-20T00:00:00Z"}
```

The response returns `subject`, `id`, `kind`, `secret`, and `expires_at`. The
secret is returned only at creation. Send a token in `Tnl-Access-Token`:

```console
curl --header "Tnl-Access-Token: $MANAGED_HTTP_TOKEN" https://SERVICE_HOSTNAME:ALLOCATED_PORT/
```

Use `kind: "share"` to receive a `share_url` on the same hostname and port. Its
redemption installs a host-only share cookie; API visitors can send the secret
in `Tnl-Share-Token`. Tokens and shares have distinct credential kinds and cannot
substitute for one another. Both expire within seven days and remain bounded by
the creator's current service access and company authentication. Revoke either
with `DELETE /v1/private-services/psvc_SERVICE/http-grants/mhg_GRANT` using a
current manager session. Public URL share, browser, and feedback APIs retain
their original URL-scoped grants.

Connector and publisher slots race QUIC with TLS/TCP fallback, authenticate
each transport, and retain a surviving path while replacing a failed slot.
Ingress can try another relay before the first visitor byte; afterward a
failed stream closes. Neither connector nor publisher migrates or replays an
admitted application stream.

## retain current authorization

Private service visitor policy consists of current owner/admin access or an
exact team/identity grant; `access: {team: true}` declares the team grant.
Inventory includes services with current access even while their publisher is
offline. Inventory is not readiness and never admits a stream by itself.

Invitations bind a verified email to an exact service grant, not a team
membership. Creation returns the one-use secret once; list operations never
return it. Acceptance requires the matching signed-in verified email. A retry
with an already used creation idempotency key cannot recover the secret.

Ingress rechecks every active visitor against its exact session, visitor ID,
device, identity, trusted source, current grant, run, and ingress lease, normally
every 30 seconds. The initial check and retries run before the actual admission
deadline, reserving time for the bounded control request even when a lease
expires sooner than the normal interval. An explicit denial closes both ends.
Successful checks return a `valid_until` bounded by the applicable grants, run,
ingress and live relay deadlines, with a hard two-minute cap. Unavailable control
cannot extend that deadline. Stream-copy workers join before ingress releases capacity.

Connector-session expiry prevents new streams on that mux; it does not revoke
already admitted streams. The connector obtains another authenticated path
for later streams and drains the old path. A revoked grant, disabled identity
or device, closed run, replaced assignment, or expired infrastructure lease
cannot continue authorizing new work.

## keep ownership explicit

Split ingress advertises `<ingress-id>.<server-domain>:443`, deriving the suffix
from `TNLD_CONTROL_HOSTNAME`. Each process needs its own stable ID, DNS name,
and reachable address. Control assigns two distinct live ingress addresses;
one split ingress process cannot establish a connector's initial two slots.
`deploy/compose.split.yaml` therefore runs `ingress-a` and `ingress-b`.

`TNLD_INGRESS_LISTEN` accepts public HTTP TLS and exact-SNI private connector
TLS/TCP. A trusted edge may prepend PROXY v2; when configured, ingress requires
that header and destination 443 before dispatch. Private QUIC uses
`TNLD_INGRESS_UDP_LISTEN`, falling back to the TCP bind address when omitted.
Fly uses `fly-global-services:443` for UDP and `0.0.0.0:8443` for TCP.
Standalone shares `TNLD_RELAY_UDP_LISTEN` between relay and private connector
ALPNs and provides two logical ingress identities on the shared listener.

After registration, control issues an ingress transport certificate bound to
the exact ingress ID, process run, lease revision, and infrastructure hostname.
Visitors obtain that issuer and public-key pin through authenticated control;
they still verify the hostname and lease identity. This infrastructure issuer
and the relay WebPKI certificates remain required. Neither issues database
visitor certificates or creates a public database port. Hosted Fly manifests
and qualification belong to `tnl.dev`; this repository owns generic self-hosted
Compose and publisher templates.

- `internal/controlstate` owns saved services, grants, invitations, device
  enrollment, connector assignments, captured managed run plans, and audit history.
- `internal/controlapi`, `internal/ingressapi`, and `internal/relayapi` expose
  those authority operations. Control manages the ingress transport certificate;
  `internal/tnldruntime` wires it and private forwarding for split and standalone
  roles. Infrastructure certificates are separate from target trust.
- `internal/privatepublisher` owns private run and publisher-connection
  lifecycle. `internal/tcpconnect` owns loopback listeners, connector slots,
  publisher proof verification, and verified managed visitor TLS. Target TLS
  negotiation belongs to the publisher through `internal/targettransport`.
- `internal/publisherjob` installs publishers and connectors under the user
  supervisor. `tnl publish NAME --install` and `tnl connect NAME --install`
  require that supervisor before changing local or server state. `--detach`
  runs independently of the terminal without automatic restart; foreground is
  the default.

Foreground and detached connectors handle a changed approved metadata revision
inside the same process: join the old runner and streams, clear readiness,
refetch the exact service ID from current visitor inventory, and reopen the
reserved port with the new protocol and managed visitor endpoint. Connectors
never consume target trust. An explicit `--protocol` remains a constraint and a
conflicting approval ends the connector. Ordinary runner failures do not restart
it. Installed connectors refresh metadata on the supervisor's next job attempt.

Private service IDs (`psvc_`), private run IDs (`psrun_`), and connector session
IDs (`pcs_`) never substitute for public URL (`url_`) or publish run (`pr_`)
IDs. Preserve `private_service_id` and `private_run_id` on the wire. Do not
route private services through public URL DNS, certificate, or public hostname
selection code.

The focused Task targets cover disposable PostgreSQL authority and audit,
separated/standalone private topology, real TLS PostgreSQL/MySQL clients, and
OpenSSH forwarding over both transports. See [test tiers](../../contributing.md#choose-a-test-tier).
