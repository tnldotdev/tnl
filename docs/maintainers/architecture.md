# architecture

These are contributor-facing runtime, trust, and package boundaries. For a
public overview, see [how tnl works](https://tnl.dev/docs/how-it-works).

See [self-hosting](https://tnl.dev/docs/self-hosting) for deployment procedures
and the [`tnld` reference](https://tnl.dev/docs/tnld) for configuration.

## see the system at a glance

```text
                              PostgreSQL
                                  ^
                                  |
                          +-------+-------+
tnl clients ------------>| control       |
                          +-------+-------+
                                  |
                         routing  |  placement
                                  |
visitor ---> ingress ------------+----> relay <=== publisher ---> app
                                      A or B
```

The arrows show responsibility, not one permanent network connection. Control
coordinates the system. Visitor bytes travel through ingress and one connected
relay to the publisher.

| Component                  | Responsibility                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------- |
| `tnl` client and publisher | Tunnel lifecycle, publisher connections, visitor TLS termination, and target forwarding |
| Control                    | Durable state, authorization, placement, certificates, administration, and coordination |
| Ingress                    | Visitor acceptance, IP policy, relay selection, usage, and one-time forwarding          |
| Relay                      | Publisher connections and visitor streams for locally connected publishers              |
| PostgreSQL                 | Authoritative durable server state                                                      |

Only control connects to PostgreSQL. Ingress receives a short-lived routing
table. Each relay knows its own lease and the publishers connected to it.

Control encrypts saved signed-in IP allowlists and request digests with
`TNLD_STORAGE_KEY`. Guest trials keep a keyed digest of their issuing IP,
never its address; a guest credential expires 72 hours after issuance. For each
public URL, control derives a purpose-specific verifier from the storage key
and sends it only over the authenticated ingress API. PostgreSQL routing
events contain hashed IP prefixes, not the verifier or the original CIDRs.
Ingress masks a visitor address to each permitted prefix length and checks its
digest before forwarding; an absent verifier rejects the visitor. Ingress and
relays never receive `TNLD_STORAGE_KEY`. The separate visitor-network usage
sketch estimates distinct networks and cannot authorize a visitor.

Standalone composes control, ingress, and two logical relay services in one
`tnld` process. It uses the same role boundaries through in-process adapters.

## follow a visitor connection

```text
visitor
   | visitor TLS ClientHello
   v
ingress: inspect hostname and apply IP policy
   | authenticated internal forwarding
   v
relay: open a stream on a ready publisher connection
   | unchanged visitor TLS bytes
   v
publisher: terminate visitor TLS
   | HTTP or HTTPS to the configured target
   v
target service
```

Ingress creates one PROXY v2 metadata header with the original source and
destination. Relay preserves that header and the visitor TLS bytes. A denied
visitor may use a separate, bounded forwarding budget to reach the publisher
for an HTTPS 403, but never reaches the target. The publisher removes
untrusted forwarding headers before proxying an allowed HTTP request.

The ingress routing table retains the relay process identity and the last
advertised lease deadline. A relay can renew its lease without changing the
public URL projection, so ingress does not treat that copied deadline as final.
The connected relay checks its current, unexpired lease and the exact process
and connection assignment identities before accepting each visitor stream.

Public URL DNS points to ingress, never to a relay. Placement can therefore
change without changing public URL DNS.

## resolve project configuration

config factories receive the project's directory relative to its worktree and
the structured worktree label. the label's project, optional checkout, and ID
are the pieces used in its finished DNS label after shortening. service names
may require further shortening. the primary checkout omits the checkout piece.
generated project declarations preserve exact label literals, and browser
metadata exposes those pieces without filesystem roots.

project alias declarations name one configured entry service. relative alias
names can contain several DNS labels; ordinary tunnel names remain one label.
configuration validation does not consult server policy or publish a URL.
TypeScript config helpers check service references in aliases, webhooks, and
path mounts; Go validation also checks computed values and static configuration.

aliases keep a persistent selected project directory in client state, initially
the corresponding project in the primary checkout. registration never takes an
explicit selection back. `use` requires a ready entry service and preserves a
different live owner unless takeover is forced. `release` returns an override
to the primary checkout, even when its service is stopped. receiver readiness
and selection are separate: restarting resumes the chosen worktree; an expired
lease does not assign a different one. revision and tunnel/run identities reject
requests prepared against older selections.

the alias publisher reuses the integration URL lifecycle and publishes only
from the selected ready entry-service tunnel. each request checks the selection
revision and destination tunnel/run before entering the local proxy. an old
publisher stops admitting requests immediately after a handoff; already admitted
requests may finish, and its hostname lock remains held through drain and join.
alias runs do not inherit preview shares or feedback state.

OAuth callback state records the initiating public URL/run separately from the
destination app tunnel. an alias-origin callback returns to the alias hostname
for its host-only cookies. a bounded, expiring single-use return record also
checks the final browser hop, so a handoff between redirect and app admission
cannot send that callback to a replacement alias run. app cookies on a stable
alias hostname can remain in the browser across worktree changes; tnl does not
rewrite them.

alias commands resolve the entry service's team/domain context and check the
advertised hostname policy before changing local selection. a rejected nested
name leaves the previous owner intact. generated alias metadata is declarative,
not a readiness claim; framework integrations admit only aliases that reach
their entry or mounted service. alias workers join before the parent tunnel
reports completion and closes client state.

## own the app-led lifecycle

the application starts with its normal development command. Vite and Next
integrations prepare browser-safe project metadata, then register the bound
listener. Node and Bun applications call `await tnl.prepare({service: "api"})`
before startup and `await publication.register(server)` after binding, including
listeners that request port 0. directory inference requires a unique configured
service. builds and production previews do not prepare registrations.

`internal/clientruntime` owns registration leases, publisher observations,
readiness, and a bounded durable local event journal. the private native command
`tnl runtime address` locates one Unix socket per canonical
project/worktree/client-state identity. the app starts `tnl runtime serve` to
maintain it. the socket is user-owned
and mode 0600 beneath a stable, short mode-0700 directory under `/tmp`.
`internal/privateprotocol` bounds and
validates requests; golden fixtures describe its wire shape. control credentials
remain in the native process and never cross the socket or browser metadata.

preparation reserves a live owner without claiming a listener. registration
acknowledges the bound target, not provisioning. duplicate live owners fail;
listener replacement cancels and joins the previous publisher before starting
another run. request admission and readiness observations check registration and
publish-run identities. an SDK reconnects after a manager crash. unregistering,
app exit, or an expired renewal stops publication. the manager joins integration
workers and drains publishers, then exits after the last registration's cleanup
grace. it never launches or terminates application processes.

registered, routable, and ready are separate facts. routable means the existing
publisher has reported control readiness. ready additionally requires a fresh
public GET: by default `/` accepts app statuses 200 through 499 except 408 and 429. tnl diagnostic responses always fail. service readiness can select a path
and exact status. checks use normal DNS/TLS, send no app credentials, follow no
redirects, and read headers only with a five-second deadline. retries start at
500 milliseconds and double to two seconds for up to two minutes. each new run
gets an automatic check; `tnl wait` checks again. a failed check leaves the
publication running. `tnl status` only reads observations.

`tnl watch` resumes after an ordered journal cursor. a status or initial watch
snapshot includes the watermark from the same journal snapshot. cursors older
than retained events fail with an authored diagnostic. the journal survives a
manager restart and contains no credentials, request bodies, or OAuth state.

## maintain project integration urls

`internal/integrationurls.Publisher` maintains one locally elected public URL
alongside app tunnels. it reuses `internal/publisher` for visitor TLS,
certificates, admission, and publisher connections. a prepared run either
proxies a local target or serves a publisher-owned HTTP handler; both retain
hostname and visitor-policy checks. header-only response observers run before
headers reach the visitor and do not disable upstream compression.

the elected worker renews a short-lived readiness record in client state.
reprovisioning and draining clear readiness. a changed preparation revision
cancels and joins the old run before preparing its replacement. the worker
holds its hostname lock through cleanup so another local process cannot
publish the same integration URL while the old run is draining.

## understand the retry boundary

Ingress may try another connected relay while it is opening a visitor stream.
It must not replay application bytes.

```text
select relay
    | stream setup rejected
    +----------------------> try another relay
    |
    | stream accepted
    v
send first visitor byte  <--- retry boundary
    |
    v
copy bytes without replay
```

After the first visitor byte is sent to a relay, any failure closes that visitor
connection. Live visitor connections are never replayed or migrated.

`internal/ingress/ingress.go` owns inspection and private-service handoff.
`internal/ingress/visitor.go` resolves a public URL or an exact challenge, applies
policy and admission, then opens a publisher stream. The open stage may try
another connected relay after a failed PROXY header write or a ClientHello
write that sent zero visitor bytes. It returns a committed stream as soon as a
visitor byte is sent; the copy stage owns that stream until close, even if the
rest of ClientHello cannot be written. A denied visitor uses separate admission
and may complete TLS at the publisher for an HTTPS 403; a challenge never falls
back to ordinary public URL lookup.

## understand public urls and publishing

control can issue a public URL publish credential to a signed-in member who may
publish one enabled, saved app URL. it records only a digest. the credential
authenticates reads for that URL and publish run creation, never team management
or public URL mutations. the saved target and current membership must still
match; the publish run token handles later run operations. control records the
credential used to start a run and closes that run on heartbeat if the
credential expires, is revoked, or its issuer loses publish authority.

an ephemeral credential instead records a team, ready domain, membership,
namespace, and DNS-01 wildcard certificate plan. issuing it does not create a
public URL or allow it to act as a saved-URL credential. control checks the
stored kind as well as the token's prefix, and team credential listing and
revocation handle both kinds by credential ID.

ad-hoc allocation is control-owned: one invocation ID and an ephemeral
credential select one URL beneath the stored namespace. control rechecks the
stored credential, current membership and domain, and the public URL creation
gate in the creation transaction. the caller supplies a canonical loopback
target and visitor IP policy, never the hostname. the 128-bit `eph-` label is
random; identical allocation retries return the same saved URL, while changed
inputs conflict. namespace wildcard DNS covers the label, but ingress still
requires the exact saved URL and a ready publish run before routing visitors.

control owns hostname policy: a member may publish any valid descendant of
their namespace, subject to the managed domain's configured depth limit.
the member namespace apex is reserved. by default, a self-hosted built-in
administrator publishes directly under the managed domain; other personal
teams use their reserved name and organization members use their member slug
and team name. a shared hosted server can opt into generated labels. personal
teams publish directly on their custom domains; organization members keep
their member slug, and an admin or owner can publish a team-shared exact URL.
when DNS automation is configured, sibling names use a wildcard under their
authorized namespace or immediate parent; custom-domain apexes use an exact
certificate name alongside the wildcard. without automation, managed-domain
URLs use exact DNS and TLS-ALPN-01 certificates. new custom domains require
an explicit opt-in and DNS automation. disabling new claims does not affect
existing custom domains or their release.

new public URL creation records one immutable, client-declared purpose: `app`,
`alias`, `demo`, `oauth`, or `webhooks`. migration labels earlier URLs as `app`.
ingress can associate connection and byte usage with that saved URL, but cannot
see which provider sent a webhook: paths remain inside visitor TLS until local
tnl terminates it.

projects with `oauth: true` publish one saved OAuth callback URL while app
tunnels run. linked worktrees share that URL through the same client state,
server, and project namespace, even if an app service selects another domain.
its name does not depend on the checkout. webhooks coordinate through project
identity and service namespace and do not require an OAuth URL.

the app publisher observes response headers before releasing authorization
redirects to the browser. a bounded, single-use OAuth state digest identifies
the initiating app's public URL and exact publish run and expires after ten
minutes. the callback handler returns the browser to that app's callback path.
the app validates state and PKCE and exchanges its code using the registered
redirect URI. control and relays receive neither login state nor callback
contents. a callback to a stopped or replaced run fails instead of reaching
another worktree.

Declared webhook endpoints use one saved `hooks-…` hostname with a 64-bit,
13-character webhook-specific HMAC suffix. OAuth uses a separate HMAC purpose
and keeps its six-character suffix. Client state replaces each pre-change
saved hostname once when the project next selects it. Each live participant
registers its declarations separately from receiver selection. All declarations
for a named endpoint must agree on service, exact path, methods, and source
policy. SQLite registration rejects conflicting names and paths atomically.
Only ready tunnels of the named service receive requests; subscriptions in
other contexts and expired tunnel leases cannot become receivers.

Ingress admits the union of the resolved source ranges because HTTP paths remain
encrypted until the publisher. The local handler checks the trusted source IP,
exact escaped path, and method before reading the body. It snapshots ready
receivers and forwards identical body bytes and signature inputs to each.
In fanout mode every receiver must return 2xx; tnl then acknowledges with 200.
Failed attempts are not retried locally, and
provider retries may revisit already successful worktrees. GET, HEAD, and
OPTIONS verification requires matching bounded responses. No request journal or
replay is retained.
Changed declarations drain the webhook publish run before re-publication;
provider IP ranges are resolved once per new run, independently of OAuth.
Control and standalone serve `/v1/webhook-providers/{provider}/source` using a
fixed provider enum. They read only documented webhook sender feeds and bounded
static ranges, with a short-lived in-process cache and a bounded last-good
fallback. If no usable range exists, the response is unavailable rather than
an unrestricted policy. The provider-labelled API request metric measures
lookups, not configured endpoints or actual webhook deliveries.
tnl reads its selected server with ETag revalidation and a per-server,
bounded last-good SQLite cache. An unavailable source affects only its
endpoint. Overrides replace rather than union with catalog ranges. New runs
resolve sources independently of OAuth; the app authenticates each request.

Selected endpoints instead select one explicitly claimed receiver. Ownership
is tied to that tunnel's liveness lease, not to publisher leadership or its
current ready/provisioning phase. Ordinary `tnl webhook use NAME` cannot replace
a live claim; `tnl webhook use NAME --force` atomically selects a ready receiver
in the calling worktree. Already-dispatched requests may finish at the old one.
Source/path/method admission runs before delivery in either mode. A selected
handler's status and bounded body are returned directly to the provider.

`tnl status` combines the app registration journal with saved integration URL
hostnames, publisher readiness leases, webhook declarations, and selected
ownership from one SQLite snapshot. the JSON result includes ready receivers from linked
worktrees even when the command selects just the current checkout's tunnels.
An expired publisher lease is stale; a live selected owner in provisioning
remains selected but is not a ready receiver. Status includes only saved
hostnames, endpoint configuration, local tunnel identity, and authored reasons;
it never includes OAuth state, codes, signature headers, or request bodies.

```text
public URL
  durable hostname, ownership, target, policy, and state
    |
    +-- publish run
          one active publication of the public URL
            |
            +-- publish run number
                  next number for this public URL
```

One app service publication or local `tnl publish` invocation is a tunnel. Starting a new
publish run increments its public URL's publish run number. Stopping a normal
tunnel ends the publish run but leaves the public URL available for a later run.

Each publish run has two publisher connection slots. Control assigns them to
different relay services.

```text
publisher
  |-- connection slot 0 ----> relay service A
  `-- connection slot 1 ----> relay service B
```

Initial routability requires the public URL certificate and both publisher
connections. After that first transition, one ready connection can keep the
public URL serving while the publisher replaces the other.

The publisher waits for one connection before certificate work, then both
connections before asking control to mark the publish run ready. A normal stop
drains admitted visitors before closing publisher connections. A rejected
heartbeat or expired certificate closes those connections immediately.

Publishers try QUIC first. After a short delay, they also try TLS/TCP with yamux
and keep the first authenticated transport that completes.
If a claimed QUIC publisher connection fails, the publisher waits for control's
replacement connection assignment. That slot tries TLS/TCP first, with QUIC as
the second candidate if TCP cannot connect. A later replacement returns to
QUIC-first after TCP recovery. The failed connection's visitor streams end;
they cannot resume on the new transport.

The publisher tracks each local slot as connecting, serving, or waiting for a
replacement. These phases describe its local session, not control's stored
assignment state. Heartbeat updates to that stored state do not restart a slot;
only a new assignment identity does.

## separate the trust boundaries

| Credential or key               | Held by                           | Purpose                                               |
| ------------------------------- | --------------------------------- | ----------------------------------------------------- |
| Access and refresh tokens       | `tnl` client                      | Authenticate a control session.                       |
| Publish run token               | Publisher                         | Update one publish run.                               |
| Publisher connection credential | Publisher and assigned relay      | Authenticate one publisher connection.                |
| Cluster secret                  | Split control, ingress, and relay | Authenticate private process coordination.            |
| Login token                     | Built-in authority control        | Recover the built-in administrator identity.          |
| Website service credential      | Control and hosted website        | Read identity context and accept browser invitations. |
| Webhook credential              | Control and mailer                | Authenticate invitation email delivery.               |
| Storage key                     | Control only                      | Encrypt recoverable secrets in PostgreSQL.            |
| Relay transport private key     | Current relay process             | Terminate publisher transport TLS.                    |

Only control receives PostgreSQL, storage, DNS, or ACME credentials. A relay can
retrieve its current relay transport certificate and private key while its lease
is valid, and keeps them only in memory.

Split ingress and relay authenticate to control with the cluster secret. Control
also checks the configured process identity, process run ID, and lease revision.
A restarted or expired process cannot continue using stale authorization.

Visitor TLS is separate from relay transport TLS. Visitor TLS passes through ingress
and relay unchanged and terminates in the publisher.

## place authority decisions

The authority API owns identities, authentication, teams, memberships,
invitations, domains, and current authorization decisions.

control and standalone serve the authority API at the control URL.
OIDC providers prove identity; control owns current memberships and publishing
decisions. the hosted website uses the narrow
[hosted integration](hosted-integration.md) for its team picker and invitations.

control creates guest trials against its own managed domain. it reserves each
guest namespace in the managed-label pool in the same
transaction as the trial; team creation cannot reuse a guest namespace. managed
guest DNS uses the configured managed zone, without a claimed DNS authority.

`TNLD_SERVER_DOMAIN` names server infrastructure. It is independent from
`TNLD_MANAGED_DOMAIN`, which provides managed public URL
namespaces.

## own each api

| Contract                                                       | Implementer                               | Caller and authentication                                                           |
| -------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------- |
| [Control](../../api/control/v1/openapi.yaml)                   | `internal/controlapi` on control          | CLI and publisher with access or publish-run credentials                            |
| [Authority](../../api/authority/v1/openapi.yaml)               | Built-in authority on control             | CLI sessions and team/domain operations; scoped website identity and invitations    |
| [Ingress](../../api/ingress/v1/openapi.yaml)                   | `internal/ingressapi` on control          | Ingress with cluster authentication, or standalone direct calls                     |
| [Relay](../../api/relay/v1/openapi.yaml)                       | `internal/relayapi` on control            | Relay with cluster authentication, or standalone direct calls                       |
| [Public URL usage](../../api/public-url-usage/v1/openapi.yaml) | External receiver                         | Control public URL usage worker with a configured bearer token                      |
| [Publisher](../../api/publisher/v1/openapi.yaml)               | `internal/publisher` on the local process | Same-origin browser feedback through public URL IP policy or a current share cookie |

OpenAPI is the wire contract. It does not promise that every reserved operation
is implemented.

the authority spec defines the HTTP exchanges used by `tnl` and the hosted
website. it generates the Go server interface and clients as well as the
website's response schemas.

`pkg/protocol/tunnelv1` is the handwritten tunnel protocol source of truth.
`internal/muxsession` provides multiplexed byte streams, `internal/tunnel`
implements handshakes, and `internal/streamcopy` copies bytes in both directions.

## keep local packages focused

| Package                    | Responsibility                                                              |
| -------------------------- | --------------------------------------------------------------------------- |
| `internal/config`          | Versioned static configuration and schema validation                        |
| `internal/projectconfig`   | Project discovery, TypeScript evaluation, worktrees, and effective services |
| `internal/tnldconfig`      | Server-role settings and environment resolution                             |
| `internal/clientstate`     | Client SQLite state and local ownership locks                               |
| `internal/clientruntime`   | App registrations, public readiness, and local lifecycle events             |
| `internal/privateprotocol` | Bounded private SDK requests and assignments                                |
| `internal/projectmeta`     | Generated browser-safe metadata and TypeScript augmentation                 |
| `internal/clioutput`       | Shared ASCII rendering for the `tnl` client                                 |
| `packages/tnl`             | Browser-safe runtime and Node framework integrations                        |

The npm public subpaths are the package root, `/config`, `/next`, and `/vite`.
The private development socket is shipped implementation, not a public extension
API.

Framework integrations receive browser-safe metadata and a private local socket.
They never receive control access tokens. They remain inactive during builds and
previews.

Go validates project metadata before writing `.tnl/project.json`. The TypeScript
package validates it again when reading it or receiving an app assignment.
Both validators use the shared hostname and project metadata fixtures under
`api/fixtures/`; private protocol golden fixtures cover requests and assignments.

Go also owns default public URL naming. It combines the primary Git checkout
name (and any project path below it), the linked worktree directory when present,
and a six-character, client-state-salted ID. Branch names are not part of the
label. publishing, app preparation, and project metadata use the same composition.

## preserve the core invariants

- Control is the only source of durable runtime state.
- Ingress and relay fail closed when leases or routing state expire.
- Publisher connection slots use different relay services.
- Visitor TLS terminates only in the publisher.
- Ingress creates PROXY v2 metadata exactly once.
- Visitor bytes are never replayed after the retry boundary.
- Credentials stay within the smallest role that needs them.
- Public URL DNS points to ingress, not placement-selected relays.

Detailed PostgreSQL locking, routing publication, usage aggregation, and cleanup
invariants are in the maintainer-only
[control-state notes](control-state.md).
