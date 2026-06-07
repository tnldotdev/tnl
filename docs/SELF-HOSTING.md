# Self-Hosting tnl

The default deployment runs the control API, public ingress, certificate
coordinator, worker backends, and SQLite database in one `tnld` process. The
split reference runs one stateful edge and a fixed pool of stateless workers.

## Deployment Roles

| `TNLD_MODE`  | Responsibilities                                                                | SQLite ownership                       |
| ------------ | ------------------------------------------------------------------------------- | -------------------------------------- |
| `standalone` | Control API, public ingress, certificates, and in-process worker backends       | Opens and owns the deployment database |
| `edge`       | Control API, public ingress, certificates, and coordination of external workers | Opens and owns the deployment database |
| `worker`     | Outbound connection to an edge and worker backends for assigned route versions  | Does not open the deployment database  |

Exactly one standalone or edge `tnld` process may open a given SQLite database
or state volume. A worker never opens it. Do not share a database or volume
between processes, including two edges intended for high availability.

## Topology

Choose one lowercase DNS domain, without a trailing dot.
`TNLD_DOMAIN=example.com` derives both public hostnames:

| Purpose                    | Name                                   | Listener |
| -------------------------- | -------------------------------------- | -------- |
| Control API hostname       | `tnl.example.com`                      | TCP 443  |
| Deployment hostname suffix | `example.com` (`*.example.com` in DNS) | TCP 443  |

Create wildcard A and, when applicable, AAAA records that resolve directly to
public ingress. The wildcard also covers `tnl.example.com`. If CAA records are
present, authorize the configured ACME CA.

The reference Compose files publish IPv4 because `TNL_PUBLIC_BIND` defaults to
`0.0.0.0`. Publish AAAA records only after adding equivalent `[::]` mappings in
a Compose override and confirming that the Docker host accepts IPv6 traffic.

Open inbound TCP 443. The daemon needs outbound HTTPS access to its ACME
directory and configured relay nodes. For a route hostname, `tnld` reads the
hostname from the TLS ClientHello and forwards the connection bytes unchanged
to the publisher through a worker backend. The publisher owns the route
certificate and private key, terminates TLS, and sends plain HTTP to the local
service. This TLS passthrough requires the original ClientHello, so route
ingress cannot sit behind a reverse proxy that terminates HTTPS. `tnld`
terminates TLS itself only for the control API hostname.

## Start Standalone

Prerequisites:

- A Linux host with Docker Engine and Docker Compose v2.
- A verified tnl image selected by its digest.
- DNS for `*.<domain>`.
- An ACME service that supports TLS-ALPN-01 and the configured route
  certificate profile.

Work from the repository's `deploy` directory:

```console
cd deploy
install -m 0600 .env.example .env
```

Set these values in `.env`:

- `TNL_IMAGE`: the verified image digest, such as
  `ghcr.io/tnldotdev/tnl@sha256:...`.
- `TNLD_DOMAIN`: the lowercase DNS domain from which the control API hostname
  and deployment hostname suffix are derived.
- `TNLD_ACME_DIRECTORY_URL`, `TNLD_ACME_EMAIL`, and
  `TNLD_ACME_ACCEPT_TERMS=true`: the ACME account configuration.
- `TNLD_ACME_PROFILE`: the profile used for route certificates.
- `TNLD_ACCESS_TOKEN_LIFETIME`: lifetime of each rotating access token; defaults
  to one hour and accepts values from five minutes through 30 days.
- `TNLD_REFRESH_TOKEN_LIFETIME`: fixed absolute control-session lifetime;
  defaults to 30 days and accepts values through 365 days. It must be at least
  the access-token lifetime.
- `TNLD_RELAY_PROVIDER=tailcat`: explicit consent to use Tailcat's hosted public
  relays.

Tailcat is the encrypted, control-plane-free transport between a publisher and
its worker backend. It uses Tailscale's DERP network to introduce the peers and
as a fallback relay, while allowing a direct peer-to-peer path when networking
permits. Provider mode fetches Tailcat's DERP map once, measures the available
regions, and stores only the selected region in the deployment database.
Restarts use that stored region without fetching the provider map again.
Tailcat and its hosted DERP service are external network dependencies; review
their service and privacy terms before opting in.

Start the daemon and inspect the server endpoints:

```console
docker compose pull
docker compose up -d
docker compose logs --no-log-prefix tnld
curl --fail --silent --show-error https://tnl.example.com/v1/health
curl --fail --silent --show-error https://tnl.example.com/v1/ready
curl --fail --silent --show-error https://tnl.example.com/v1/capabilities
```

Health checks control TLS and HTTP serving. Readiness also checks SQLite.
Capabilities reports DNS state; publish one test route to verify the full path.

Prometheus metrics listen on container port 9090 and are intentionally not
published to the host. Attach a private scraper to the Compose network or add a
loopback-only port mapping. Never expose metrics directly to the Internet.

## Enroll A Client

On first startup, `tnld` creates a login token in its state volume. Retrieve
it without printing it in daemon logs or storing it in `.env`:

```console
docker compose exec tnld tnl admin server login-token --state-dir /var/lib/tnl
```

Install and verify a release archive or an exact-version `@tnldotdev/tnl`
package as described in [Releases](RELEASES.md), then log in. The npm package
contains the client only; keep deploying `tnld` from the verified container.
Browser authorization is preferred when the server advertises it; otherwise
`tnl login` prompts for the login token:

```console
tnl login https://tnl.example.com
tnl host claim demo
tnl publish localhost:3000 --host=demo
```

The publishing command stays in the foreground and obtains the route
certificate automatically. It prints lifecycle messages to stderr; use
`--output=ndjson` for newline-delimited JSON events on stdout. A second interrupt
exits immediately.

The route becomes `https://demo.example.com`. Omit `--host` to have the server
generate a temporary hostname for that invocation. A claimed managed hostname
or custom domain authorizes its exact hostname and child hostnames up to eight
labels below it. Manage claimed hostnames with:

```console
tnl host list
tnl host release demo.example.com
tnl logout
```

Releasing a managed hostname stops its routes and changes its status to
inactive, but ownership remains with the same identity. That identity may claim
it again, which restores active status. The client rotates access and refresh
tokens automatically without extending the fixed `TNLD_REFRESH_TOKEN_LIFETIME`
session expiry. Existing route-session heartbeats can continue after
control-session expiry, but a later client restart or hostname command requires
`tnl login` again.

The daemon stores only credential hashes. If a refresh rotation commits but its
response is lost, retrying the replaced refresh token is treated as reuse and
revokes that control-session family; run `tnl login` again. Recovering the exact
rotated credentials would require retaining recoverable credential material and
would weaken replay protection.

## Identities

An identity is a server-local authorization principal. It owns hostnames,
routes, route credentials, and control sessions on that server; it is not a
team or account shared across servers.

The login token always authenticates the server's built-in admin identity, and
its control sessions receive `publish` and `admin` grants. Each distinct OIDC
issuer and subject pair authenticates a distinct server-local identity whose
control sessions are publish-only. The same subject from two issuers represents
two identities, and an OIDC identity is distinct from the built-in admin
identity.

## Administer The Server

The remote commands use the selected server and saved control session, or
explicit `--server` and `--access-token` values:

```console
tnl admin server status
tnl admin routes list
tnl admin routes suspend route_... --revision=1 --reason='maintenance'
tnl admin routes resume route_... --revision=2
tnl admin hostnames list
tnl admin credentials list
tnl admin control-sessions list
tnl admin maintenance list
tnl admin maintenance disable route_session_creation
```

Maintenance controls are stored in SQLite and audited. All three are enabled by
default:

| Control                  | Effect when disabled                                                                                  |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| `route_creation`         | Rejects creation of new durable routes; existing routes and sessions continue                         |
| `route_session_creation` | Rejects new publisher sessions and route versions; current sessions continue                          |
| `certificate_issuance`   | Rejects starting or resuming certificate issuance; installed certificates and current routes continue |

Use `tnl admin maintenance enable CONTROL` to reopen a path. Disabling a
maintenance control does not suspend existing routes.

Suspension revisions must increase monotonically. Suspending a route changes
its durable state from enabled to suspended, expires its sessions, removes its
runtime routing and certificate-challenge routing, and drains its worker
backend. Resuming enables the route at a new route version, but the route is not
routable until a publisher creates and readies a session for that version.
Hostname quarantine suspends all current routes and prevents them from
resuming; removing the quarantined hostname deletes those routes.

List and show outputs exclude credential secrets. Commands that print or create
secret material are limited to `tnl admin server login-token`, `tnl admin server
token worker`, and `tnl admin server token service`.

To use a custom domain, run `tnl host claim docs.other.com`. Supply it in
lowercase DNS form without a trailing dot. The command prints the
verification-specific CNAME records, or the verification CNAME and ingress
addresses for the custom domain itself, then waits for DNS proof. Releasing the
custom domain stops its routes and changes its status to available. An identity
may claim it only after completing new DNS proof.

## OIDC Login

To enable browser login through an OpenID Connect provider, configure:

- `TNLD_OIDC_ISSUER`: the provider's exact HTTPS issuer.
- `TNLD_OIDC_CLIENT_ID`: a public client with the `openid` scope.
- `TNLD_OIDC_LOGIN_FLOW`: `device_code` for the device authorization grant, or
  `authorization_code_pkce` for a loopback callback and PKCE.

The provider must publish standard discovery metadata and sign ID tokens with
RS256. The server verifies tokens locally and derives the server-local identity
from the token's exact issuer and subject. When OIDC login is available, the
client uses it by default; pass `--token` to `tnl login` to use the server's
login token for operator recovery.

## Route Usage

An edge or standalone daemon can send route registrations, ordered lifecycle
events, and minute/hour usage bucket reports to a receiver implementing the
route-usage API:

- `POST /v1/routes` accepts one route registration.
- `POST /v1/routes/lifecycle-events` accepts batches of ordered lifecycle
  events.
- `POST /v1/routes/usage-bucket-reports` accepts batches of
  `RouteUsageBucketReport` records.

The registration records the route's hostname and authorization metadata.
Lifecycle events use a per-route sequence number. Each lifecycle event and
bucket report identifies its route version with the `route_version` field. A
bucket report contains cumulative values for its minute or hour, a revision,
the time through which it has observed traffic, and whether the bucket is
complete. Its values include attempt outcomes, successful-stream duration and
bytes, and fixed cumulative latency histograms.

The `visitor_network_estimate` value is an approximate count of distinct
visitor networks in the bucket, not a count of people or devices. Each IPv4
address is counted as a /32 network and each IPv6 address as a /64 network.
Route versions within the same route and time bucket share the count, so
receivers must not add those values together. The accompanying
`visitor_network_hll` value contains the precision-12 HyperLogLog sketch. Before
entering the sketch, each network is HMACed with a route-specific daily key
derived from a secret in the deployment database; source addresses and network
identifiers are never stored or sent.

Generate a dedicated credential with `tnl admin server token service`, then
configure both values:

- `TNLD_ROUTE_USAGE_URL`: the receiver's HTTPS base URL. Plain HTTP is accepted
  only for a loopback URL used by the local development stack.
- `TNLD_ROUTE_USAGE_TOKEN`: the generated service token.

Leaving both values empty disables reporting; configuring only one is invalid.
Worker mode cannot report usage because it does not own the route database.

The standalone or edge process checkpoints counters and visitor sketches in SQLite.
It also writes each unsent registration, lifecycle event, and bucket-report
revision to a SQLite outbox before delivery. Registrations are sent one at a
time; lifecycle events and bucket reports are sent in batches of up to 32 items
and 256 KiB. The receiver returns a result for each item ID. The sender removes
only an accepted item at the exact revision it sent, so a response for an older
bucket revision cannot remove a newer report. Rejected items and requests that
fail remain queued and are retried, including after restart.

## Split Edge And Workers

`compose.split.yaml` runs one edge with the deployment's SQLite database and one
or more stateless workers. Generate one worker credential with the verified
`tnld` binary and add it to `.env` as `TNLD_WORKER_TOKEN`:

```console
tnl admin server token worker
docker compose --file compose.split.yaml pull
docker compose --file compose.split.yaml up -d --scale worker=2
docker compose --file compose.split.yaml exec edge \
  tnl admin server login-token --state-dir /var/lib/tnl
```

Each worker connects outbound to the edge, so no worker ingress port is
required. Set `TNLD_EDGE_URL` or `--edge-url` in worker mode to
`wss://tnl.<domain>/internal/v1/worker`. Keep at least one worker running and
size `TNLD_WORKER_CAPACITY` for the intended fixed pool.

This topology scales route work and tolerates an individual worker restart. It
does not make the edge highly available: only that edge reads and writes its
SQLite volume, and worker assignments exist only in its process. Do not share
the volume or run multiple edges against it. Automated scale-in should wait for
a documented drain policy and workload-specific qualification.

## Custom Relays

Custom DERP replaces Tailcat's hosted relay service, not the Tailcat transport.
Publishers and worker backends still use Tailcat's encrypted WireGuard and NAT
traversal layer. Leave `TNLD_RELAY_PROVIDER` unset, mount a reviewed Tailscale
DERP map smaller than 1 MiB, and set `TNLD_RELAY_MAP_FILE`. Configuring both map
sources is rejected. If the map contains multiple regions, also set
`TNLD_RELAY_REGION` to the selected `RegionCode`; the server selects the only
region automatically when the map contains one.

Only install a reviewed map on the daemon. Clients and workers fetch the
selected region from the control API. The endpoint is unauthenticated so
workers can bootstrap; never include credentials or unnecessary private
metadata in the map.

To re-measure the Tailcat provider regions and replace the stored selection,
stop the daemon and run the offline refresh command against its state volume:

```console
docker compose stop tnld
docker compose run --rm --entrypoint tnl tnld admin server relay refresh --state-dir /var/lib/tnl
docker compose start tnld
```

## State And Recovery

`tnld.db` contains all durable server state, including ACME data, the login
token, and the stored relay region. The default Compose project stores it in
the `tnl_tnld-state` named volume.

Set `TNLD_BACKUP_URL=s3://bucket/path` to continuously replicate the database
with Litestream. AWS environment variables, shared credentials, instance roles,
and web identity are supported. For S3-compatible storage, add `endpoint` and
optional `region` query parameters to the URL. Protect the bucket with provider
encryption and access controls because backups contain credentials and private
keys.

At startup, a standalone or edge `tnld` restores the newest backup only when
`tnld.db` is absent. If the remote path is empty, it initializes a new
database. On shutdown it stops mutations and performs a final backup sync before
releasing the state lock.

Shutdown stops new control requests and public connections, then gives active
streams 30 seconds by default to finish before closing them. Long-lived
WebSockets should reconnect after a rollout. If `TNLD_DRAIN_TIMEOUT` is raised,
raise Compose `stop_grace_period` by the same amount; backup shutdown may use an
additional 15 seconds.

For a cold standby, keep its state volume empty and do not start it until the
active edge is stopped or fenced. Start it with the same backup URL and external
configuration, then verify the restored server endpoints before directing
traffic to it. Only one process may access a given SQLite database and backup
path. Test this
promotion regularly; the recovery point is the latest successful Litestream
sync.

Without `TNLD_BACKUP_URL`, stop `tnld` before archiving its state volume. Do not
copy a live SQLite file directly. See [Releases](RELEASES.md) for upgrade and
rollback commands.

To rotate the login token, stop the standalone or edge process and run:

```console
docker compose stop tnld
docker compose run --rm --entrypoint tnl tnld admin server login-token --state-dir /var/lib/tnl --rotate
docker compose start tnld
```

Rotation increments the login-token source revision and revokes every control
session issued from an older revision.

Each client stores its control session, private keys, and certificate state
under `TNL_STATE_DIR`. Its default is the user configuration directory followed
by `tnl` (`~/.config/tnl` on typical Linux systems and
`~/Library/Application Support/tnl` on macOS). Linux protects secret state with
user-owned directories and `0600` files. On macOS, a profile key in Keychain
encrypts access and refresh tokens and route TLS private keys before they are
written to the state directory.

Stop every `tnl` process before backing up its complete state directory. A
macOS state-directory backup is not independently usable: preserve the login
Keychain through a platform-supported backup and restore to the same configured
`TNL_STATE_DIR`. Without the matching Keychain item, reauthenticate and discard
the affected local route state so `tnl` can create new certificate keys.

## Operational Boundaries

- Run exactly one standalone or edge `tnld` process against each SQLite volume;
  worker processes never open it.
- Keep `tnl` and `tnld` on the same release before 1.0.
- Preserve `TNLD_DOMAIN` and the state volume across restarts.
- Do not restore an old database over a running daemon.
- Do not run an older daemon against state migrated by a newer release.
- Keep outer PROXY v2 disabled unless the only path to ingress is a trusted
  proxy configured to emit exactly one header.
