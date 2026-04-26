# Self-Hosting tnl

The default deployment runs the control API, public ingress, route worker,
certificate coordinator, and SQLite database in one `tnld` process. A separate
reference supports one stateful edge and a fixed pool of stateless workers.

## Topology

Choose one canonical base domain. `TNLD_DOMAIN=example.com` derives both public
names:

| Purpose | Name | Listener |
| --- | --- | --- |
| Server API | `tnl.example.com` | TCP 443 |
| Public routes | `*.apps.example.com` | TCP 443 |

Create A and, when applicable, AAAA records for both names. The wildcard must
resolve directly to public ingress. If CAA records are present, authorize the
configured ACME CA.

The reference Compose files publish IPv4 because `TNL_PUBLIC_BIND` defaults to
`0.0.0.0`. Publish AAAA records only after adding equivalent `[::]` mappings in
a Compose override and confirming that the Docker host accepts IPv6 traffic.

Open inbound TCP 443. The daemon needs outbound HTTPS access to its ACME
directory and configured relay nodes. Public ingress is opaque TLS and cannot
sit behind an HTTPS-terminating reverse proxy: `tnld` selects its control API or
an application route from the original SNI without decrypting route traffic.

## Start Standalone

Prerequisites:

- A Linux host with Docker Engine and Docker Compose v2.
- A verified, digest-pinned tnl image.
- DNS for `tnl.<domain>` and `*.apps.<domain>`.
- An ACME service that supports TLS-ALPN-01 and the configured application
  certificate profile.

Work from the repository's `deploy` directory:

```console
cd deploy
install -m 0600 .env.example .env
```

Set these values in `.env`:

- `TNL_IMAGE`: the verified image digest, such as
  `ghcr.io/0xcadams/tnl@sha256:...`.
- `TNLD_DOMAIN`: the base domain from which control and route names are derived.
- `TNLD_ACME_DIRECTORY_URL`, `TNLD_ACME_EMAIL`, and
  `TNLD_ACME_ACCEPT_TERMS=true`: the ACME account configuration.
- `TNLD_ACME_PROFILE`: the profile used for application certificates.
- `TNLD_RELAY_PROVIDER=tailcat`: explicit consent to use Tailcat's hosted public
  relays.

Tailcat provider mode fetches the provider map once, measures the available
regions, and stores only the selected region in daemon state. Restarts use that
pinned region without fetching a mutable provider map. Tailcat is an external
network dependency: review its service and privacy terms before opting in.

Start the daemon and inspect the control endpoint:

```console
docker compose pull
docker compose up -d
docker compose logs --no-log-prefix tnld
curl --fail --silent --show-error https://tnl.example.com/v1/capabilities
```

The capabilities response proves that the control endpoint is serving. Before
accepting traffic, inspect logs for certificate errors and publish one complete
test route.

Prometheus metrics listen on container port 9090 and are intentionally not
published to the host. Attach a private scraper to the Compose network or add a
loopback-only port mapping. Never expose metrics directly to the Internet.

## Enroll A Client

On first startup, `tnld` creates a login token in its state volume. Retrieve
it without printing it in daemon logs or storing it in `.env`:

```console
docker compose exec tnld tnld login-token --state-dir /var/lib/tnl
```

Install and verify a release archive as described in [Releases](releases.md),
then log in. Browser authorization is preferred when the server advertises it;
otherwise `tnl login` prompts for the login token:

```console
tnl login https://tnl.example.com
tnl public http://127.0.0.1:3000 --name=demo
```

The publication command stays in the foreground and obtains the application
certificate automatically. It prints lifecycle messages to stderr; use
`--output=ndjson` for bounded machine-readable events on stdout. A second
interrupt exits immediately.

The route becomes `https://demo.apps.example.com`. Omit `--name` for a stable
random label. Manage durable claims with:

```console
tnl host list
tnl host release demo.apps.example.com
tnl logout
```

Release is permanent: the hostname is tombstoned and cannot be reclaimed.
Access credentials expire after 30 days at most. Existing lease-token
heartbeats can continue, but a later client restart or hostname command may
require `tnl login` again.

## OIDC Login

To enable browser login through an OpenID Connect provider, configure:

- `TNLD_OIDC_ISSUER`: the provider's exact HTTPS issuer.
- `TNLD_OIDC_CLIENT_ID`: a public client that supports the device authorization
  grant and `openid` scope.

The provider must publish standard discovery metadata and sign ID tokens with
RS256. The server verifies tokens locally. When OIDC login is available,
`tnl login` uses it by default; pass `--token` with the server's login token for
operator recovery.

## Route Export

An edge or standalone daemon can export ordered route lifecycle events and
minute/hour usage snapshots to a compatible receiver. Generate a dedicated
credential with `tnld token service`, then configure both values:

- `TNLD_EXPORT_URL`: the receiver's HTTPS base URL. Loopback HTTP is allowed for
  local development.
- `TNLD_EXPORT_TOKEN`: the generated service token.

Leaving both values empty disables export; configuring only one is invalid.
Worker mode cannot export because it does not own the durable route state. The
daemon retains an SQLite outbox across restarts and removes an item only after a
`204 No Content` response.

## Split Edge And Workers

`compose.split.yaml` runs one edge with durable SQLite state and one or more
stateless workers. Generate one worker credential with the verified `tnld`
binary and add it to `.env` as `TNLD_WORKER_TOKEN`:

```console
tnld token worker
docker compose --file compose.split.yaml pull
docker compose --file compose.split.yaml up -d --scale worker=2
docker compose --file compose.split.yaml exec edge \
  tnld login-token --state-dir /var/lib/tnl
```

The worker connects outbound to `wss://tnl.<domain>/internal/v1/worker`, so no
worker ingress port is required. Keep at least one worker running and size
`TNLD_WORKER_CAPACITY` for the intended fixed pool.

This topology scales route work and tolerates an individual worker restart. It
does not make the edge highly available: the edge and its SQLite volume remain
a single state authority, and assignments are process-local. Do not share its
volume or run multiple edges against it. Automated scale-in should wait for a
documented drain policy and workload-specific qualification.

## Custom Relays

Custom DERP remains available as an advanced override. Remove
`TNLD_RELAY_PROVIDER`, mount an approved Tailscale DERP map smaller than 1 MiB,
and set `TNLD_RELAY_MAP_FILE`. If the map contains multiple regions, also set
`TNLD_RELAY_PROFILE` to the selected `RegionCode`; a single valid region is
selected automatically.

Only install a reviewed map on the daemon. Clients and workers fetch the
selected region from the control API. The endpoint is unauthenticated so
workers can bootstrap; never include credentials or unnecessary private
metadata in the map.

To deliberately re-measure and replace a Tailcat provider pin, stop the daemon
and run the offline refresh command against its state volume:

```console
docker compose stop tnld
docker compose run --rm tnld relay refresh --state-dir /var/lib/tnl
docker compose start tnld
```

## State And Recovery

`tnld` stores SQLite files, ACME account and certificate data, the login
token, and the pinned relay region under `/var/lib/tnl`. The default Compose
project keeps that directory in the `tnl_tnld-state` named volume.

Only take cold backups: stop `tnld`, archive the complete volume, and then
restart it. Copying only `tnld.db` omits required files; copying a live database
can lose WAL transactions or produce an inconsistent backup. See
[Releases](releases.md) for backup, restore, upgrade, and rollback commands.

Treat backups and login tokens as secrets. Test restoration regularly on an
isolated host and encrypt backups at rest. `tnld` takes an exclusive state lock
and refuses to start a second state-owning process on the same directory.

To rotate the login token, stop the state owner and run:

```console
docker compose stop tnld
docker compose run --rm tnld login-token --state-dir /var/lib/tnl --rotate
docker compose start tnld
```

Rotation invalidates the old login credential but does not revoke access
tokens already issued from it. Use `tnl logout` from enrolled clients to revoke
their current access tokens.

Each client stores its access credential, private keys, certificate state, and
stable random-name selection under `TNL_STATE_DIR`. Its default is the user
configuration directory followed by `tnl` (`~/.config/tnl` on typical Linux
systems and `~/Library/Application Support/tnl` on macOS). Stop every `tnl`
process before backing up that complete directory.

## Operational Boundaries

- Run one state-owning `tnld` against each SQLite volume.
- Keep `tnl` and `tnld` on the same release before 1.0.
- Preserve `TNLD_DOMAIN` and the state volume across restarts.
- Do not restore an old database over a running daemon.
- Do not run an older daemon against state migrated by a newer release.
- Keep outer PROXY v2 disabled unless the only path to ingress is a trusted
  proxy configured to emit exactly one header.
