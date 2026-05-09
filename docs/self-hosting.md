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
| Public routes | `*.example.com` | TCP 443 |

Create wildcard A and, when applicable, AAAA records that resolve directly to
public ingress. The wildcard also covers `tnl.example.com`. If CAA records are
present, authorize the configured ACME CA.

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
- DNS for `*.<domain>`.
- An ACME service that supports TLS-ALPN-01 and the configured application
  certificate profile.

Work from the repository's `deploy` directory:

```console
cd deploy
install -m 0600 .env.example .env
```

Set these values in `.env`:

- `TNL_IMAGE`: the verified image digest, such as
  `ghcr.io/tnldotdev/tnl@sha256:...`.
- `TNLD_DOMAIN`: the base domain from which control and route names are derived.
- `TNLD_ACME_DIRECTORY_URL`, `TNLD_ACME_EMAIL`, and
  `TNLD_ACME_ACCEPT_TERMS=true`: the ACME account configuration.
- `TNLD_ACME_PROFILE`: the profile used for application certificates.
- `TNLD_ACCESS_TOKEN_LIFETIME`: lifetime of newly issued credentials; defaults
  to seven days and accepts values from five minutes through 30 days.
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
docker compose exec tnld tnld login-token --state-dir /var/lib/tnl
```

Install and verify a release archive as described in [Releases](releases.md),
then log in. Browser authorization is preferred when the server advertises it;
otherwise `tnl login` prompts for the login token:

```console
tnl login https://tnl.example.com
tnl host claim demo
tnl public localhost:3000 --name=demo
```

The publication command stays in the foreground and obtains the application
certificate automatically. It prints lifecycle messages to stderr; use
`--output=ndjson` for bounded machine-readable events on stdout. A second
interrupt exits immediately.

The route becomes `https://demo.example.com`. Omit `--name` for a fresh friendly
ephemeral name on every invocation. A persistent base can authorize its apex and
descendants up to eight labels deep. Manage persistent claims with:

```console
tnl host list
tnl host release demo.example.com
tnl logout
```

Managed release stops its routes and frees active quota, but the base remains
permanently bound to its original owner and may be reactivated. Access
credentials expire after `TNLD_ACCESS_TOKEN_LIFETIME`, seven days by default.
Existing lease-token heartbeats can continue, but a later client restart or
hostname command may require `tnl login` again.

To use a custom domain, run `tnl host claim docs.other.com.`. The command prints
the exact claim-specific CNAME records, or the apex verification CNAME and
ingress addresses, then waits for DNS proof. Custom-domain release stops its
routes and permits another owner to claim it only after fresh proof.

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

Custom DERP is the alternative to Tailcat. Leave `TNLD_RELAY_PROVIDER` unset,
mount an approved Tailscale DERP map smaller than 1 MiB, and set
`TNLD_RELAY_MAP_FILE`. Configuring both sources is rejected. If the map contains
multiple regions, also set `TNLD_RELAY_PROFILE` to the selected `RegionCode`; a
single valid region is selected automatically.

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

`tnld.db` contains all durable daemon state, including ACME data, the login
token, and the pinned relay region. The default Compose project stores it in the
`tnl_tnld-state` named volume.

Set `TNLD_BACKUP_URL=s3://bucket/path` to continuously replicate the database
with Litestream. AWS environment variables, shared credentials, instance roles,
and web identity are supported. For S3-compatible storage, add `endpoint` and
optional `region` query parameters to the URL. Protect the bucket with provider
encryption and access controls because backups contain credentials and private
keys.

At startup, a state-owning `tnld` restores the newest backup only when
`tnld.db` is absent. If the remote path is empty, it initializes a fresh
database. On shutdown it stops mutations and performs a final backup sync before
releasing the state lock.

Shutdown stops new control requests and public connections, then gives active
streams 30 seconds by default to finish before closing them. Long-lived
WebSockets should reconnect after a rollout. If `TNLD_DRAIN_TIMEOUT` is raised,
raise Compose `stop_grace_period` by the same amount; backup shutdown may use an
additional 15 seconds.

For a cold standby, keep its state volume empty and do not start it until the
active edge is stopped or fenced. Start it with the same backup URL and external
configuration, then verify the restored control endpoint before directing
traffic to it. Never run two state owners against one backup path. Test this
promotion regularly; the recovery point is the latest successful Litestream
sync.

Without `TNLD_BACKUP_URL`, stop `tnld` before archiving its state volume. Do not
copy a live SQLite file directly. See [Releases](releases.md) for upgrade and
rollback commands.

To rotate the login token, stop the state owner and run:

```console
docker compose stop tnld
docker compose run --rm tnld login-token --state-dir /var/lib/tnl --rotate
docker compose start tnld
```

Rotation invalidates the old login credential but does not revoke access
tokens already issued from it. Use `tnl logout` from enrolled clients to revoke
their current access tokens.

Each client stores its access credential, private keys, and certificate state
under `TNL_STATE_DIR`. Its default is the user configuration directory followed
by `tnl` (`~/.config/tnl` on typical Linux systems and
`~/Library/Application Support/tnl` on macOS). Linux protects secret state with
user-owned directories and `0600` files. On macOS, a profile key in Keychain
encrypts access tokens and route TLS private keys before they are written to the
state directory.

Stop every `tnl` process before backing up its complete state directory. A
macOS state-directory backup is not independently usable: preserve the login
Keychain through a platform-supported backup and restore to the same canonical
`TNL_STATE_DIR`. Without the matching Keychain item, reauthenticate and discard
the affected local route state so `tnl` can create new certificate keys.

## Operational Boundaries

- Run one state-owning `tnld` against each SQLite volume.
- Keep `tnl` and `tnld` on the same release before 1.0.
- Preserve `TNLD_DOMAIN` and the state volume across restarts.
- Do not restore an old database over a running daemon.
- Do not run an older daemon against state migrated by a newer release.
- Keep outer PROXY v2 disabled unless the only path to ingress is a trusted
  proxy configured to emit exactly one header.
