# Self-hosting tnl

This guide covers the supported standalone-preview deployment. Standalone mode
runs the control API, public ingress, route worker, certificate coordinator,
and SQLite database in one `tnld` process. Edge and worker modes are
experimental and are not covered by this runbook.

## Topology

Use separate control and public DNS names:

| Purpose | Example | Listener |
| --- | --- | --- |
| Control API | `core.example.com` | TCP 443 |
| Public routes | `*.apps.example.com` | TCP 443 |

Create A and, when applicable, AAAA records for both names. The wildcard must
resolve directly to public ingress. If CAA records are present, authorize the
CA configured for automatic certificates.

The reference Compose file publishes on IPv4 because its bind defaults are
`0.0.0.0`. Publish AAAA records only after adding equivalent `[::]` mappings in
a Compose override and confirming the Docker host accepts the listener over
IPv6.

Open inbound TCP 443. The daemon host needs outbound HTTPS access to the ACME
directory and configured DERP nodes. Each `tnl` client needs outbound HTTPS to
the control hostname and the configured DERP nodes; permit each endpoint port
listed in the approved DERP map, plus its STUN UDP port when direct-path
discovery is used. Public ingress is opaque TLS and cannot share its TCP 443
listener with an HTTPS reverse proxy. `tnld` selects the local control API or
an opaque route by SNI.

## Prerequisites

- A Linux host with Docker Engine and Docker Compose v2.
- A canonical route suffix such as `apps.example.com`.
- An approved Tailscale DERP map JSON file smaller than 1 MiB. Its selected
  region must be smaller than 64 KiB and have a unique `RegionCode` matching
  `TNLD_RELAY_PROFILE`.
- The matching `tnl` release on each client.

Install the reviewed relay map only on the daemon. Clients fetch the selected
region from the control API. The endpoint is unauthenticated so workers can
bootstrap; do not include credentials or unnecessary private metadata in the
map.

## Configure Compose

Work from the repository's `deploy` directory:

```console
cd deploy
install -m 0600 .env.example .env
```

Install the approved map at `deploy/derp-map.json`. Generate the bootstrap
credential with the same release of `tnl`:

```console
tnl token bootstrap
```

Edit `.env` and set:

- `TNL_IMAGE` to the verified release image digest, for example
  `ghcr.io/0xcadams/tnl@sha256:...`.
- `TNL_STATE_VOLUME` to the named volume holding daemon state. Keep the default
  for a first deployment and change it only during a tested restore or rollback.
- `TNLD_CONTROL_HOSTNAME` to the exact control API hostname.
- `TNLD_ROUTE_SUFFIX` to the public wildcard suffix.
- `TNLD_BOOTSTRAP_TOKEN` to the generated credential.
- `TNLD_RELAY_PROFILE` to a region code in `derp-map.json`.
- `TNLD_ACME_DIRECTORY_URL`, `TNLD_ACME_EMAIL`,
  `TNLD_ACME_ACCEPT_TERMS=true`, and `TNLD_ACME_PROFILE=tlsserver` to enable
  automatic control and application certificates. The CA must implement ACME
  Profiles, advertise the `tlsserver` profile, and support TLS-ALPN-01.

The example `.env` uses Let's Encrypt production. Check DNS, CAA, and TCP 443
before starting to avoid rate-limit failures. A CA staging directory is safer
for repeated issuance tests, but staging certificates are not publicly
trusted: install that CA's staging root only on isolated test clients before
using the `curl` and `tnl` commands below, and remove it after testing. Never
add a staging root to production trust stores.

The bootstrap token is a deployment root secret and remains necessary across
daemon restarts. Do not place `.env`, private keys, access tokens, or state
backups in source control. Docker exposes container environment variables to
users who can inspect the daemon, so restrict Docker access as carefully as
root access to the host.

## Start And Inspect

Start the pinned image:

```console
docker compose pull
docker compose up -d
docker compose logs --no-log-prefix tnld
```

The unauthenticated capabilities endpoint confirms control-plane readiness:

```console
curl --fail --silent --show-error \
  https://core.example.com/v1/capabilities
```

It does not prove that asynchronous application-certificate initialization or
TLS-ALPN-01 forwarding works. Before accepting traffic, inspect the daemon log
for certificate errors and publish one complete test route.

Prometheus metrics listen on container port 9090 and are intentionally not
published to the host. Attach a private scraper to the Compose network or add a
loopback-only port mapping. Never expose this listener directly to the public
Internet.

## Enroll A Client

Install and verify a release archive as described in [Releases](releases.md),
then exchange the bootstrap token. The approved relay map remains on the daemon,
and clients fetch its selected region from the core API:

```console
export TNL_CORE_URL=https://core.example.com
read -rsp 'Bootstrap token: ' TNL_BOOTSTRAP_TOKEN && printf '\n'
export TNL_BOOTSTRAP_TOKEN
export TNL_ACCESS_TOKEN="$(tnl auth exchange)"
unset TNL_BOOTSTRAP_TOKEN
```

Publish one literal-loopback HTTP target:

```console
tnl public http://127.0.0.1:3000 --host=demo
```

The command remains in the foreground and prints readiness and shutdown events
to stderr. Use `--output=ndjson` for machine-readable lifecycle events on
stdout. A second interrupt exits immediately.

Automatic certificate issuance requires the client to remain connected while
the CA reaches `demo.apps.example.com` on TCP 443. If automatic certificates
are disabled, provide a certificate and key to `tnl public`; the leaf must use
an ECDSA P-256 key and exactly one DNS SAN equal to the route hostname.

Hostname commands use the same `TNL_CORE_URL` and `TNL_ACCESS_TOKEN`:

```console
tnl host list
tnl host release demo.apps.example.com
```

Release is permanent. The hostname is tombstoned and cannot be reclaimed.
Access tokens expire after 30 days. Existing lease-token heartbeats can
continue, but a later client restart or hostname command requires a fresh
bootstrap exchange when the access token has expired.

## State And Recovery

`tnld` stores `tnld.db` and its SQLite WAL files under `/var/lib/tnl`. The
Compose project keeps that directory in the `tnl_tnld-state` named volume.
State includes credentials, hostname claims, route ownership, lease history,
and control and application ACME data.

Only take cold backups: stop `tnld`, archive the complete volume, and then
restart it. Copying only `tnld.db` omits the control certificate cache, and
copying it while the daemon is running can lose WAL transactions or produce an
inconsistent backup. See [Releases](releases.md)
for backup, restore, upgrade, and rollback commands.

Test restoration regularly on an isolated host. Treat backups as secrets and
encrypt them at rest.

Each client also keeps private keys, certificate state, and stable random-name
selection under `TNL_STATE_DIR`. Its default is the operating system user
configuration directory followed by `tnl` (`~/.config/tnl` on typical Linux
systems and `~/Library/Application Support/tnl` on macOS). Stop every `tnl`
process before backing up that complete directory, encrypt the backup, and
restore it only for the same user and control origin.

## Operational Boundaries

- Run one standalone `tnld` against a state volume. SQLite is not shared
  storage and this deployment is not active-active.
- Keep `tnl` and `tnld` on the same release during the preview period.
- Preserve the control hostname, route suffix, and state volume across
  restarts.
- Do not restore an old database over a running daemon.
- Do not run an older daemon against state migrated by a newer release.
- Bootstrap-token rotation is the recovery mechanism; there is no remote
  administration API in the preview release.
