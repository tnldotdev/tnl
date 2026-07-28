# Self-Hosting

Use standalone for a single-process deployment, or split control, ingress, and
relay roles for independent replication. See [Architecture](ARCHITECTURE.md) for
role and API ownership. This guide owns deployment and recovery procedures.

Only standalone and control processes use PostgreSQL. Ingress and relay are
stateless, receive no database credentials, and register through the private
cluster-authenticated control API. Run `tnld migrate` before starting control or
standalone; serving processes never migrate the database.

## Required Configuration

| Mode       | Required settings                                                                                                                                                             |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standalone | `TNLD_MODE`, `TNLD_DATABASE_URL`, `TNLD_SERVER_DOMAIN`, `TNLD_MANAGED_DEPLOYMENT_DOMAIN`, `TNLD_ACME_EMAIL`, `TNLD_ACME_ACCEPT_TERMS`, one authority mode, `TNLD_STORAGE_KEY` |
| Control    | The same control-owned settings as standalone, plus `TNLD_CLUSTER_SECRET`                                                                                                     |
| Ingress    | `TNLD_MODE`, `TNLD_CONTROL_HOSTNAME`, `TNLD_CLUSTER_SECRET`, `TNLD_INGRESS_ID`                                                                                                |
| Relay      | `TNLD_MODE`, `TNLD_CONTROL_HOSTNAME`, `TNLD_CLUSTER_SECRET`, `TNLD_RELAY_SERVICE_ID`, `TNLD_RELAY_ID`, `TNLD_RELAY_ADDRESS`, `TNLD_INTERNAL_RELAY_ADDRESS`                    |

`TNLD_CONTROL_HOSTNAME` is a canonical hostname without a scheme, path, or
port. HTTPS on port 443 is always implied. Process run IDs are generated locally
on each ingress or relay start.

Ingress and relay processes normally dial the private control API at
`TNLD_CONTROL_HOSTNAME` on TCP 9443. Set `TNLD_PRIVATE_CONTROL_ADDRESS` to a
private `host:port` when internal DNS uses a different address. TLS continues to
verify `TNLD_CONTROL_HOSTNAME`; the private address changes dialing only.

Listen addresses, limits, timing, metrics, a non-default ACME directory, and
static public certificate overrides are optional advanced settings. Private
internal PKI and custom trust-root settings are not part of the configuration.

Relay QUIC listeners use optimized UDP packet I/O by default. Set
`TNLD_RELAY_QUIC_PACKET_IO_MODE=basic` only when the network path is incompatible
with UDP out-of-band operations. Basic mode uses `ReadFrom` and `WriteTo`, fixes
the QUIC packet size at 1200 bytes, and disables path MTU discovery.

Control and standalone require exactly one authority mode. The built-in mode
leaves `TNLD_AUTHORITY_ENDPOINT` unset and requires `TNLD_LOGIN_TOKEN`. The
external mode sets `TNLD_AUTHORITY_ENDPOINT`, `TNLD_HOSTED_SECRET`, and the
`TNLD_OIDC_*` discovery settings, and rejects `TNLD_LOGIN_TOKEN`. The hosted
secret is shared only by control and the external authority.

The runtime URL belongs in `TNLD_DATABASE_URL`. The direct migration URL belongs
in `TNLD_DATABASE_DIRECT_URL` and is read only by `tnld migrate`. Use a pooled
runtime endpoint in replicated control deployments.

`tnld serve --config /path/to/tnl.yml` loads the static file's `tnld` section;
`TNLD_CONFIG` selects the same file through the environment. `tnld` accepts only
versioned YAML or JSON, performs no discovery, and resolves relative control TLS
certificate and private-key paths from the configuration directory. Use
`tnld config check --config /path/to/tnl.yml` to validate without serving.

## Storage Encryption And Recovery

Control and standalone require `TNLD_STORAGE_KEY`, a canonical unpadded
base64url encoding of exactly 32 random bytes. Keep an independent backup in the
deployment secret store. Losing the current and previous keys makes ACME account
keys, cached control certificate state, relay certificate keys, and retry
secrets unrecoverable. Ingress and relay processes must never receive either
storage key.

To rotate the key, deploy every control process with the new value in
`TNLD_STORAGE_KEY` and the old value in `TNLD_STORAGE_KEY_PREVIOUS`. Each process
claims old-key rows in bounded transactions and re-encrypts them while holding
row locks. Wait for every control replica to report that stored secrets were
re-encrypted, then remove `TNLD_STORAGE_KEY_PREVIOUS` in a second rolling deploy.

## Addresses And DNS

The server domain is an infrastructure suffix independent from the managed
deployment domain. For:

```text
TNLD_SERVER_DOMAIN=tnl.example.com
TNLD_MANAGED_DEPLOYMENT_DOMAIN=tunnels.example.com
```

configure DNS for:

```text
control.tnl.example.com       # public control and authority origin
ingress.tnl.example.com       # public route DNS target
relay.tnl.example.com         # standalone relay address
relay-a.tnl.example.com       # split relay service A
relay-b.tnl.example.com       # split relay service B
```

Public route hostnames beneath `tunnels.example.com` point to the ingress
address. Relay placement never changes public route DNS. Split relay service
labels come from `TNLD_RELAY_SERVICE_ID`.

Control obtains and renews exact public certificates through ACME.
`TNLD_ACME_EMAIL` and `TNLD_ACME_ACCEPT_TERMS=true` are required; the ACME
directory has a production default and may be overridden for private or test
directories. Standalone obtains its control and physical relay certificates
through TLS-ALPN-01. Static public certificates are optional advanced overrides.

Relay transport TLS uses an exact-hostname WebPKI certificate managed by
control. A relay retrieves its relay service certificate and decrypted private
key only while its exact process run ID and relay lease revision remain current,
then holds the material only in memory. Publishers use system trust roots and
exact hostname verification. Browser-facing route TLS remains publicly trusted
and terminates at the publisher.

For split deployments, configure `TNLD_ROUTE53_SERVER_ZONE_ID` on control with
the hosted zone containing `TNLD_SERVER_DOMAIN`. Control uses DNS-01 to issue and
renew each relay service certificate. The Route 53 credentials belong only on
control. A static relay certificate/key pair on each relay is the advanced
alternative.

To let control manage route A and AAAA records beneath the managed deployment
domain, configure `TNLD_ROUTE53_MANAGED_ZONE_ID` and at least one stable ingress
address through `TNLD_INGRESS_IPV4_ADDRESSES` or
`TNLD_INGRESS_IPV6_ADDRESSES`. Leaving these unset keeps route DNS
provider-free; operators must then publish the required records themselves.

## Bootstrap Management

Generate one bootstrap management token and store it in the deployment secret
store:

```console
tnld login-token
```

Provide it to every control replica as `TNLD_LOGIN_TOKEN`. Control and
standalone using the built-in authority refuse to start without it. The token
authenticates the built-in administrator identity and that identity's permanent
personal team; it is not a multi-user credential. Retain it for operator
recovery.

`tnl login` saves a revocable control session. Rotating `TNLD_LOGIN_TOKEN`
invalidates sessions issued from the previous token. `TNLD_ACCESS_TOKEN_LIFETIME`
defaults to one hour and accepts five minutes through 30 days.
`TNLD_REFRESH_TOKEN_LIFETIME` defaults to 30 days and allows up to 365 days;
existing sessions retain their stored absolute expiry.

## Interactive OIDC

The built-in authority can additionally exchange ID tokens from one OIDC issuer
for local control sessions. Configure all three settings together:

```text
TNLD_OIDC_ISSUER=https://example.us.auth0.com/
TNLD_OIDC_CLIENT_ID=your-public-client-id
TNLD_OIDC_LOGIN_FLOW=device_code
TNLD_OIDC_SCOPES=openid,profile,email
```

`TNLD_OIDC_LOGIN_FLOW` accepts `device_code` or
`authorization_code_pkce`. For Auth0, use a native application, enable the
selected grant, and configure loopback callbacks when using authorization-code
PKCE. The client is public: do not configure or distribute an OIDC client
secret. `openid` is required; `profile` and `email` provide useful local
identity details but are not required. `TNLD_OIDC_ISSUER` is the provider's
exact discovery issuer and may include a tenant- or realm-specific path.

The ID token must use RS256, name the configured client in its audience, and
have the configured issuer. Multiple audiences require `azp` equal to the
client ID. Device-code tokens may omit `nonce`; authorization-code PKCE tokens
must return the exact login nonce. Each raw ID token can be exchanged only once.

The first exchange for an exact issuer and subject atomically creates a local,
non-administrator identity with a permanent personal team. Later exchanges
update its bounded display name and verified email. Local access and refresh
tokens remain valid independently of `TNLD_LOGIN_TOKEN` rotation. Use the
bootstrap administrator for administrative operations.

External authority mode advertises the same OIDC settings to clients but does
not register the built-in authority routes. The external authority owns token
exchange and authorization decisions in that mode.

## Cluster Authentication

Generate one high-entropy `TNLD_CLUSTER_SECRET` and provide it to control,
ingress, and relay processes in a split deployment. It authenticates the private
control API at `control.<server-domain>:9443`; keep that listener restricted to
the deployment network. It is not a user credential and does not authorize the
public control API.

For rolling rotation, deploy the new value in `TNLD_CLUSTER_SECRET` and the old
value in `TNLD_CLUSTER_SECRET_PREVIOUS`, update every split process, then remove
the previous value. Standalone does not accept either setting because its
components communicate in process.

Each ingress and relay generates a process run ID at startup and registers its
configured process identity through the private API. Lease renewal remains
authorized only while the exact process run ID and lease revision are current.

## Standalone Compose

The reference [`compose.yaml`](../deploy/compose.yaml) runs migration and then a
standalone `tnld` process. Prepare the configuration:

```console
cd deploy
install -m 0600 .env.example .env
```

Replace every placeholder, including `TNLD_STORAGE_KEY`. Generate the bootstrap
token with `tnld login-token` and keep `TNL_IMAGE` pinned to a
[verified image digest](RELEASES.md#verify-the-container). Configure public DNS
and TCP/UDP 443, then start:

```console
docker compose pull
docker compose up -d
curl --fail https://control.tnl.example.com/v1/ready
```

The image runs as a non-root user with a read-only root filesystem. No daemon
state volume or certificate mount is required; PostgreSQL owns durable ACME,
route, placement, and product state.

Authenticate and publish from a local service:

```console
tnl login https://control.tnl.example.com --token
tnl publish 3000
```

The first successful login atomically creates the built-in identity, personal
team, owner membership, generated member label, and managed deployment-domain
default. The default publish hostname combines the local worktree beneath that
member namespace. The built-in personal team may also publish an exact route
directly beneath the managed deployment domain.

## Split Compose

The reference [`compose.split.yaml`](../deploy/compose.split.yaml) runs control,
ingress, and at least two independently addressable relay services. Replicas in
one relay service share a relay address and managed relay transport certificate,
but have unique relay IDs and process run IDs.

Expose public TCP 443 for control and ingress and public TCP and UDP 443 for each
relay service. Restrict TCP 9443 plus internal relay addresses to the
deployment network. Ingress and relay containers need no PostgreSQL, ACME,
authority, or administrator credentials and no certificate mounts.

## Administration

Only identities whose current authority context marks them as administrators
may use `tnl admin`. Inspect the server and its current relay leases with:

```console
tnl admin server status
tnl admin relays list
tnl admin maintenance list
```

Relay listing reads every cursor page. To drain one process, copy its relay ID,
process run ID, and lease revision from the listing:

```console
tnl admin relays drain relay-a \
  --relay-run-id relay-run-id \
  --relay-lease-revision 3 \
  --deadline 30s
```

Control immediately removes that exact lease from placement. After the relay's
next lease renewal, the process rejects new publisher connections and visitor
streams. Admitted visitor streams may finish until the deadline; any remaining
streams are closed at the deadline. The acknowledged process run remains
draining and does not register again. Restart the relay to create a new process
run ID after the drain completes.

Maintenance controls gate only new work and do not stop existing routes or
sessions:

```console
tnl admin maintenance disable route_creation
tnl admin maintenance disable route_session_creation
tnl admin maintenance disable certificate_issuance
tnl admin maintenance enable route_creation
```

Relay-drain and maintenance-control mutations are committed with durable audit
events in PostgreSQL. Their exact process revisions and generated request IDs
make stale or repeated mutations fail closed.

## Teams And Domains

The authority API is the sole owner of identities, authentication, teams,
memberships, invitations, domains, and current authorization decisions.
Self-hosted control serves the authority and control APIs at the same origin.
Hosted deployments advertise their external authority origin through control
discovery.

The bootstrap personal team starts with the managed deployment domain as its
default. Organization teams and claimed domains use the regular CLI:

```console
tnl team create resend --member-slug chase
tnl team use resend
tnl domain claim dev.resend.com --default
tnl team invite create --member-slug alex --role member
```

## Current Capabilities

The built-in authority implements bootstrap and OIDC login, local sessions,
teams, memberships, invitations, and domains. Hosted service authorization
belongs only to an external authority; the built-in
`/v1/service/authorize` path returns HTTP 404. Unknown public API paths also
return structured HTTP 404 problems.

Public server status, maintenance controls, relay listing, and exact relay drain
are available through `tnl admin`. Drain rejects new work and allows admitted
streams to finish until its deadline; live visitor streams are not replayed or
migrated.

## Route Usage

Only ingress records route usage. Ingress processes report revisioned time
buckets to control; controls aggregate and persist them by route and route
version. Configure `TNLD_ROUTE_USAGE_URL` and `TNLD_ROUTE_USAGE_TOKEN` together
to deliver durable reports to an external receiver. Leaving both empty disables
external delivery.

Source addresses and raw network identifiers must never be persisted or sent.
Visitor-network estimates use route-specific daily keyed sketches and are not a
count of people or devices.

The [receiver contract](../api/route-usage/v1/openapi.yaml) requires one result
per submitted item ID, without duplicate or unknown IDs. Accepted results omit
`code`; rejected results supply a valid rejection code. Control retries rejected
items and retries the batch after an invalid response or ambiguous delivery, so
receivers must handle redelivery idempotently. This is separate from
[CLI telemetry](../README.md#telemetry).

## Backups And Upgrades

### Backups

Use the PostgreSQL platform's supported backup tools. A logical backup requires
a direct URL whose role can read all tnl schemas:

```console
umask 077
mkdir -p backups
pg_dump --format=custom \
  --file="backups/tnl-$(date -u +%Y%m%d%H%M%S).dump" \
  "$TNLD_DATABASE_DIRECT_URL"
```

Record the matching binary and schema versions. Encrypt and restrict backups:
they contain identities, sessions, routes, authority state, and encrypted
certificate/ACME keys. Back up deployment secrets separately, especially
`TNLD_STORAGE_KEY` and any previous storage key still in use.

Test restoration into a new disposable database, never over the live database:

```console
createdb tnl_restore_test
pg_restore --exit-on-error --no-owner \
  --dbname=tnl_restore_test \
  backups/tnl-YYYYMMDDHHMMSS.dump
```

Use only an isolated deployment with the matching `tnld` version to exercise
login, team/domain reads, route creation, and route-session establishment.

### Upgrade

Serving processes require the exact supported schema and fail closed on older
or newer schemas. A same-schema binary update does not require a migration;
check release notes for protocol compatibility before mixing versions. No
general mixed-version or zero-downtime upgrade guarantee is provided.

For a schema-changing upgrade, plan an interruption:

1. [Verify release artifacts](RELEASES.md), review compatibility notes, and record the running versions.
2. Stop every control/standalone process, including background writers. Maintenance gates are not a substitute.
3. Take the final PostgreSQL backup and verify restoration before migrating. Preserve the matching deployment secrets.
4. Run the new image's `tnld migrate` once with `TNLD_DATABASE_DIRECT_URL`. Never give this URL to ingress or relay.
5. Start the new controls or standalone processes, then update ingress and relay services to the matching release.
6. Check [per-process readiness](OBSERVABILITY.md#service-health), certificates, leases, and routing-table progress. Publish a test route before resuming normal use.
7. Update `tnl` clients as required by the release's compatibility notes.

### Rollback

Never start an older control/standalone binary against a newer schema. After a
schema-changing upgrade:

1. Stop the new deployment and preserve a diagnostic database backup.
2. Restore the complete pre-upgrade backup into a new database, with its matching secrets.
3. Select the previous verified image digest and point control/standalone at the restored database.
4. Recreate the previous deployment without running the newer migration image.
5. Check process readiness, discovery, and logs; publish a test route and restore matching clients.

Rollback discards writes made after the backup. Without a pre-upgrade backup,
stop rather than attempting an in-place schema downgrade.

## Operational Checks

- Use the [probe matrix](OBSERVABILITY.md#service-health) for each role; public control readiness does not establish whole-server readiness.
- Scrape `TNLD_METRICS_LISTEN` only over a private network.
- Alert on certificate renewal failure, expired ingress or relay leases,
  insufficient ready publisher connections, capacity rejection, and control API
  failure.
- Keep the management token, database credentials, storage key, cluster secret,
  and optional DNS credentials in appropriately protected stores.
- Preserve public TCP and UDP 443 through firewalls and load balancers.
- Never give ingress or relay processes PostgreSQL credentials.

See [Observability](OBSERVABILITY.md) for metrics and alert guidance and
[Releases](RELEASES.md) for artifact verification.
