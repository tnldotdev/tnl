# Self-Hosting

The tnl server runs `tnld` in one of four roles:

| `TNLD_MODE`  | Responsibilities                                                                          |
| ------------ | ----------------------------------------------------------------------------------------- |
| `standalone` | Control, ingress, and two logical relay services in one process                           |
| `control`    | Control and authority APIs, PostgreSQL state, placement, certificates, and administration |
| `ingress`    | Public visitor acceptance, route policy, usage, and internal forwarding                   |
| `relay`      | Publisher connections and internal forwarding to local publishers                         |

Only standalone and control processes use PostgreSQL. Ingress and relay are
stateless, receive no database credentials, and bootstrap through service
enrollment. Run `tnld migrate` before starting control or standalone; serving
processes never migrate the database.

## Required Configuration

| Mode       | Required settings                                                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standalone | `TNLD_MODE`, `TNLD_DATABASE_URL`, `TNLD_SERVER_DOMAIN`, `TNLD_MANAGED_DEPLOYMENT_DOMAIN`, `TNLD_ACME_EMAIL`, `TNLD_ACME_ACCEPT_TERMS`, `TNLD_LOGIN_TOKEN` |
| Control    | The same control-owned settings as standalone                                                                                                             |
| Ingress    | `TNLD_MODE`, `TNLD_CONTROL_HOSTNAME`, `TNLD_SERVICE_ENROLLMENT_TOKEN`, `TNLD_INGRESS_ID`                                                                  |
| Relay      | `TNLD_MODE`, `TNLD_CONTROL_HOSTNAME`, `TNLD_SERVICE_ENROLLMENT_TOKEN`, `TNLD_RELAY_ID`, `TNLD_INTERNAL_RELAY_ADDRESS`                                     |

`TNLD_CONTROL_HOSTNAME` is a canonical hostname without a scheme, path, or
port. HTTPS on port 443 is always implied. Process run IDs and service private
keys are generated locally on each ingress or relay start.

Listen addresses, limits, timing, metrics, a non-default ACME directory, and
static public certificate overrides are optional advanced settings. Static
service-mTLS certificate, private-key, and trust-bundle files are not part of
the final configuration.

The runtime URL belongs in `TNLD_DATABASE_URL`. The direct migration URL belongs
in `TNLD_DATABASE_DIRECT_URL` and is read only by `tnld migrate`. Use a pooled
runtime endpoint in replicated control deployments.

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
labels come from enrollment-token scope rather than relay environment variables.

Control obtains and renews the public certificate for its control hostname
through ACME. `TNLD_ACME_EMAIL` and `TNLD_ACME_ACCEPT_TERMS=true` are required;
the ACME directory has a production default and may be overridden for private or
test directories. Static public certificates are optional advanced overrides.

Relay transport TLS uses private PKI. Control's durable service CA issues a
one-hour server certificate for each relay service hostname. Publishers
receive the service CA certificate from authenticated route-session setup and
use it only for relay transport connections. Browser-facing route TLS remains
publicly trusted and terminates at the publisher.

## Bootstrap Management

Generate one bootstrap management token and store it in the deployment secret
store:

```console
tnld login-token
```

Provide it to every control replica as `TNLD_LOGIN_TOKEN`. Control and
standalone refuse to start without it. The token authenticates the built-in
administrator identity and that identity's permanent personal team; it is not a
multi-user credential. Use OIDC for multiple users and retain the bootstrap
token for operator recovery.

## Service Enrollment

After authenticating as an administrator, create one reusable ingress token and
one token for each relay service:

```console
tnl admin enrollment-tokens create --role ingress
tnl admin enrollment-tokens create --role relay --relay-service relay-a
tnl admin enrollment-tokens create --role relay --relay-service relay-b
```

The raw `tnl_enrollment_...` token is returned exactly once. Control stores only
its lookup ID, digest, role, relay-service scope, audit metadata, and revocation
state. A token remains valid until revoked, so one ingress token supports all
ingress replicas and one relay-service token supports all replicas in that
service. Each replica still uses a unique ingress ID or relay ID.

Each split process generates its service private key locally and sends a CSR,
role, and process identity to `POST /v1/service-enrollments` on the public
control HTTPS endpoint. Enrollment returns:

- A one-hour service certificate.
- The service CA trust bundle.
- The role's internal control API endpoint.
- Stable facts needed for lease registration.

Relay enrollment also returns the relay service ID, derived relay address, TLS
server name, and shared one-hour relay transport certificate/key. A process
re-enrolls with the same token after approximately thirty minutes. Revoked or
cross-role tokens cannot enroll. An expired service certificate makes the
process unready and prevents lease renewal.

The ingress control API uses `control.<server-domain>:9443`; the relay control
API uses `control.<server-domain>:9444`. Keep both listeners private. Their
contracts, certificates, permissions, and clients remain separate.

Standalone does not enroll itself. Its control, ingress, and two logical relay
services use the same authorization and stale-state boundaries through
in-process calls.

## Standalone Compose

The reference [`compose.yaml`](../deploy/compose.yaml) runs migration and then a
standalone `tnld` process. Copy the example configuration, replace every
placeholder, and start the deployment:

```console
cd deploy
install -m 0600 .env.example .env
docker compose pull
docker compose up -d
curl --fail https://control.tnl.example.com/v1/ready
```

The image runs as a non-root user with a read-only root filesystem. No daemon
state volume or certificate mount is required; PostgreSQL owns durable service
CA, ACME, route, placement, and product state.

Authenticate and publish from a local service:

```console
tnl login https://control.tnl.example.com --token
tnl publish 3000
```

The first successful login atomically creates the built-in identity, personal
team, owner membership, generated member label, and managed deployment-domain
default. The default publish hostname is that member namespace. The built-in
personal team may also publish an exact route directly beneath the managed
deployment domain.

## Split Compose

The reference [`compose.split.yaml`](../deploy/compose.split.yaml) runs control,
ingress, and at least two independently addressable relay services. Replicas in
one relay service share an enrollment token, relay address, and short-lived
relay transport certificate, but have unique relay IDs and process run IDs.

Expose public TCP 443 for control and ingress and public TCP and UDP 443 for each
relay service. Restrict TCP 9443 and 9444 plus internal relay addresses to the
deployment network. Ingress and relay containers need no PostgreSQL, ACME,
authority, or administrator credentials and no certificate mounts.

Each route session maintains exactly two connection slots assigned to distinct
relay services. Initial routability requires the route certificate and both
publisher connections ready. Afterward, one ready connection remains routable
while the publisher replenishes toward two.

## Teams And Domains

The authority API is the sole owner of identities, authentication, teams,
memberships, invitations, domains, and signed authorizations. Self-hosted
control serves the authority and control APIs at the same origin. Hosted
deployments advertise their external authority origin through control discovery.

The bootstrap personal team starts with the managed deployment domain as its
default. Organization teams and claimed domains use the regular CLI:

```console
tnl team create resend --slug chase
tnl team use resend
tnl domain claim dev.resend.com --default
tnl team invite create --slug alex --role member
```

## Maintenance And Drain

Maintenance controls independently gate route creation, route-session creation,
and certificate issuance:

```console
tnl admin maintenance list
tnl admin maintenance set route_session_create off
```

Drain a relay process before planned removal:

```console
tnl admin relays drain relay-a-1 --deadline 30s
```

Draining rejects new work, removes the process from placement and ingress
selection, and allows admitted streams to finish until the deadline. Live
visitor streams are not replayed or migrated.

Revoke an enrollment token to prevent future enrollment:

```console
tnl admin enrollment-tokens list
tnl admin enrollment-tokens revoke <token-id>
```

Already issued service certificates remain valid only until their one-hour
expiration.

## Route Usage

Only ingress records route usage. Ingress processes report revisioned time
buckets to control; controls aggregate and persist them by route and route
version. Configure `TNLD_ROUTE_USAGE_URL` and `TNLD_ROUTE_USAGE_TOKEN` together
to deliver durable reports to an external receiver. Leaving both empty disables
external delivery.

Source addresses and raw network identifiers must never be persisted or sent.
Visitor-network estimates use route-specific daily keyed sketches and are not a
count of people or devices.

## Backups And Upgrades

Back up PostgreSQL with the platform's supported physical or logical backup
tools. The backup contains the service CA and other certificate state, so apply
the same access controls used for deployment secrets. Test restoration into an
isolated database and verify `tnld migrate` before changing production.

Upgrade in this order:

1. Verify release artifacts and review release notes.
2. Back up and test restore of PostgreSQL.
3. Stop writes or enable the relevant maintenance controls.
4. Run the new image's `tnld migrate` with `TNLD_DATABASE_DIRECT_URL`.
5. Roll controls, ingress, and then relay services while monitoring leases and ready publisher connections.
6. Re-enable maintenance controls after readiness and route checks pass.

Serving processes require the exact supported schema version and fail closed on
older or newer schemas.

## Operational Checks

- Probe `/v1/health` for HTTP serving and `/v1/ready` for control readiness.
- Scrape `TNLD_METRICS_LISTEN` only over a private network.
- Alert on certificate renewal failure, expired ingress or relay leases,
  insufficient ready publisher connections, capacity rejection, and control API
  failure.
- Keep the management token, enrollment tokens, database credentials, service
  CA state, and optional DNS credentials in appropriately protected stores.
- Preserve public TCP and UDP 443 through firewalls and load balancers.
- Never give ingress or relay processes PostgreSQL credentials.

See [Observability](OBSERVABILITY.md) for metrics and alert guidance and
[Releases](RELEASES.md) for artifact verification.
