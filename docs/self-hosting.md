# self-hosting

A tnl server includes PostgreSQL and one or more `tnld` processes. Start with
the standalone role. Split control, ingress, and relay into separate services
only when you need independent scaling or failure boundaries.

This guide covers the deployment workflow. See the [`tnld` reference](tnld-reference.md)
for every setting and [observability](observability.md) for probes and metrics.

## choose a deployment shape

Standalone runs the complete tnl server in one process:

```text
tnl clients -------------------+
                              |
visitors ---------------------v
                       +-------------+
publishers ----------->| standalone  |<----> PostgreSQL
                       | tnld        |
                       +-------------+
```

It contains control, ingress, and two logical relay services. This is the
simplest production shape and the best place to start.

A split deployment separates the stateful and stateless roles:

```text
tnl clients ----------> control service --------> PostgreSQL
                              |
                              | routing and placement
                              v
visitors ------------> ingress service
                              |
                              v
                       relay services <---------- publishers
                         A and B
```

Only control connects to PostgreSQL. Ingress and relay are stateless. A split
deployment needs at least two independently addressable relay services.

## run standalone with compose

The reference [`deploy/compose.yaml`](../deploy/compose.yaml) runs the database
migration and then starts one standalone `tnld` process.

Prepare its environment:

```console
cd deploy
install -m 0600 .env.example .env
```

Replace every placeholder. At minimum, standalone needs:

| Setting                          | Purpose                                                |
| -------------------------------- | ------------------------------------------------------ |
| `TNLD_DATABASE_URL`              | Pooled runtime PostgreSQL connection.                  |
| `TNLD_DATABASE_DIRECT_URL`       | Direct PostgreSQL connection used only by migration.   |
| `TNLD_SERVER_DOMAIN`             | Infrastructure domain for control, ingress, and relay. |
| `TNLD_MANAGED_DEPLOYMENT_DOMAIN` | Domain used for managed public routes.                 |
| `TNLD_ACME_EMAIL`                | ACME account contact.                                  |
| `TNLD_ACME_ACCEPT_TERMS=true`    | Accept the selected ACME directory's terms.            |
| `TNLD_LOGIN_TOKEN`               | Built-in administrator login token.                    |
| `TNLD_STORAGE_KEY`               | Encrypt recoverable secrets in PostgreSQL.             |

Pin `TNL_IMAGE` to a [verified image digest](releases.md#verify-a-container).
Configure public DNS and allow TCP and UDP port 443, then start the deployment:

```console
docker compose pull
docker compose up -d
curl --fail https://control.tnl.example.com/v1/ready
```

The image runs as a non-root user with a read-only root filesystem. It needs no
state volume or certificate mount. PostgreSQL stores durable server state.

Connect a client and publish a test service:

```console
tnl login https://control.tnl.example.com --token
tnl publish 3000
```

Do not consider the deployment complete until a test route serves a real
request.

## migrate postgresql

`tnld migrate` is the only migration path:

```console
TNLD_DATABASE_DIRECT_URL='postgresql://tnl_migrate:...@db.example.test/tnl?sslmode=require' \
  tnld migrate
```

Serving control and standalone processes read only `TNLD_DATABASE_URL`. They
never migrate on startup and require the exact schema version supported by the
binary. Ingress and relay must not receive either database URL.

Use a pooled runtime URL for replicated control. Use a direct URL for migration
and logical backups.

## protect stored secrets

Control and standalone require `TNLD_STORAGE_KEY`: exactly 32 random bytes in
unpadded base64url form. The key encrypts recoverable ACME, certificate, and retry
material in PostgreSQL.

Back up the storage key separately in your deployment secret store. A database
backup cannot recover those secrets without the matching key.

Rotate it in two deployments:

1. Set the new value in `TNLD_STORAGE_KEY` and the old value in
   `TNLD_STORAGE_KEY_PREVIOUS` on every control process.
2. Wait for every control replica to report that re-encryption completed.
3. Remove `TNLD_STORAGE_KEY_PREVIOUS` from every control process.

Never give a storage key to ingress or relay.

## configure addresses and dns

The server domain and managed deployment domain serve different purposes:

```text
TNLD_SERVER_DOMAIN=tnl.example.com
TNLD_MANAGED_DEPLOYMENT_DOMAIN=tunnels.example.com
```

The server domain contains infrastructure names:

```text
control.tnl.example.com       control API and authority API
ingress.tnl.example.com       public visitor entry point
relay.tnl.example.com         standalone relay address
relay-a.tnl.example.com       split relay service A
relay-b.tnl.example.com       split relay service B
```

Public route hostnames beneath `tunnels.example.com` point to the ingress
address. They never point directly to a relay.

```text
api.alice.tunnels.example.com
              |
              v
       ingress address
              |
              v
       selected relay
```

Control obtains exact public certificates through ACME. Publishers verify relay
transport certificates with system trust roots. Private PKI and custom client
trust roots are not supported.

For split deployments, control can use Route 53 for relay certificate DNS-01
challenges and public route DNS. DNS credentials belong only on control. Static
certificates and operator-managed route records are advanced alternatives.

## configure authentication

Control and standalone require one authority configuration.

For the built-in authority, leave `TNLD_AUTHORITY_ENDPOINT` unset and set
`TNLD_LOGIN_TOKEN`. Generate the token once:

```console
tnld login-token
```

The token authenticates the built-in administrator identity and its permanent
personal team. Store it as an operator recovery credential. It is not a shared
multi-user login.

The built-in authority can also use OIDC for individual identities. An external
authority instead requires `TNLD_AUTHORITY_ENDPOINT`, OIDC discovery settings,
and `TNLD_HOSTED_SECRET`; it must not receive the login token. See
[authority and session settings](tnld-reference.md#authority-and-sessions).

## run split services

The reference [`deploy/compose.split.yaml`](../deploy/compose.split.yaml) runs
control, ingress, and two relay services.

Split processes need these settings in addition to the control-owned
configuration:

| Role    | Required process settings                                                                               |
| ------- | ------------------------------------------------------------------------------------------------------- |
| Control | `TNLD_CLUSTER_SECRET`                                                                                   |
| Ingress | `TNLD_CONTROL_HOSTNAME`, `TNLD_CLUSTER_SECRET`, `TNLD_INGRESS_ID`                                       |
| Relay   | Control hostname, cluster secret, relay service ID, relay ID, relay address, and internal relay address |

Ingress and relay normally call the private control API on TCP 9443. Restrict
that listener and every internal relay address to the deployment network.

Expose:

| Service            | Public ports    |
| ------------------ | --------------- |
| Control            | TCP 443         |
| Ingress            | TCP 443         |
| Each relay service | TCP and UDP 443 |

Give every relay process a unique relay ID. Replicas in one relay service share
the same relay service ID, public relay address, and relay transport certificate.

## rotate cluster authentication

Split processes use `TNLD_CLUSTER_SECRET` to authenticate private coordination.
It is not a user credential and does not authorize the public control API.

Rotate it without stopping all processes:

1. Put the new value in `TNLD_CLUSTER_SECRET` and the old value in
   `TNLD_CLUSTER_SECRET_PREVIOUS`.
2. Roll the change through control, ingress, and every relay.
3. Remove the previous value in a second rollout.

Standalone does not accept a configured cluster secret because its roles call
each other in process.

## administer the server

Use an administrator identity to inspect the deployment:

```console
tnl admin server status
tnl admin relays list
tnl admin maintenance list
```

Maintenance controls gate new work without stopping existing routes or sessions:

```console
tnl admin maintenance block route_session_creation
tnl admin maintenance allow route_session_creation
```

Drain one exact relay lease before removing a process:

```console
tnl admin relays drain relay-a \
  --relay-run-id relay-run-id \
  --relay-lease-revision 3 \
  --deadline 30s
```

Control immediately removes the lease from new placement. Existing visitor
streams can finish until the deadline. Restart the process after drain completes
to create a new process run ID.

## deliver route usage

Route usage delivery is optional. Set `TNLD_ROUTE_USAGE_URL` and
`TNLD_ROUTE_USAGE_TOKEN` together to send stored usage buckets to an HTTPS
receiver. Leave both empty to disable delivery.

Receivers must safely accept the same item more than once because uncertain
delivery is retried. The exact receiver contract is in
[`api/route-usage/v1/openapi.yaml`](../api/route-usage/v1/openapi.yaml).

Route usage never includes raw source addresses. It is separate from client
[telemetry](../readme.md#telemetry).

## back up and restore

Use your PostgreSQL platform's supported backup tools. A logical backup requires
a direct URL whose role can read every tnl schema:

```console
umask 077
mkdir -p backups
pg_dump --format=custom \
  --file="backups/tnl-$(date -u +%Y%m%d%H%M%S).dump" \
  "$TNLD_DATABASE_DIRECT_URL"
```

Record the matching binary and schema versions. Encrypt the backup and protect
it as sensitive data. Back up deployment secrets separately, especially the
current and previous storage keys.

Test restoration into a new disposable database, never over the live database:

```console
createdb tnl_restore_test
pg_restore --exit-on-error --no-owner \
  --dbname=tnl_restore_test \
  backups/tnl-YYYYMMDDHHMMSS.dump
```

Use an isolated deployment with the matching `tnld` version to test login,
team and domain reads, route creation, and publishing.

## upgrade

Serving processes require the exact supported schema. Mixed-version and
zero-downtime upgrades are not generally supported.

For an upgrade that changes the schema:

1. Verify the new release and read its compatibility notes.
2. Stop every control or standalone process, including background writers.
3. Take the final PostgreSQL backup and test its restoration.
4. Run the new image's `tnld migrate` once with the direct database URL.
5. Start the new control service or standalone process.
6. Update ingress and relay to the matching release.
7. Check readiness, leases, certificates, and routing freshness.
8. Publish a test route before returning the server to normal use.

Maintenance gates do not replace stopping control-side writers before a schema
migration.

## roll back

Never start an older control or standalone binary against a newer schema.

After a schema-changing upgrade:

1. Stop the new deployment and preserve a diagnostic backup.
2. Restore the complete pre-upgrade backup into a new database.
3. Restore the matching deployment secrets.
4. Start the previous verified image against the restored database.
5. Check readiness and publish a test route.

Rollback discards writes made after the backup. Do not attempt an in-place
schema downgrade.

## know the current boundaries

- The built-in authority supports login tokens, OIDC login, sessions, teams,
  memberships, invitations, and domains.
- Only an external authority supports service authorization.
- Live visitor streams are not replayed or migrated after a failure.
- Private PKI and custom trust roots are not supported.
- Serving processes never migrate PostgreSQL automatically.
- A readiness probe does not prove that every route or local service works.

## check the deployment

- Probe every process with the role-specific checks in
  [observability](observability.md#check-process-health).
- Keep the metrics listener private.
- Alert on certificate renewal, expired leases, capacity rejection, control API
  errors, and file-descriptor pressure.
- Preserve public TCP and UDP 443 through firewalls and load balancers.
- Never give PostgreSQL or storage credentials to ingress or relay.
- Publish a real test route after deployment and after every upgrade.
