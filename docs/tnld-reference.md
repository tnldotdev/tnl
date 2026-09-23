# `tnld` reference

`tnld` runs a tnl server as a standalone, control, ingress, or relay process.
Use [self-hosting](self-hosting.md) for the deployment workflow. Use this page
when you need an exact command or setting.

## commands

| Command                           | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `tnld serve`                      | Run one configured `tnld` process. This is the default command. |
| `tnld migrate`                    | Apply embedded PostgreSQL migrations.                           |
| `tnld login-token`                | Generate a login token.                                         |
| `tnld config check --config=PATH` | Validate static server configuration.                           |
| `tnld version`                    | Print release version information.                              |

Bare `tnld`, `tnld serve`, and a command line beginning with a serve flag all
run the server. Every command accepts `-h` and `--help`.

## understand output and exit status

`tnld` does not use the client CLI's diagram renderer.

- Help, `login-token`, and `version` write to stdout.
- Successful `migrate` and `config check` commands are silent.
- A serving process normally writes only operational logs to stderr.
- Errors are written once as `tnld: <error>`.
- Success exits 0. Parsing, configuration, migration, startup, and runtime
  failures exit 1.

SIGINT or SIGTERM begins graceful drain. A supervisor's stop grace period should
exceed `TNLD_DRAIN_TIMEOUT`; cleanup can continue for up to six more seconds.

## serve a role

```text
tnld [serve] [--config=PATH] [serve flags]
```

`serve` validates configuration before opening listeners. Control and
standalone connect to an already-migrated database and require the exact
supported schema. Ingress and relay register through control and never connect
to PostgreSQL.

| Role       | Required settings                                                                              | Responsibility                                                               |
| ---------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Standalone | Database, server and managed domains, ACME, authority, storage key                             | Compose control, ingress, and two logical relay services.                    |
| Control    | Standalone's control-owned settings plus cluster secret                                        | Store state and coordinate placement, certificates, DNS, and administration. |
| Ingress    | Control hostname, cluster secret, ingress ID                                                   | Accept visitors, apply route policy, and forward each connection.            |
| Relay      | Control hostname, cluster secret, relay service and process IDs, public and internal addresses | Hold publisher connections and visitor streams.                              |

The tables below use `S`, `C`, `I`, and `R` for standalone, control, ingress,
and relay.

## set configuration values

Every serve setting has three names:

```text
--server-domain
TNLD_SERVER_DOMAIN
server_domain
```

The first is a command flag, the second is an environment variable, and the
third is the key under the static `tnld` configuration section. The tables list
the environment name because it makes the other two forms predictable.

The config selector is not a file field. Repeatable file keys also stay singular
while their environment names are plural.

Highest precedence wins:

```text
command-line flag
        |
        v
TNLD_* environment variable
        |
        v
tnld file field
        |
        v
parser and role default
```

An explicitly empty environment variable still overrides a file value.
`--config` overrides `TNLD_CONFIG`.

`TNLD_DATABASE_DIRECT_URL` is outside this system. Only `tnld migrate` reads it.

## selection, database, and probes

| Environment           | Default          | Applies | Meaning                                                                                  |
| --------------------- | ---------------- | ------- | ---------------------------------------------------------------------------------------- |
| `TNLD_CONFIG`         | unset            | all     | Select one YAML or JSON configuration file.                                              |
| `TNLD_ROLE`           | `standalone`     | all     | Select `standalone`, `control`, `ingress`, or `relay`.                                   |
| `TNLD_DATABASE_URL`   | unset            | S/C     | Required pooled PostgreSQL runtime URL.                                                  |
| `TNLD_METRICS_LISTEN` | `127.0.0.1:9090` | all     | Private HTTP address for health, readiness, metrics, and diagnostics. Empty disables it. |

Ingress and relay reject a database URL. Serving processes never read
`TNLD_DATABASE_DIRECT_URL` and never run migrations.

## listeners and names

| Environment                      | Role default                      | Applies      | Meaning                                                                             |
| -------------------------------- | --------------------------------- | ------------ | ----------------------------------------------------------------------------------- |
| `TNLD_CONTROL_LISTEN`            | `:443`                            | C            | Public control HTTPS address. Standalone uses its shared public TCP listener.       |
| `TNLD_PRIVATE_CONTROL_LISTEN`    | `:9443`                           | C            | Private ingress and relay API. Standalone calls control in process.                 |
| `TNLD_INGRESS_LISTEN`            | `:443`                            | S/I          | Public visitor address and standalone shared TCP address.                           |
| `TNLD_RELAY_TCP_LISTEN`          | `:443`                            | R            | Public TLS/TCP publisher address. Standalone uses its shared TCP address.           |
| `TNLD_RELAY_UDP_LISTEN`          | `:443`                            | S/R          | Public QUIC publisher address.                                                      |
| `TNLD_INTERNAL_RELAY_LISTEN`     | relay derives the advertised port | R            | Internal forwarding listener.                                                       |
| `TNLD_DNS_SERVER`                | system resolver                   | S/C with DNS | Resolver used to verify claimed domains.                                            |
| `TNLD_SERVER_DOMAIN`             | unset                             | S/C          | Required infrastructure DNS suffix.                                                 |
| `TNLD_MANAGED_DEPLOYMENT_DOMAIN` | unset                             | S/C          | Required domain used for managed route namespaces.                                  |
| `TNLD_CONTROL_HOSTNAME`          | unset                             | I/R          | Required canonical control hostname without scheme, path, or port.                  |
| `TNLD_PRIVATE_CONTROL_ADDRESS`   | unset                             | I/R          | Optional private `host:port` dial address. TLS still verifies the control hostname. |

Listener addresses use `host:port`. An empty host such as `:443` is valid. IPv6
addresses require brackets.

## public tls and acme

| Environment                         | Default                  | Applies | Meaning                                                      |
| ----------------------------------- | ------------------------ | ------- | ------------------------------------------------------------ |
| `TNLD_CONTROL_TLS_CERTIFICATE_FILE` | unset                    | S/C     | Static control certificate chain. Pair with its key.         |
| `TNLD_CONTROL_TLS_PRIVATE_KEY_FILE` | unset                    | S/C     | Static control private key.                                  |
| `TNLD_RELAY_TLS_CERTIFICATE_FILE`   | unset                    | S/R     | Static relay transport certificate chain. Pair with its key. |
| `TNLD_RELAY_TLS_PRIVATE_KEY_FILE`   | unset                    | S/R     | Static relay transport private key.                          |
| `TNLD_ACME_DIRECTORY_URL`           | Let's Encrypt production | S/C     | ACME directory used for automatic certificates.              |
| `TNLD_ACME_EMAIL`                   | unset                    | S/C     | Required ACME account email.                                 |
| `TNLD_ACME_ACCEPT_TERMS`            | false                    | S/C     | Must be true.                                                |
| `TNLD_ACME_PROFILE`                 | `tlsserver`              | S/C     | Certificate profile name.                                    |
| `TNLD_ROUTE_CERTIFICATE_WORKERS`    | `4`                      | S/C     | Concurrent route certificate workers, from 1 through 8.      |

Certificate and key overrides must be supplied in pairs. Static control
certificates do not remove the ACME requirement because control still issues
route certificates.

## authority and sessions

| Environment                   | Default            | Applies                | Meaning                                              |
| ----------------------------- | ------------------ | ---------------------- | ---------------------------------------------------- |
| `TNLD_LOGIN_TOKEN`            | unset              | S/C built-in authority | Required built-in administrator login token.         |
| `TNLD_AUTHORITY_ENDPOINT`     | built-in authority | S/C                    | External authority HTTPS origin.                     |
| `TNLD_OIDC_ISSUER`            | unset              | S/C                    | OIDC discovery issuer.                               |
| `TNLD_OIDC_CLIENT_ID`         | unset              | S/C                    | Public OIDC client ID.                               |
| `TNLD_OIDC_LOGIN_FLOW`        | unset              | S/C                    | `device_code` or `authorization_code_pkce`.          |
| `TNLD_OIDC_SCOPES`            | `openid`           | S/C                    | Comma-separated scopes; must include `openid`.       |
| `TNLD_ACCESS_TOKEN_LIFETIME`  | `1h`               | S/C                    | New access-token lifetime, from `5m` through `720h`. |
| `TNLD_REFRESH_TOKEN_LIFETIME` | `720h`             | S/C                    | Absolute session lifetime, up to `8760h`.            |

The built-in authority requires a login token and may also use OIDC. An external
authority requires its endpoint, complete OIDC settings, and a hosted secret; it
rejects the login token.

The OIDC client is public. Do not configure or distribute a client secret.
Authorization-code PKCE requires localhost callbacks. ID tokens must use RS256,
the configured issuer, and the configured client audience.

## dns and route usage

| Environment                    | Default     | Applies           | Meaning                                                   |
| ------------------------------ | ----------- | ----------------- | --------------------------------------------------------- |
| `TNLD_ROUTE53_REGION`          | `us-east-1` | S/C with Route 53 | AWS signing region.                                       |
| `TNLD_ROUTE53_MANAGED_ZONE_ID` | unset       | S/C               | Zone used for public route DNS.                           |
| `TNLD_ROUTE53_SERVER_ZONE_ID`  | unset       | S/C               | Zone used for relay certificate DNS-01.                   |
| `TNLD_INGRESS_IPV4_ADDRESSES`  | empty       | S/C managed DNS   | Stable ingress IPv4 addresses published in route records. |
| `TNLD_INGRESS_IPV6_ADDRESSES`  | empty       | S/C managed DNS   | Stable ingress IPv6 addresses published in route records. |
| `TNLD_ROUTE_USAGE_URL`         | unset       | S/C               | HTTPS route usage receiver URL.                           |
| `TNLD_ROUTE_USAGE_TOKEN`       | unset       | S/C               | Bearer token paired with the receiver URL.                |

A managed zone requires at least one ingress address. Ingress addresses require
a managed zone. AWS credentials come from the normal AWS SDK configuration
chain; `tnld` has no AWS credential flags.

Route usage URL and token must be configured together. HTTP is accepted only for
loopback testing.

## secrets

| Environment                    | Applies                | Meaning                                                            |
| ------------------------------ | ---------------------- | ------------------------------------------------------------------ |
| `TNLD_CLUSTER_SECRET`          | C/I/R                  | Current shared secret for split-process coordination.              |
| `TNLD_CLUSTER_SECRET_PREVIOUS` | C/I/R                  | Previous cluster secret accepted during rotation.                  |
| `TNLD_HOSTED_SECRET`           | S/C external authority | Current secret shared by control and the external authority.       |
| `TNLD_HOSTED_SECRET_PREVIOUS`  | S/C external authority | Previous hosted secret accepted during rotation.                   |
| `TNLD_STORAGE_KEY`             | S/C                    | Current 32-byte storage encryption key in unpadded base64url form. |
| `TNLD_STORAGE_KEY_PREVIOUS`    | S/C                    | Previous storage key used during re-encryption.                    |

Cluster and hosted secrets must contain 32 through 4096 bytes with no whitespace
or comma. Current and previous values must differ.

Standalone rejects configured cluster secrets. Ingress and relay reject hosted
secrets and storage keys.

## split-process identity

| Environment                   | Applies | Meaning                                         |
| ----------------------------- | ------- | ----------------------------------------------- |
| `TNLD_INGRESS_ID`             | I       | Required stable ingress process identity.       |
| `TNLD_RELAY_SERVICE_ID`       | R       | Required stable relay service identity.         |
| `TNLD_RELAY_ID`               | R       | Required unique relay process identity.         |
| `TNLD_RELAY_ADDRESS`          | R       | Required public relay hostname and port.        |
| `TNLD_INTERNAL_RELAY_ADDRESS` | R       | Required internal forwarding hostname and port. |

Ingress and relay generate a new process run ID every time they start. Process
run IDs are not configurable.

## capacity and policy

| Environment                                | Default | Applies | Meaning                                                      |
| ------------------------------------------ | ------: | ------- | ------------------------------------------------------------ |
| `TNLD_SOURCE_CONNECTION_RATE`              |    `50` | S/I     | New ordinary visitor connections per second for each source. |
| `TNLD_SOURCE_CONNECTION_BURST`             |   `200` | S/I     | Per-source burst allowance.                                  |
| `TNLD_CLIENT_HELLO_CONNECTION_LIMIT`       |  `1024` | S/I     | Concurrent metadata and ClientHello inspections.             |
| `TNLD_CHALLENGE_CONNECTION_LIMIT`          |  `1024` | S/I     | Concurrent active route certificate checks.                  |
| `TNLD_CHALLENGE_HOSTNAME_CONNECTION_LIMIT` |     `8` | S/I     | Route certificate checks per hostname.                       |
| `TNLD_STANDALONE_CONTROL_CONNECTION_LIMIT` |  `1024` | S       | Concurrent standalone control handoffs.                      |
| `TNLD_STANDALONE_RELAY_CONNECTION_LIMIT`   |  `4096` | S       | Concurrent standalone relay TCP handoffs.                    |
| `TNLD_VISITOR_CONNECTION_LIMIT`            | `20000` | S/I     | Concurrent ordinary visitor connections.                     |
| `TNLD_ROUTE_CONNECTION_LIMIT`              |   `500` | S/I     | Concurrent visitor connections for one route.                |
| `TNLD_PUBLISHER_CONNECTION_LIMIT`          |  `4000` | S/R     | Publisher connections held by one relay process.             |
| `TNLD_RELAY_STREAM_CAPACITY`               |  `4096` | S/R     | Visitor streams held by one relay process.                   |
| `TNLD_QUIC_MAX_INCOMING_STREAMS`           |  `4096` | S/R     | Incoming QUIC streams per publisher connection.              |
| `TNLD_REQUIRE_PROXY_HEADER`                |   false | S/I     | Require a trusted outer PROXY v2 header at public ingress.   |

These limits are process-local. Replicas do not share counters or source token
buckets. Source IPv6 addresses are grouped by /64.

Certificate checks and standalone service handoffs have their own capacities and
do not consume ordinary visitor source tokens.

## timing

| Environment                   | Default | Applies | Meaning                                        |
| ----------------------------- | ------- | ------- | ---------------------------------------------- |
| `TNLD_QUIC_IDLE_TIMEOUT`      | `45s`   | S/R     | Publisher QUIC idle timeout.                   |
| `TNLD_INGRESS_LEASE_DURATION` | `30s`   | S/C     | Lease duration granted to ingress.             |
| `TNLD_RELAY_LEASE_DURATION`   | `30s`   | S/C     | Lease duration granted to relay.               |
| `TNLD_LEASE_RENEWAL_INTERVAL` | `10s`   | S/I/R   | Lease renewal frequency.                       |
| `TNLD_CONTROL_RETRY_INTERVAL` | `1s`    | S/I/R   | Retry delay after a transient control failure. |
| `TNLD_ROUTING_TABLE_WAIT`     | `25s`   | S/I     | Maximum wait for routing-table events.         |
| `TNLD_DRAIN_TIMEOUT`          | `30s`   | all     | Graceful connection drain deadline.            |

All durations must be positive. The renewal interval must be shorter than both
lease durations. Routing-table wait must be a whole number of seconds no greater
than 25 seconds.

## use a static configuration file

`tnld serve --config` and `tnld config check --config` accept versioned YAML or
JSON:

```yaml
$schema: https://tnl.dev/schema/v1.json
version: 1
tnld:
  role: ingress
  control_hostname: control.tnl.example.com
  ingress_id: ingress-a
  metrics_listen: 127.0.0.1:9090
```

Static server configuration:

- must use `.yml`, `.yaml`, or `.json`;
- requires `version: 1` and an object-valued `tnld` section;
- rejects unknown fields, duplicate YAML keys, and trailing JSON content;
- accepts at most 1 MiB of valid UTF-8;
- does not support TypeScript, imports, includes, or interpolation.

Repeatable file keys stay singular: `oidc_scope`, `ingress_ipv4_address`, and
`ingress_ipv6_address`. Their environment variables are plural.

Control certificate paths from the file are resolved from the file's directory.
Other paths are resolved from the process working directory.

## migrate the database

```text
TNLD_DATABASE_DIRECT_URL=... tnld migrate
```

Migration creates the control schema and persistent migration lock when needed,
applies all embedded forward migrations, and verifies the resulting version.
There is no down, target-version, status, or dry-run mode.

An up-to-date database makes no changes. A newer database schema is rejected.

## generate a login token

```text
tnld login-token
```

The command writes one new credential followed by a newline. It does not save
the token and does not generate a cluster secret or storage key.

## check configuration

```text
tnld config check --config=/path/to/tnl.yml
```

The command loads the static document, applies defaults and ambient `TNLD_*`
values, resolves the role, and validates configuration. Success is silent.

It does not:

- connect to PostgreSQL or verify its schema;
- open listeners or detect address conflicts;
- read certificate or private-key files;
- perform OIDC discovery;
- contact ACME, Route 53, control, or a route usage receiver;
- verify that advertised addresses are reachable.

Because ambient environment variables override the file, clear unrelated
`TNLD_*` values when you need an environment-neutral check.

## understand serving side effects

After validation, control and standalone can:

- connect to PostgreSQL and verify the schema;
- re-encrypt stored secrets when a previous storage key is set;
- clean up expired ephemeral routes;
- load or create an ACME account;
- issue route and relay certificates;
- manage route DNS;
- deliver route usage;
- open public, private, and observability listeners.

Ingress and relay generate a fresh process run ID, open their listeners, and
register with control. A relay without static TLS files retrieves its relay
transport certificate from control and keeps it only in memory.
