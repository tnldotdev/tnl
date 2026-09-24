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

| Component                  | Responsibility                                                                                  |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| `tnl` client and publisher | Local tunnel lifecycle, publisher connections, route TLS termination, and local HTTP forwarding |
| Control                    | Durable state, authorization, placement, certificates, administration, and coordination         |
| Ingress                    | Visitor acceptance, IP policy, relay selection, usage, and one-time forwarding                  |
| Relay                      | Publisher connections and visitor streams for locally connected publishers                      |
| PostgreSQL                 | Authoritative durable server state                                                              |

Only control connects to PostgreSQL. Ingress receives a short-lived routing
table. Each relay knows its own lease and the publishers connected to it.

Standalone composes control, ingress, and two logical relay services in one
`tnld` process. It uses the same role boundaries through in-process adapters.

## follow a visitor connection

```text
visitor
   | route TLS ClientHello
   v
ingress: inspect hostname and apply IP policy
   | authenticated internal forwarding
   v
relay: open a stream on a ready publisher connection
   | unchanged route TLS bytes
   v
publisher: terminate route TLS
   | validated HTTP over localhost
   v
local service
```

Ingress creates one PROXY v2 metadata header with the original source and
destination. Relay preserves that header and the route TLS bytes. The publisher
removes untrusted forwarding headers before proxying the HTTP request.

Public route DNS points to ingress, never to a relay. Placement can therefore
change without changing public route DNS.

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

## understand routes and publishing

```text
route
  durable hostname, ownership, target, policy, and state
    |
    +-- route session
          one publisher using the route
            |
            +-- route version
                  one continuous publishing run
```

One local `tnl publish` or `tnl dev` invocation is a tunnel. Starting a new
route session increments the route version. Stopping a normal tunnel ends the
session but leaves the route available for a later run.

Each route session has two publisher connection slots. Control assigns them to
different relay services.

```text
publisher
  |-- connection slot 0 ----> relay service A
  `-- connection slot 1 ----> relay service B
```

Initial routability requires the route certificate and both publisher
connections. After that first transition, one ready connection can keep the
route serving while the publisher replaces the other.

Publishers try QUIC first. After a short delay, they also try TLS/TCP with yamux
and keep the first authenticated transport that completes.

## separate the trust boundaries

| Credential or key               | Held by                           | Purpose                                         |
| ------------------------------- | --------------------------------- | ----------------------------------------------- |
| Access and refresh tokens       | `tnl` client                      | Authenticate a control session.                 |
| Route session token             | Publisher                         | Update one route session.                       |
| Publisher connection credential | Publisher and assigned relay      | Authenticate one publisher connection.          |
| Cluster secret                  | Split control, ingress, and relay | Authenticate private process coordination.      |
| Login token                     | Built-in authority control        | Recover the built-in administrator identity.    |
| Hosted secret                   | Control and external authority    | Authenticate control to the external authority. |
| Storage key                     | Control only                      | Encrypt recoverable secrets in PostgreSQL.      |
| Relay transport private key     | Current relay process             | Terminate publisher transport TLS.              |

Only control receives PostgreSQL, storage, DNS, or ACME credentials. A relay can
retrieve its current relay transport certificate and private key while its lease
is valid, and keeps them only in memory.

Split ingress and relay authenticate to control with the cluster secret. Control
also checks the configured process identity, process run ID, and lease revision.
A restarted or expired process cannot continue using stale authorization.

Route TLS is separate from relay transport TLS. Route TLS passes through ingress
and relay unchanged and terminates in the publisher.

## place authority decisions

The authority API owns identities, authentication, teams, memberships,
invitations, domains, and current authorization decisions.

Control or standalone can serve the built-in authority. It can instead call an
external authority maintained outside this repository. The control API does not
become the owner of authority state in that arrangement.

`TNLD_SERVER_DOMAIN` names server infrastructure. It is independent from
`TNLD_MANAGED_DEPLOYMENT_DOMAIN`, which provides managed public route
namespaces.

## own each api

| Contract                                          | Implementer                              | Caller and authentication                                                             |
| ------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------- |
| [Control](../api/control/v1/openapi.yaml)         | `internal/controlapi` on control         | CLI and publisher with access or route-session credentials                            |
| [Authority](../api/authority/v1/openapi.yaml)     | Built-in authority or external authority | CLI sessions and team/domain operations; control uses the hosted secret when external |
| [Ingress](../api/ingress/v1/openapi.yaml)         | `internal/ingressapi` on control         | Ingress with cluster authentication, or standalone direct calls                       |
| [Relay](../api/relay/v1/openapi.yaml)             | `internal/relayapi` on control           | Relay with cluster authentication, or standalone direct calls                         |
| [Route usage](../api/route-usage/v1/openapi.yaml) | External receiver                        | Control route-usage worker with a configured bearer token                             |

OpenAPI is the wire contract. It does not promise that every reserved operation
is implemented.

`pkg/protocol/tunnelv1` is the handwritten tunnel protocol source of truth.
`internal/muxsession` provides multiplexed byte streams, `internal/tunnel`
implements handshakes, and `internal/streamcopy` copies bytes in both directions.

## keep local packages focused

| Package                  | Responsibility                                                              |
| ------------------------ | --------------------------------------------------------------------------- |
| `internal/config`        | Versioned static configuration and schema validation                        |
| `internal/projectconfig` | Project discovery, TypeScript evaluation, worktrees, and effective services |
| `internal/tnldconfig`    | Server-role settings and environment resolution                             |
| `internal/clientstate`   | Client SQLite state and local ownership locks                               |
| `internal/projectmeta`   | Generated browser-safe metadata and TypeScript augmentation                 |
| `internal/clioutput`     | Shared ASCII rendering for the `tnl` client                                 |
| `packages/tnl`           | Browser-safe runtime and Node framework integrations                        |

The npm public subpaths are the package root, `/config`, `/next`, and `/vite`.
The private development socket is shipped implementation, not a public extension
API.

Framework integrations receive browser-safe metadata and a private local socket.
They never receive control access tokens. They remain inactive during builds and
previews.

## preserve the core invariants

- Control is the only source of durable runtime state.
- Ingress and relay fail closed when leases or routing state expire.
- Publisher connection slots use different relay services.
- Route TLS terminates only in the publisher.
- Ingress creates PROXY v2 metadata exactly once.
- Visitor bytes are never replayed after the retry boundary.
- Credentials stay within the smallest role that needs them.
- Public route DNS points to ingress, not placement-selected relays.

Detailed PostgreSQL locking, routing publication, usage aggregation, and cleanup
invariants are in the maintainer-only
[control-state notes](control-state.md).
