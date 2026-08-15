# Architecture

This document describes runtime guarantees and the boundaries between packages
and APIs. See [Self-Hosting](SELF-HOSTING.md) for deployment settings and current
limitations. Each source contract documents its own wire fields. Use the
vocabulary in [AGENTS.md](../AGENTS.md).

## Processes And State

| Component                          | Owns                                                                       |
| ---------------------------------- | -------------------------------------------------------------------------- |
| `cmd/tnl`, `internal/publisher`    | Local tunnel lifecycle, publisher connections, and route TLS termination   |
| `cmd/tnld`, `internal/tnldruntime` | Server configuration, role composition, listeners, and shutdown            |
| Control                            | Stored state, placement, certificate coordination, and administration      |
| Ingress                            | Visitor acceptance, route policy, relay selection, usage, and forwarding   |
| Relay                              | Publisher connections and visitor streams for locally connected publishers |

A standalone `tnld` process composes control, ingress, and two logical relay
services against PostgreSQL. Split deployments run a control service, an ingress
service, and at least two independently addressable relay services.

Only control and standalone connect to PostgreSQL. `internal/controlstate`
changes persistent runtime state. Ingress receives a short-lived routing table.
Each relay knows only its own lease and the publishers connected to it.

The authority API manages identities, teams, memberships, invitations, domains,
authentication, and authorization decisions. Control or standalone can serve
the built-in authority, or use an external authority maintained outside this
repository.

`TNLD_SERVER_DOMAIN` is the infrastructure suffix for control, ingress, and relay
hostnames. It is independent of `TNLD_MANAGED_DEPLOYMENT_DOMAIN`, which supplies
public route namespaces.

## Connections And Trust

Publishers maintain two connections through different relay services. A route
version becomes routable after its certificate is installed and both connections
are ready. It can then remain routable with one connection while the publisher
replaces the other.

Publishers try QUIC first. After a short delay, they also try TLS/TCP with yamux
and use the first transport accepted by the relay. Control manages the relay
transport certificates. Publishers verify those certificates with system trust
roots. Relays authenticate publishers with short-lived publisher connection
credentials.

The visitor path is `visitor -> ingress -> relay -> publisher -> local service`.
Ingress creates exactly one PROXY v2 metadata header. Relay preserves that
header and route TLS bytes unchanged; route TLS terminates at the publisher.
Ingress may try another relay before sending the first visitor byte, never
afterward. Live visitor connections are not replayed or migrated.

Split ingress and relay processes use `TNLD_CLUSTER_SECRET` to authenticate to
control. Requests are accepted only while the process run ID and lease revision
match the current lease. Standalone calls the same operations in process and
does not use a cluster secret.

The standalone adapters implement controller operations without HTTP
authentication or request editors. Role controllers receive API errors rather
than database-specific errors.

Control and standalone using the built-in authority require a login token. An
external authority instead requires an authority endpoint, OIDC configuration,
and the hosted secret shared with control. Control and standalone obtain public
control certificates through ACME unless static certificates are configured.
Only these roles receive the storage key, PostgreSQL credentials, DNS
credentials, or ACME account keys. A relay can retrieve its relay transport
certificate and private key while its lease is current. It keeps them only in
memory.

## API Ownership

| Source contract                                   | Implementer                                   | Caller and authentication                                                                             |
| ------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [Control](../api/control/v1/openapi.yaml)         | `internal/controlapi` on control              | CLI/publisher; access or route-session credential according to operation                              |
| [Authority](../api/authority/v1/openapi.yaml)     | `internal/authorityapi` or external authority | CLI login/session and team/domain operations; control uses the hosted secret for hosted authorization |
| [Ingress](../api/ingress/v1/openapi.yaml)         | `internal/ingressapi` on control              | Ingress; cluster authentication, or standalone direct calls                                           |
| [Relay](../api/relay/v1/openapi.yaml)             | `internal/relayapi` on control                | Relay; cluster authentication, or standalone direct calls                                             |
| [Route usage](../api/route-usage/v1/openapi.yaml) | External receiver                             | Control's `internal/routeusageworker`; configured receiver bearer token                               |

OpenAPI describes the wire contract. It does not guarantee that every reserved
operation is implemented; see the self-hosting capability table. Shared OpenAPI
components contain only identical referenced schemas and do not generate a Go
package.

`pkg/protocol/tunnelv1` is the handwritten tunnel protocol source of truth.
`internal/muxsession` provides multiplexed byte streams. `internal/tunnel`
implements handshakes and acknowledgments. `internal/streamcopy` copies bytes in
both directions. Test the protocol with golden JSON and wire frames, invalid and
size-bound cases, fuzzing, and shared transport tests. Do not add a separate
tunnel schema.

## Local Package Boundaries

| Package                  | Responsibility                                                                           |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| `internal/config`        | Serialized configuration and schema validation                                           |
| `internal/projectconfig` | Discovery, trusted TypeScript evaluation, worktrees, and effective service configuration |
| `internal/tnldconfig`    | Server-role configuration and environment resolution                                     |
| `internal/clientstate`   | Client SQLite state and local ownership locks                                            |
| `internal/projectmeta`   | Generated project metadata and TypeScript augmentation                                   |
| `internal/clioutput`     | Shared ASCII rendering; command handlers provide semantic content only                   |
| `packages/tnl`           | Browser-safe project runtime and Node-only framework integrations                        |

The npm public subpaths are the root, `/config`, `/next`, and `/vite`. The private
development socket is shipped implementation, not a public extension API.
During development, framework integrations load project metadata and connect to
the matching `tnl dev` process through explicit setup or socket discovery. They
do nothing during builds and previews. Never expose access tokens to child
development processes or browser metadata.

Keep each role's lifecycle, retry, and authorization rules with that role. Share
reusable mechanics and identical contracts, not code that only looks similar.
Generation and verification instructions belong in [Contributing](../CONTRIBUTING.md).
