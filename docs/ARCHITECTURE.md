# Architecture

This document owns runtime invariants and package/API boundaries. Deployment
settings and current capability limitations belong in
[Self-Hosting](SELF-HOSTING.md); wire fields belong in their source contracts.
Use the vocabulary in [AGENTS.md](../AGENTS.md).

## Processes And State

| Component                          | Owns                                                                       |
| ---------------------------------- | -------------------------------------------------------------------------- |
| `cmd/tnl`, `internal/publisher`    | Local tunnel lifecycle, publisher connections, and route TLS termination   |
| `cmd/tnld`, `internal/tnldruntime` | Server configuration, role composition, listeners, and shutdown            |
| Control                            | Durable state, placement, certificate coordination, and administration     |
| Ingress                            | Visitor acceptance, route policy, relay selection, usage, and forwarding   |
| Relay                              | Publisher connections and visitor streams for locally connected publishers |

A standalone `tnld` process composes control, ingress, and two logical relay
services against PostgreSQL. Split deployments run a control service, an ingress
service, and at least two independently addressable relay services.

Only control and standalone connect to PostgreSQL. `internal/controlstate` owns
durable runtime mutations; ingress receives only the short-lived ingress routing
table, and relays know their own lease and locally connected publishers.
The authority API owns identities, teams, memberships, invitations, domains,
authentication, and current authorization decisions. The hosted TypeScript
application is maintained outside this repository.

`TNLD_SERVER_DOMAIN` is the infrastructure suffix for control, ingress, and relay
hostnames. It is independent of `TNLD_MANAGED_DEPLOYMENT_DOMAIN`, which supplies
public route namespaces.

## Connections And Trust

Publishers maintain two connection slots on distinct relay services. A route
version first becomes routable once its certificate is installed and both
publisher connections are ready. It then remains routable with one ready
connection while replenishing toward two.

Publishers prefer QUIC, racing TLS/TCP with yamux after a short delay. Control
manages exact-hostname WebPKI relay certificates. Publishers verify relay
transport TLS using system trust roots; relays authenticate publishers with
short-lived publisher connection credentials.

The visitor path is `visitor -> ingress -> relay -> publisher -> local service`.
Ingress creates exactly one PROXY v2 metadata header. Relay preserves that
header and route TLS bytes unchanged; route TLS terminates at the publisher.
Ingress may try another relay before sending the first visitor byte, never
afterward. Live visitor connections are not replayed or migrated.

Split ingress and relay processes authenticate private control requests with
`TNLD_CLUSTER_SECRET`. Their exact process run ID and lease revision must remain
current. Standalone uses direct in-process adapters without a cluster secret.
These adapters implement controller-facing operations, not HTTP authentication
or request-editor execution; role controllers must not depend on database error
types.

Control and standalone require a bootstrap management token and obtain public
control certificates through ACME; static certificates are advanced overrides.
Only these roles receive the storage key, hosted secret, PostgreSQL credentials,
DNS credentials, or ACME account keys. A relay may retrieve its own managed
certificate/private key under its current lease and holds it in memory.

## API Ownership

| Source contract                                   | Implementer                                   | Caller and authentication                                                                             |
| ------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [Control](../api/control/v1/openapi.yaml)         | `internal/controlapi` on control              | CLI/publisher; access or route-session credential according to operation                              |
| [Authority](../api/authority/v1/openapi.yaml)     | `internal/authorityapi` or external authority | CLI login/session and team/domain operations; control uses the hosted secret for hosted authorization |
| [Ingress](../api/ingress/v1/openapi.yaml)         | `internal/ingressapi` on control              | Ingress; cluster authentication, or standalone direct calls                                           |
| [Relay](../api/relay/v1/openapi.yaml)             | `internal/relayapi` on control                | Relay; cluster authentication, or standalone direct calls                                             |
| [Route usage](../api/route-usage/v1/openapi.yaml) | External receiver                             | Control's `internal/routeusageworker`; configured receiver bearer token                               |

OpenAPI describes the wire contract, not a guarantee that every reserved
operation is implemented. See the self-hosting capability table. Shared OpenAPI
components contain only byte-identical referenced schemas and do not generate
another Go package.

`pkg/protocol/tunnelv1` is the handwritten tunnel protocol source of truth.
`internal/muxsession` abstracts multiplexed byte streams; `internal/tunnel`
owns handshakes and acknowledgments; `internal/streamcopy` owns bidirectional
copying. Preserve golden JSON, framed-wire, invalid, bounds, fuzz, and shared
transport tests instead of introducing a parallel tunnel schema.

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
Framework integrations discover metadata during development and attach to a
matching `tnl dev` through explicit bootstrap or socket discovery. Builds and
previews remain inert. Never expose server access tokens to child development
processes or browser metadata.

Keep role-specific lifecycle, retry, and authorization policy with its owner.
Share mechanics and identical contracts, not merely similar control flow.
Generation and verification instructions belong in [Contributing](../CONTRIBUTING.md).
