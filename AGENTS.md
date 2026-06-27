# Canonical Terms

Use these terms consistently in code, APIs, CLI help, and documentation.

## System And Roles

| Term                | Definition                                                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **tnl server**      | The complete deployed service, including control, ingress, relays, and PostgreSQL.                                                            |
| **`tnld` process**  | One running daemon process configured with a server role.                                                                                     |
| **control**         | A stateful `tnld` role that owns durable runtime state, placement, certificates, administration, and coordination through PostgreSQL.         |
| **control service** | All interchangeable control processes sharing PostgreSQL.                                                                                     |
| **ingress**         | A stateless `tnld` role that accepts visitor connections, applies route policy, selects a connected relay, and forwards each connection once. |
| **ingress service** | The replicated ingress processes behind one health-aware public address.                                                                      |
| **relay**           | A stateless `tnld` role that maintains publisher connections and carries visitor streams from ingress to publishers.                          |
| **relay service**   | Interchangeable relay processes behind one stable relay address and sharing one intended failure boundary.                                    |
| **relay process**   | One running `tnld` process configured with the relay role and belonging to a relay service.                                                   |
| **standalone**      | A `tnld` role that composes control, ingress, and two logical relay services in one process against PostgreSQL.                               |
| **control API**     | The server HTTP API used by clients and administrators.                                                                                       |
| **authority API**   | The HTTP API that owns identities, teams, memberships, invitations, domains, authentication, and signed authorizations.                       |

## People And Local Processes

| Term              | Definition                                                                     |
| ----------------- | ------------------------------------------------------------------------------ |
| **identity**      | A server-local authorization principal representing a person or administrator. |
| **publisher**     | The local `tnl publish` or `tnl dev` process.                                  |
| **visitor**       | A browser or other client connecting to a public route.                        |
| **local service** | The developer's HTTP application.                                              |
| **target**        | The loopback URL the publisher uses to reach the local service.                |
| **tunnel**        | One local `tnl publish` or `tnl dev` invocation and its lifecycle.             |

## Addresses And DNS

| Term                       | Definition                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **hostname**               | A complete DNS name exposed by tnl.                                                                                 |
| **server domain**          | The infrastructure DNS suffix from which control, ingress, and relay hostnames are derived.                         |
| **control hostname**       | The public hostname clients use to reach the control API over HTTPS.                                                |
| **ingress address**        | The public, health-aware address that sends visitor connections to ingress processes.                               |
| **public route DNS**       | DNS records that send public route hostnames to the ingress address.                                                |
| **relay address**          | The stable public hostname and port a publisher uses to establish a publisher connection through one relay service. |
| **internal relay address** | The internal hostname and port ingress uses to forward visitor connections to a relay.                              |

## Routes

| Term                      | Definition                                                                                                                  |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **route**                 | The durable server-side mapping from a public hostname to a target, policy, and lifecycle state.                            |
| **route session**         | The persisted lifecycle of one publisher attachment to a route.                                                             |
| **route version**         | A monotonic number identifying one continuous publishing run for a route. A new route session receives a new route version. |
| **enabled**               | A durable route that has not been suspended or deleted.                                                                     |
| **routable**              | A route version that currently has its certificate and enough ready publisher connections to receive visitors.              |
| **route TLS**             | The visitor's TLS connection, which passes through ingress and relay and terminates at the publisher.                       |
| **IP policy**             | The rule controlling which visitor source addresses may use a route.                                                        |
| **ingress routing table** | The short-lived routing information control sends to ingress, including route policy and connected relays.                  |

## Publisher Connections

| Term                                | Definition                                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **publisher connection**            | A long-lived multiplexed connection from a publisher to a relay.                                        |
| **publisher connection ID**         | The unique identifier for one publisher connection lifecycle.                                           |
| **connection slot**                 | One of the two publisher connections maintained by a route session.                                     |
| **connection assignment**           | Control's instruction assigning a connection slot to a particular relay service and relay address.      |
| **connection assignment revision**  | A monotonic number changed whenever control replaces the assignment for a connection slot.              |
| **assigned relay**                  | The relay service selected by control for a connection assignment.                                      |
| **connected relay**                 | The concrete relay process that claimed and currently holds a publisher connection for a route session. |
| **ready publisher connection**      | An authenticated, current publisher connection that can carry visitor streams.                          |
| **publisher connection credential** | An opaque credential authorizing one publisher to establish one assigned publisher connection.          |
| **transport**                       | The mechanism carrying a publisher connection: QUIC or TLS/TCP with yamux.                              |

## Visitor Connections

| Term                      | Definition                                                                                                      |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **visitor connection**    | One public TCP connection from a visitor to a route hostname.                                                   |
| **visitor connection ID** | The unique identifier used to correlate one visitor connection across ingress, relay, and publisher.            |
| **visitor stream**        | A multiplexed bidirectional stream carrying one visitor connection through a relay to the publisher.            |
| **internal forwarding**   | Sending a visitor connection from ingress to a connected relay over an authenticated internal connection.       |
| **retry boundary**        | The first visitor byte sent to a relay. Ingress may try another relay before this point but never afterward.    |
| **PROXY v2 metadata**     | The original visitor source and destination information created once by ingress and preserved to the publisher. |

## Process Coordination

| Term                    | Definition                                                                                                                    |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **ingress lease**       | Control's time-limited permission for an ingress process to serve visitor traffic and use the ingress routing table.          |
| **relay lease**         | Control's time-limited permission for a relay process to accept connection assignments and publisher connections.             |
| **lease renewal**       | A periodic request that extends a process's lease.                                                                            |
| **lease expiration**    | The deadline after which control considers a process unavailable if its lease was not renewed.                                |
| **lease revision**      | A monotonic number distinguishing the current lease from an older lease for the same process identity.                        |
| **process run ID**      | A unique identifier generated each time an ingress or relay process starts.                                                   |
| **stale-state checks**  | Checks that reject operations from an old route session, replaced connection assignment, expired lease, or restarted process. |
| **placement**           | Control's selection of distinct relay services for a route session's connection slots.                                        |
| **draining**            | A process state that rejects new work while allowing existing connections to finish until a deadline.                         |
| **connection capacity** | The number of publisher connections a relay is configured to support.                                                         |
| **stream capacity**     | The number of concurrent visitor streams a relay is configured to support.                                                    |

## Internal Security

| Term                         | Definition                                                                                                                        |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **service CA**               | The control-owned private certificate authority persisted in PostgreSQL and used for internal and relay transport certificates.   |
| **service mTLS**             | Certificate-authenticated TLS used for internal communication among control, ingress, and relays.                                 |
| **service enrollment**       | Token-authenticated issuance or renewal of a process-local service identity through the public control API.                       |
| **service enrollment token** | A reusable, revocable, role-scoped secret used by ingress or relay processes to enroll without pre-provisioned certificate files. |
| **service certificate**      | A short-lived certificate carrying one process role and identity for service mTLS.                                                |
| **service identity**         | The role and process identity carried by a service certificate.                                                                   |
| **ingress identity**         | A service identity authorized to receive routing information and forward visitor connections.                                     |
| **relay identity**           | A service identity authorized to accept connection assignments and publisher connections.                                         |
| **relay transport TLS**      | Server-authenticated TLS on a public relay address using a one-hour relay-service certificate issued by the service CA.           |
| **trust bundle**             | The service CA certificates used in a scoped TLS configuration to verify service identities or relay transport certificates.      |

## Teams And Domains

| Term                          | Definition                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| **team**                      | The durable ownership and authorization boundary for domains and routes.                              |
| **membership**                | The relationship between an identity and a team, including team role and immutable member slug.       |
| **member namespace**          | A complete hostname derived from a membership and domain.                                             |
| **managed deployment domain** | A server-controlled domain beneath which member namespaces are generated.                             |
| **claimed domain**            | A domain assigned exclusively to one team after DNS authority verification.                           |
| **shared route**              | A team-owned route outside individual member namespaces.                                              |
| **route scope**               | Whether a route belongs to one membership or to the team collectively.                                |
| **maintenance control**       | An administrator-controlled gate for route creation, route-session creation, or certificate issuance. |
| **route usage bucket report** | A usage report for one route, route version, time bucket, and report revision.                        |

## Machine Field Names

| Concept                         | Field                             |
| ------------------------------- | --------------------------------- |
| Route version                   | `route_version`                   |
| Publisher connection ID         | `publisher_connection_id`         |
| Connection slot                 | `connection_slot`                 |
| Connection assignment revision  | `connection_assignment_revision`  |
| Publisher connection credential | `publisher_connection_credential` |
| Visitor connection ID           | `visitor_connection_id`           |
| Ingress identity                | `ingress_id`                      |
| Ingress process run ID          | `ingress_run_id`                  |
| Ingress lease revision          | `ingress_lease_revision`          |
| Relay service identity          | `relay_service_id`                |
| Relay identity                  | `relay_id`                        |
| Relay process run ID            | `relay_run_id`                    |
| Relay lease revision            | `relay_lease_revision`            |
| Lease expiration                | `lease_expires_at`                |
| Relay address                   | `relay_address`                   |
| Internal relay address          | `internal_relay_address`          |
| Ingress routing-table revision  | `routing_table_revision`          |
| Transport                       | `transport`                       |
| Service enrollment token        | `service_enrollment_token`        |

## Retired And Replaced Terms

| Retired term                  | Replacement                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| gateway                       | relay                                                        |
| ingress gateway               | ingress                                                      |
| gateway fleet                 | No dedicated term; say "available relay processes"           |
| gateway pool                  | relay service                                                |
| gateway lease                 | relay lease                                                  |
| gateway ID                    | relay ID                                                     |
| gateway boot ID               | relay process run ID                                         |
| gateway lease epoch           | relay lease revision                                         |
| gateway link                  | publisher connection                                         |
| publisher link                | publisher connection                                         |
| publisher tunnel              | publisher connection or tunnel, depending on context         |
| link ID                       | publisher connection ID                                      |
| link slot                     | connection slot                                              |
| link assignment               | connection assignment                                        |
| assignment revision           | connection assignment revision                               |
| link owner                    | connected relay                                              |
| usable link                   | ready publisher connection                                   |
| route attachment              | publisher connection                                         |
| carrier                       | transport                                                    |
| carrier hostname              | relay address                                                |
| private endpoint              | internal relay address                                       |
| private forwarding            | internal forwarding                                          |
| gateway-to-gateway forwarding | Removed                                                      |
| route directory               | ingress routing table                                        |
| route DNS                     | public route DNS                                             |
| public front door             | ingress address                                              |
| control address               | control hostname                                             |
| fencing                       | stale-state checks                                           |
| fence                         | Name the specific identity or revision being checked         |
| boot ID                       | process run ID                                               |
| lease epoch                   | lease revision                                               |
| DERP relay                    | Removed; unrelated to the new relay role                     |
| relay map                     | Removed                                                      |
| relay region                  | Removed                                                      |
| relay provider                | Removed                                                      |
| edge                          | ingress or control, depending on the old responsibility      |
| worker                        | relay or publisher connection handling, depending on context |

- Never introduce `Core` as a tnl architectural term. Use tnl server, `tnld` process, control API, control, ingress, relay, or authorization receiver as appropriate.
- In prose, always write the product and binaries as lowercase `tnl` and `tnld`. Use uppercase only where required by case-sensitive identifiers such as `TNLD_*` environment variables.
- Reserve `generation` for internal mutation counters; public route counters are route versions.

# CLI Human Output

Human-readable output from `tnl`, including diagnostics, uses the shared ASCII diagram renderer. The renderer and its tests are the source of truth for layout, width, wrapping, escaping, and frame syntax. Command handlers provide semantic content only and must not construct borders, rails, padding, or connectors.

Frames follow this general form:

```text
+--[ <command> ]-- <state> -------------------------------+
|                                                         |
|  diagram or structured details                          |
|                                                         |
+-- <optional action, hint, or diagnostic code> -----------+
```

- Use short, lowercase, concrete states and ASCII-only frame syntax. Use `v` for healthy flow and `x` for the exact failure boundary.
- Keep human output deterministic and at most 72 columns. Do not truncate meaningful values or emit ANSI control sequences.
- Keep JSON and NDJSON contracts unchanged. `tnl version` and one-time credentials remain exact raw values, and generated help remains unframed.
- Finite results go to stdout; prompts, lifecycle output, warnings, and errors go to stderr. Preserve `tnl dev` child output unchanged.
- Render errors once at the top level through the same renderer. Preserve stable diagnostic codes, help URLs, HTTP behavior, and HTML negotiation.
- `tnl publish` and `tnl dev` share one tunnel presentation.
- Do not use the diagram renderer for `tnld`. Its commands retain exact raw values, silent successes, and compact one-line operational logs and errors.
- Never include secrets in diagrams or logs.

# Development Workflow

- Use the versions in `mise.toml`. Bootstrap with `mise trust`, `mise install`, then `mise exec -- pnpm install --frozen-lockfile`; run repository commands from the root through `mise exec --`.
- The Taskfile injects `GOFLAGS=-tags=ts_omit_ssh`. Preserve it for direct Go commands, for example `mise exec -- env GOFLAGS=-tags=ts_omit_ssh go test ./internal/admin -run '^TestMaintenanceControlIsDurableAndAudited$'`.
- The full local sequence is `task generate`, `task format`, `task generate-check`, `task format-check`, `task lint`, `task test`, `task go:test-race`, `task go:test-integration`, then `task build`, each through `mise exec --`.
- `task generate-check` runs generation before checking the generated-directory diff; it is not read-only. `task format-check` applies Oxfmt to supported files across the repository.
- `pnpm test` and `pnpm typecheck` build through lifecycle hooks. Their `:ci` variants and direct Vitest runs do not; build first. For example, run `mise exec -- pnpm --filter @tnldotdev/vite build`, then `mise exec -- pnpm exec vitest run packages/vite/index.test.ts -t 'test name'`.
- Integration tests are opt-in and excluded from routine Go test tasks. `task go:test-integration` requires Pebble from `mise install`, installed JavaScript dependencies, and built package output.

# Architecture

- `cmd/tnl` is the client CLI, `cmd/tnld` is the server process, and `cmd/tnlbench` is the benchmark driver. Product releases contain `tnl` and `tnld`.
- The runtime architecture and implementation sequence in [QUIC.md](https://md.cormo-turtle.ts.net/git/personal/tnl/QUIC.md) are authoritative when another document conflicts with them.
- A standalone `tnld` process composes control, ingress, and two logical relay services against PostgreSQL. Split deployments run a control service, an ingress service, and at least two independently addressable relay services.
- Control serves the control API and separate service-mTLS APIs for ingress and relay processes. Ingress accepts public route TLS. Relay processes accept publisher connections over QUIC or TLS/TCP with yamux and accept internal forwarding from ingress.
- `TNLD_SERVER_DOMAIN` is an infrastructure suffix independent from `TNLD_MANAGED_DEPLOYMENT_DOMAIN`. It derives `control.<server-domain>`, `ingress.<server-domain>`, and standalone or relay-service hostnames.
- Split ingress and relay processes bootstrap through the public control API using reusable role-scoped service enrollment tokens. They generate service private keys locally, receive one-hour certificates, and renew after approximately thirty minutes. Standalone uses the same authorization boundaries through in-process calls and does not enroll itself.
- Control persists the private service CA in PostgreSQL. The same CA issues role-constrained service certificates and one-hour relay-service server certificates; publishers use a control-provided trust bundle only for relay transport connections. ACME is not used for relay transport TLS.
- Control and standalone require a bootstrap management token and obtain their public control certificate automatically through ACME. Static public certificates are optional advanced overrides; static service-mTLS files are not part of the final configuration.
- Route TLS terminates in the publisher. Ingress creates exactly one PROXY v2 metadata header, and relays preserve it unchanged to the publisher.
- A route version first becomes routable after its certificate is installed and both publisher connections are ready on distinct relay services. After that first transition it remains routable with one ready publisher connection and replenishes toward two.
- Ingress and relays never connect to PostgreSQL or own durable product state. Only ingress receives the ingress routing table; relays know only their own lease and locally connected publishers.
- `packages/dev` owns the private socket protocol between `tnl dev` and framework integrations. `packages/next` and `packages/vite` configure the tunnel, register the actual loopback port, and remain inert outside `tnl dev`; do not expose server access tokens to child development processes.
- The hosted TypeScript application is maintained outside this repository.

# Contracts and State

- The five HTTP OpenAPI sources are `api/control/v1/openapi.yaml`, `api/authority/v1/openapi.yaml`, `api/ingress/v1/openapi.yaml`, `api/relay/v1/openapi.yaml`, and `api/route-usage/v1/openapi.yaml`. They generate committed models, clients, and strict server interfaces under `pkg/api/*`. `api/shared/v1/components.yaml` may contain only byte-identical referenced schemas and does not generate a Go package.
- `pkg/protocol/tunnelv1` is handwritten and is the sole tunnel protocol source of truth. Do not add standalone tunnel JSON Schemas or schema-parity tests; use golden JSON and framed-wire fixtures, invalid fixtures, bounds tests, fuzzing, and shared transport behavior tests.
- PostgreSQL migrations and queries under `internal/controlstate` generate the committed `controlstatedb` package. Client SQLite sources under `internal/clientstate` generate `clientstatedb`. Edit sources, not generated Go files, then run `task generate` and `task format`.
- `tnld migrate` is the only migration path and accepts only `TNLD_DATABASE_DIRECT_URL`. Serving controls and standalone processes accept only pooled `TNLD_DATABASE_URL` and require the exact supported schema version.

# Operational Safety

- The local stack order is `task local:up`, `task local:trust`, then `task local:login`. `local:trust` modifies the macOS login keychain; `local:down` preserves state, while `local:reset` removes trust, containers, volumes, and `.local`.
- Never execute the Fly benchmark without explicit approval. Planning is read-only, but execution requires `BENCH_SUITE` and `BENCH_APPROVED=1` and uses paid persistent Fly and DNS resources.
- For release/version/tag work, load and follow `.agents/skills/tnl-release/SKILL.md`; do not duplicate or improvise its approval gates.
- Keep GitHub Actions SHA-pinned with explicit permissions, timeouts, and `persist-credentials: false`; retain `actionlint` and `zizmor` checks.
- CI publishes release artifacts and images but does not deploy production. Production Compose images must remain digest-pinned.
- Release archives and native npm packages must retain all required dependency license and legal files; see `CONTRIBUTING.md`.
