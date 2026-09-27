# Canonical Terms

Use these terms consistently in code, APIs, CLI help, and documentation.

## System And Roles

| Term                   | Definition                                                                                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **tnl server**         | The complete deployed system, including control, ingress, relays, and PostgreSQL.                                                                  |
| **`tnld` process**     | One running daemon process configured with a server role.                                                                                          |
| **control**            | A stateful `tnld` role that stores runtime state in PostgreSQL and manages placement, certificates, administration, and coordination.              |
| **control service**    | All interchangeable control processes sharing PostgreSQL.                                                                                          |
| **ingress**            | A stateless `tnld` role that accepts visitor connections, applies public URL policy, selects a connected relay, and forwards each connection once. |
| **ingress service**    | The replicated ingress processes behind one health-aware public address.                                                                           |
| **relay**              | A stateless `tnld` role that maintains publisher connections and carries visitor streams from ingress to publishers.                               |
| **relay service**      | Interchangeable relay processes behind one stable relay address and sharing one intended failure boundary.                                         |
| **relay process**      | One running `tnld` process configured with the relay role and belonging to a relay service.                                                        |
| **standalone**         | A `tnld` role that composes control, ingress, and two logical relay services in one process against PostgreSQL.                                    |
| **control API**        | The server HTTP API used by clients and administrators.                                                                                            |
| **authority API**      | The HTTP API that manages identities, teams, memberships, invitations, domains, authentication, and current authorization decisions.               |
| **built-in authority** | The authority API served by control or standalone for login, sessions, teams, memberships, invitations, and domains.                               |
| **external authority** | A separately deployed authority API that makes authentication and authorization decisions for a tnl server.                                        |

## People And Local Processes

| Term              | Definition                                                                        |
| ----------------- | --------------------------------------------------------------------------------- |
| **identity**      | A person or administrator known to one tnl server.                                |
| **publisher**     | The local `tnl publish` or `tnl dev` process when its architectural role matters. |
| **visitor**       | A browser or other client connecting to a public URL.                             |
| **local service** | The developer's HTTP application.                                                 |
| **target**        | The local HTTP URL the publisher uses to reach the local service.                 |
| **tunnel**        | One local `tnl publish` or `tnl dev` invocation and its lifecycle.                |

## Projects And Client State

| Term                      | Definition                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **project**               | The directory selected from where the command runs, project configuration, and Git worktree.                        |
| **project service**       | A named local service in project configuration, with optional settings that override project defaults.              |
| **project configuration** | The selected `tnl.yml`, `tnl.yaml`, `tnl.json`, or `tnl.config.ts` file and its validated settings.                 |
| **project metadata**      | Generated, browser-safe hostname and project-service information used by framework integrations during development. |
| **client state**          | Local data saved by `tnl`, including sessions, certificates, project records, and locks.                            |
| **worktree label**        | A DNS-safe label derived from the project worktree and client state for use in default public URL hostnames.        |

## Addresses And DNS

| Term                       | Definition                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **hostname**               | A complete DNS name exposed by tnl.                                                                                 |
| **control URL**            | The normalized HTTPS origin clients use to reach the control API.                                                   |
| **server domain**          | The infrastructure DNS suffix from which control, ingress, and relay hostnames are derived.                         |
| **control hostname**       | The public hostname clients use to reach the control API over HTTPS.                                                |
| **ingress address**        | The public, health-aware address that sends visitor connections to ingress processes.                               |
| **public URL DNS**         | DNS records that send public URL hostnames to the ingress address.                                                  |
| **relay address**          | The stable public hostname and port a publisher uses to establish a publisher connection through one relay service. |
| **internal relay address** | The internal hostname and port ingress uses to forward visitor connections to a relay.                              |

## Public URLs And Publish Runs

| Term                             | Definition                                                                                                  |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **public URL**                   | The saved mapping from a public hostname to a target, policy, and state.                                    |
| **publish run**                  | One active publication of a public URL, including its number and publisher connections.                     |
| **publish run number**           | An ever-increasing number for one public URL; each new publish run receives the next number.                |
| **ephemeral public URL**         | A public URL removed after its tunnel stops instead of remaining available for a later publish run.         |
| **enabled**                      | A saved public URL that has not been suspended or deleted.                                                  |
| **routable**                     | A publish run with its certificate and enough ready publisher connections to receive visitors.              |
| **visitor TLS**                  | The visitor's TLS connection. It passes through ingress and relay and ends at the publisher.                |
| **public URL certificate**       | The publicly trusted certificate the publisher uses to terminate visitor TLS for a public URL hostname.     |
| **certificate plan**             | The hostnames, cache scope, and challenge method approved for a public URL certificate.                     |
| **certificate issuance**         | One attempt to obtain and install a public URL certificate for a publish run's certificate plan.            |
| **IP policy**                    | The rule controlling which visitor source addresses may use a public URL.                                   |
| **ingress routing table**        | Short-lived routing information control sends to ingress, including public URL policy and connected relays. |
| **policy revision**              | The authority policy version recorded when a public URL operation is authorized.                            |
| **public URL mutation revision** | An ever-increasing counter changed whenever editable public URL state changes.                              |

## Publisher Connections

| Term                                | Definition                                                                                         |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- |
| **publisher connection**            | A long-lived multiplexed connection from a publisher to a relay.                                   |
| **publisher connection ID**         | The unique identifier for one publisher connection from creation through close.                    |
| **connection slot**                 | One of the two publisher connections maintained by a publish run.                                  |
| **connection assignment**           | Control's instruction assigning a connection slot to a particular relay service and relay address. |
| **connection assignment revision**  | An ever-increasing number changed whenever control replaces the assignment for a connection slot.  |
| **assigned relay**                  | The relay service selected by control for a connection assignment.                                 |
| **connected relay**                 | The specific relay process that claimed and holds a publisher connection for a publish run.        |
| **ready publisher connection**      | An authenticated, current publisher connection that can carry visitor streams.                     |
| **publisher connection credential** | A secret that lets one publisher establish one assigned publisher connection.                      |
| **transport**                       | The mechanism carrying a publisher connection: QUIC or TLS/TCP with yamux.                         |
| **publish run token**               | A credential authorizing the publisher to update one publish run.                                  |

## Visitor Connections

| Term                      | Definition                                                                                                      |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **visitor connection**    | One public TCP connection from a visitor to a public URL hostname.                                              |
| **visitor connection ID** | The unique identifier used to correlate one visitor connection across ingress, relay, and publisher.            |
| **visitor stream**        | One multiplexed stream that carries a visitor connection through a relay to the publisher and back.             |
| **internal forwarding**   | Sending a visitor connection from ingress to a connected relay over an authenticated internal connection.       |
| **retry boundary**        | The first visitor byte sent to a relay. Ingress may try another relay before this point but never afterward.    |
| **PROXY v2 metadata**     | The original visitor source and destination information created once by ingress and preserved to the publisher. |

## Process Coordination

| Term                                | Definition                                                                                                           |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **ingress lease**                   | Control's time-limited permission for an ingress process to serve visitor traffic and use the ingress routing table. |
| **relay lease**                     | Control's time-limited permission for a relay process to accept connection assignments and publisher connections.    |
| **lease renewal**                   | A periodic request that extends a process's lease.                                                                   |
| **lease expiration**                | The deadline after which control considers a process unavailable if its lease was not renewed.                       |
| **lease revision**                  | An ever-increasing number that distinguishes the current lease from an older lease for the same process identity.    |
| **process run ID**                  | A unique identifier generated each time an ingress or relay process starts.                                          |
| **stale-state checks**              | Checks that reject an old publish run, replaced connection assignment, expired lease, or restarted process.          |
| **placement**                       | Control's choice of different relay services for a publish run's connection slots.                                   |
| **draining**                        | A process state that rejects new work while allowing existing connections to finish until a deadline.                |
| **connection capacity**             | The number of publisher connections a relay is configured to support.                                                |
| **stream capacity**                 | The number of concurrent visitor streams a relay is configured to support.                                           |
| **recovery episode**                | The time from an unexpected publisher connection loss until a visitor again receives a publisher byte.               |
| **public URL recovery observation** | Control's recorded measurement that closes one recovery episode.                                                     |

## Internal Security

| Term                            | Definition                                                                                                                   |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **cluster authentication**      | Authentication with a shared secret for private communication among control, ingress, and relays in one deployment.          |
| **cluster secret**              | The current secret configured as `TNLD_CLUSTER_SECRET`; split ingress and relay processes use it to authenticate to control. |
| **hosted secret**               | The secret shared only by control and `tnl.dev` for hosted authorization, revocation, and DNS-authority service calls.       |
| **storage key**                 | The symmetric key available only to control and standalone for encrypting recoverable secrets in PostgreSQL.                 |
| **login token**                 | The credential used to create administrator control sessions through the built-in authority.                                 |
| **control session**             | A login session that can be revoked and has an access token and refresh token.                                               |
| **access token**                | A short-lived credential that authorizes control API and authority API requests for a control session.                       |
| **refresh token**               | A longer-lived credential used to rotate a control session's access and refresh tokens.                                      |
| **ingress identity**            | The configured ingress process identity bound to ingress leases and internal-forwarding sessions.                            |
| **relay identity**              | The configured relay process identity bound to relay leases and publisher connection claims.                                 |
| **relay transport certificate** | The exact-hostname WebPKI certificate shared by a relay service and managed by control.                                      |
| **relay transport TLS**         | Server-authenticated TLS on a relay address using the relay transport certificate.                                           |

## Teams And Domains

| Term                               | Definition                                                                                               |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **team**                           | The stored ownership and authorization boundary for domains and public URLs.                             |
| **personal team**                  | The permanent, single-owner team created for each identity.                                              |
| **organization team**              | A team created for collaboration among multiple identities.                                              |
| **membership**                     | The relationship between an identity and a team, including team role and immutable member slug.          |
| **invitation**                     | A time-limited offer to create a membership with a reserved member slug and initial team role.           |
| **member slug**                    | A team-unique, immutable DNS label chosen for a membership and used with claimed domains.                |
| **managed label**                  | A server-generated, immutable DNS label used with the managed deployment domain.                         |
| **namespace**                      | A complete hostname built from a membership and domain.                                                  |
| **managed deployment domain**      | A server-controlled domain beneath which namespaces are generated.                                       |
| **claimed domain**                 | A domain assigned exclusively to one team after DNS authority verification.                              |
| **team domain**                    | A managed deployment domain or claimed domain available to one team.                                     |
| **default domain**                 | The ready team domain used when a command does not select another domain.                                |
| **DNS authority**                  | State control uses to manage public URL DNS beneath one claimed domain.                                  |
| **shared public URL**              | A team-owned public URL outside individual namespaces.                                                   |
| **public URL scope**               | Whether a public URL belongs to one membership or to the team collectively.                              |
| **maintenance control**            | An administrator-controlled gate for public URL creation, publish run creation, or certificate issuance. |
| **public URL usage bucket report** | A usage report for one public URL, publish run number, time bucket, and report revision.                 |

## Public URL Usage

| Term                          | Definition                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| **public URL usage receiver** | An external HTTPS service that accepts public URL usage bucket reports from control.                  |
| **visitor network estimate**  | An approximate count of distinct visitor IPv4 /32 or IPv6 /64 networks for one public URL and bucket. |

## Machine Field Names

| Concept                         | Field                             |
| ------------------------------- | --------------------------------- |
| Public URL ID                   | `public_url_id`                   |
| Publish run ID                  | `publish_run_id`                  |
| Publish run number              | `publish_run_number`              |
| Publish run token               | `publish_run_token`               |
| Policy revision                 | `policy_revision`                 |
| Public URL mutation revision    | `public_url_mutation_revision`    |
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
| Recovery episode ID             | `recovery_episode_id`             |
| DNS authority reference         | `dns_authority_reference`         |
| Transport                       | `transport`                       |
| Cluster secret                  | `cluster_secret`                  |

## Retired And Replaced Terms

| Retired term                  | Replacement                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| route (saved object)          | public URL                                                   |
| route ID                      | public URL ID                                                |
| route session                 | publish run                                                  |
| route session ID              | publish run ID                                               |
| route version                 | publish run number                                           |
| route session token           | publish run token                                            |
| route mutation revision       | public URL mutation revision                                 |
| route certificate             | public URL certificate                                       |
| route TLS                     | visitor TLS                                                  |
| route usage                   | public URL usage                                             |
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
| publisher attachment          | publish run                                                  |
| publisher lease               | publish run or its expiration, depending on context          |
| carrier                       | transport                                                    |
| carrier hostname              | relay address                                                |
| private endpoint              | internal relay address                                       |
| private forwarding            | internal forwarding                                          |
| gateway-to-gateway forwarding | Removed                                                      |
| route directory               | ingress routing table                                        |
| route DNS                     | public URL DNS                                               |
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
| service CA                    | Removed                                                      |
| service mTLS                  | cluster authentication                                       |
| service enrollment            | Removed                                                      |
| service enrollment token      | cluster secret                                               |
| service certificate           | Removed                                                      |
| relay service certificate     | relay transport certificate                                  |
| public relay certificate      | relay transport certificate                                  |
| trust bundle                  | system trust roots                                           |
| bootstrap management token    | login token                                                  |
| hosted authority              | external authority                                           |

- Never introduce `Core` as a tnl architectural term. Use tnl server, `tnld` process, control API, control, ingress, relay, or external authority as appropriate.
- In prose, always write the product and binaries as lowercase `tnl` and `tnld`. Use uppercase only where required by case-sensitive identifiers such as `TNLD_*` environment variables.
- Reserve `generation` for internal mutation counters; public URL counters are publish run numbers.

# Brand Identity

Brand identity: lowercase, spare, concrete, practical, and understated.
Developer-to-developer language with little hype or ornament.
In branded headings and page titles, write `url` in lowercase.

# CLI Human Output

In user-facing CLI diagrams and introductory documentation, label the local
process `tnl`. Reserve **publisher** for architectural and protocol distinctions
from other `tnl` commands and the local service; do not rename machine fields
such as `publisher_connection_id`.

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

- Use lowercase documentation filenames and headings. Keep `AGENTS.md` and
  `SKILL.md` uppercase for automatic agent discovery.
- Keep public product, client, and operator documentation on `tnl.dev`; the
  repository README and npm package README link there. Keep contributor,
  maintainer, and benchmark documentation with the code.

# Tests and Benchmarks

- Routine tests cover deterministic invariants without external infrastructure.
- Integration tests use the smallest real setup needed to verify a boundary.
- Runtime tests use one separated local topology and default to small smoke workloads.
- Large load and fault sweeps and deployed benchmarks are explicit opt-in runs.
- Local and deployed benchmarks share publisher, visitor, and measurement implementations.
- Add coverage at the lowest sufficient layer; migrate unique assertions before retiring overlapping tests.

# Development Commands

- Use the versions in `mise.toml`. Bootstrap with `mise trust`, `mise install`, then `mise exec -- pnpm install --frozen-lockfile`; run repository commands from the root through `mise exec --`.
- The Taskfile injects `GOFLAGS=-tags=ts_omit_ssh`. Preserve it for direct Go commands.
- Follow [contributing.md](contributing.md) for the validation sequence, generated-source ownership, local stack, and test-tier prerequisites.
- `task generate-check` regenerates files before comparing generated paths to `HEAD`; it is not read-only. `task format-check` is read-only.
- Task targets are the public test interface; use `go:test:integration:*` and `go:test:load:*`, and have CI call the same targets.
- Use `-tnl-*` flags for Go test selection and inputs. Never introduce `TNL_TEST_*` environment variables.
- Keep routine tests safe by default; opt-in tests must explicitly require their test tier.
- PostgreSQL-backed targets must create, use, and remove digest-pinned disposable PostgreSQL themselves.
- Use environment variables only for Task/Compose orchestration and resource limits; pass test-binary settings as flags.
- Package `test` and `typecheck` scripts build explicitly; `*:run` variants reuse an existing build.
- Author Node tooling and npm runtime code in TypeScript. Keep strict compiler and lint checks enabled; validate external data before narrowing it. The embedded project-config loader JavaScript is generated from `internal/projectconfig/loader.ts`.

# Architecture

- `cmd/tnl` is the client CLI, `cmd/tnld` is the server process, and `cmd/tnlbench` is the benchmark driver. Product releases contain `tnl` and `tnld`.
- Follow [contributor architecture](docs/maintainers/architecture.md) for runtime invariants, trust boundaries, and package/API ownership. Operational procedures and current capability limitations belong in [self-hosting](https://tnl.dev/docs/self-hosting).

# Contracts and State

- The five HTTP OpenAPI sources are `api/control/v1/openapi.yaml`, `api/authority/v1/openapi.yaml`, `api/ingress/v1/openapi.yaml`, `api/relay/v1/openapi.yaml`, and `api/public-url-usage/v1/openapi.yaml`. They generate committed models, clients, and strict server interfaces under `pkg/api/*`. `api/shared/v1/components.yaml` may contain only byte-identical referenced schemas and does not generate a Go package.
- `pkg/protocol/tunnelv1` is handwritten and is the sole tunnel protocol source of truth. Do not add standalone tunnel JSON Schemas or schema-parity tests; use golden JSON and framed-wire fixtures, invalid fixtures, bounds tests, fuzzing, and shared transport behavior tests.
- PostgreSQL migrations and queries under `internal/controlstate` generate the committed `controlstatedb` package. Client SQLite sources under `internal/clientstate` generate `clientstatedb`. Edit sources, not generated Go files, then run `task generate` and `task format`.
- `tnld migrate` is the only migration path and accepts only `TNLD_DATABASE_DIRECT_URL`. Serving controls and standalone processes accept only pooled `TNLD_DATABASE_URL` and require the exact supported schema version.

# Operational Safety

- The local stack order is `task local:up`, `task local:trust`, then `task local:login`. `local:trust` modifies the macOS login keychain; `local:down` preserves state, while `local:reset` removes trust, containers, volumes, and `.local`.
- When AWS SSO expires, prefer `mise exec -- aws sso login --profile <profile> --no-browser --use-device-code`. If terminal output is buffered while the command polls, run it in the background with a private temporary log outside the repo and promptly give the user the prefilled `.../#/device?user_code=...` URL printed by AWS CLI. After approval, verify with `mise exec -- aws sts get-caller-identity --profile <profile>`; do not store the code in the repo or bypass authentication.
- Never execute a deployed benchmark without explicit approval. Planning is read-only, but execution requires `BENCH_SUITE` and `BENCH_APPROVED=1` and creates billable compute, database, and DNS resources. Explicit continuing approval covers retries of the same plan during one debugging session; ask again if the suite, overrides, resources, or spending limit changes.
- For release/version/tag work, load and follow `.agents/skills/tnl-release/SKILL.md`; do not duplicate or improvise its approval gates.
- Keep GitHub Actions SHA-pinned with explicit permissions, timeouts, and `persist-credentials: false`; retain `actionlint` and `zizmor` checks.
- CI publishes release artifacts and images but does not deploy production. Production Compose images must remain digest-pinned.
- Release archives and native npm packages must retain all required dependency license and legal files; see `contributing.md`.
