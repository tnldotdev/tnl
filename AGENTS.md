# Canonical Terminology

Use these terms consistently in code, APIs, CLI help, and documentation.

| Term | Meaning |
| --- | --- |
| tnl server | The deployed service as a whole. Never call it Core. |
| `tnld` process | One running daemon process. |
| control API | The server HTTP API used by clients and administrators. |
| standalone | A `tnld` role providing the control API, ingress, durable state, certificates, and in-process forwarding. |
| edge | A stateful `tnld` role providing the control API, ingress, durable state, certificates, and worker coordination. |
| worker | A stateless `tnld` role that hosts worker backends and connects outbound to an edge. |
| local service | The developer's HTTP application. |
| target | The loopback URL used by the publisher to reach the local service. |
| publisher | The local `tnl publish` or `tnl dev` process. |
| worker backend | The internal forwarding attachment connecting ingress to a publisher. |
| tunnel | One local `publish` or `dev` invocation and its lifecycle. |
| route | The durable server-side mapping from a public hostname to a target, policy, and lifecycle state. |
| route session | The persisted lifecycle of one publisher attachment for a route. |
| route version | The monotonic fencing number for successive runtime route incarnations; use `route_version` in machine formats and `RouteVersion` in code. |
| enabled | A durable route that is not suspended or deleted. |
| routable | A route version currently ready to receive ingress traffic. |
| hostname | A complete DNS name exposed by tnl. |
| deployment hostname suffix | The DNS suffix under which a server allocates managed hostnames. |
| managed hostname | A persistent hostname claimed under the deployment hostname suffix. |
| custom domain | An externally owned DNS domain claimed after DNS verification. |
| child hostname | A hostname below a claimed managed hostname or custom domain. |
| temporary hostname | A server-generated hostname for one publish invocation. |
| identity | A server-local authorization principal. Login-token access uses the built-in administrator identity; each OIDC issuer/subject pair maps to a distinct identity. |
| maintenance control | An administrator-controlled gate for route creation, route-session creation, or certificate issuance. |
| Tailcat | The encrypted transport between a publisher and worker backend. |
| DERP relay | A Tailscale relay used by Tailcat when a direct path is unavailable. |
| route usage bucket report | A transmitted report for one route, route version, time bucket, and report revision. |

- Never introduce `Core` as a tnl architectural term. Use server, `tnld` process, control API, edge, or authorization receiver as appropriate.
- Do not bulk-rename existing `Core`-prefixed OIDC nonce symbols or wire values; they predate this terminology and are compatibility-sensitive.
- Avoid unqualified `name`, `base`, `session`, `version`, and `active` when a canonical term above is more precise.
- Reserve `generation` for internal mutation counters; public route counters are route versions.

# Development Workflow

- Use the versions in `mise.toml`. Bootstrap with `mise trust`, `mise install`, then `mise exec -- pnpm install --frozen-lockfile`; run repository commands from the root through `mise exec --`.
- The Taskfile injects `GOFLAGS=-tags=ts_omit_ssh`. Preserve it for direct Go commands, for example `mise exec -- env GOFLAGS=-tags=ts_omit_ssh go test ./internal/admin -run '^TestMaintenanceControlIsDurableAndAudited$'`.
- The full local sequence is `task generate`, `task format`, `task generate-check`, `task format-check`, `task lint`, `task test`, `task go:test-race`, `task go:test-integration`, then `task build`, each through `mise exec --`.
- `task generate-check` runs generation before checking the generated-directory diff; it is not read-only. `task format-check` does not cover root Markdown, API YAML, shell, Docker, or Compose files.
- `pnpm test` and `pnpm typecheck` build through lifecycle hooks. Their `:ci` variants and direct Vitest runs do not; build first. For example, run `mise exec -- pnpm --filter @tnldotdev/vite build`, then `mise exec -- pnpm exec vitest run packages/vite/index.test.ts -t 'test name'`.
- Integration tests are opt-in and excluded from routine Go test tasks. `task go:test-integration` requires Pebble from `mise install`, installed JavaScript dependencies, and built package output.

# Architecture

- `cmd/tnl` is the client CLI, `cmd/tnld` is the server process, and `cmd/tnlbench` is the benchmark driver. Product releases contain `tnl` and `tnld`.
- A standalone `tnld` process creates an in-process worker. An edge exposes the worker WebSocket hub. A worker owns no durable state and reconnects outbound to an edge.
- The control API and route ingress share one public TLS listener. Exact control-hostname SNI goes to the control TLS server; other SNI is resolved as route ingress without terminating route TLS.
- Route TLS terminates in the publisher. Preserve the PROXY v2 metadata path from ingress through the worker backend to the publisher.
- A route version becomes routable only after its worker backend is attached and the publisher completes the ready transition.
- `packages/dev` owns the private socket protocol between `tnl dev` and framework integrations. `packages/next` and `packages/vite` configure the tunnel, register the actual loopback port, and remain inert outside `tnl dev`; do not expose server access tokens to child development processes.
- The hosted TypeScript application is maintained outside this repository.

# Contracts and State

- OpenAPI sources live under `api/` and generate committed `pkg/protocol/*/openapi.gen.go` files. SQL migrations and queries under `internal/state` and `internal/clientstate` generate the committed `statedb` and `clientstatedb` packages. Edit the sources, not generated Go files, then run `task generate` and `task format`.
- `pkg/protocol/workerv1` is handwritten. Keep it synchronized with `api/worker/v1/control.schema.json`; the protocol parity test checks this contract.
- Never share a state directory or SQLite volume between standalone or edge processes. Migrations run automatically upward; daemon rollback requires restoring the complete older backup into an empty volume.

# Operational Safety

- The local stack order is `task local:up`, `task local:trust`, then `task local:login`. `local:trust` modifies the macOS login keychain; `local:down` preserves state, while `local:reset` removes trust, containers, volumes, and `.local`.
- Never execute the Fly benchmark without explicit approval. Planning is read-only, but execution requires `BENCH_SUITE` and `BENCH_APPROVED=1` and uses paid persistent Fly and DNS resources.
- For release/version/tag work, load and follow `.agents/skills/tnl-release/SKILL.md`; do not duplicate or improvise its approval gates.
- Keep GitHub Actions SHA-pinned with explicit permissions, timeouts, and `persist-credentials: false`; retain `actionlint` and `zizmor` checks.
- CI publishes release artifacts and images but does not deploy production. Production Compose images must remain digest-pinned.
- Release archives and native npm packages must retain all required dependency license and legal files; see `CONTRIBUTING.md`.
