# contributing

Run commands from the repository root. The tool versions are pinned in `mise.toml`:

```console
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- uv sync --frozen --project packages/py
```

## place your change

Use an operation-focused file in the existing owner before adding a package.
A new package needs a concrete lifecycle or authority boundary, a useful consumer,
an allowed dependency direction, and a reason the existing owner cannot be reused.
Move its implementation, supporting values, fixtures, tests, and callers together.
See the [practical ownership examples](AGENTS.md#place-implementation-with-its-owner).

Commands own input and presentation. Reusable operations own selection, remote
calls, retries, and cleanup; process owners own startup, supervision, drain, and
joins. For example, `internal/client/team` owns shared team/domain selection,
`internal/client/project/resolve` owns selected project facts, declarations, and
metadata, `internal/client/project/init` owns install/edit sequencing, and
`internal/client/project/meta` owns portable generation. Publisher and connector
operations consume these owners directly.

Keep one defining domain model and one source for identical wire shapes. Resolve
an upward dependency by moving the real value/operation lower, using a narrow
consumer-owned interface, or composing above both users. Preserve unique test
assertions and their tier/selector before removing overlap.

## check your change

Run the focused check that fits your change first. For a broad change, use this
sequence once on the integrated tree:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task format-check
mise exec -- task go:test
mise exec -- task go:lint
mise exec -- task js:check
mise exec -- task py:check
mise exec -- task connect:check
mise exec -- task workflows:lint
mise exec -- task go:vulncheck
mise exec -- task go:test:race
mise exec -- task go:test:harness
mise exec -- task go:test:integration
mise exec -- task build
```

`go:test` includes `go test ./...` and the external public Go consumer fixture;
`go:lint` includes root vet/staticcheck and `go:lint:harness` for the separate
harness module. `js:check` builds once, then reuses that build for types, tests,
lint, formatting, and source packing. `py:check` includes Ruff, mypy, native-owner
pytest, and wheel-source checks. `test` and `lint` remain public aggregate aliases;
when one already covered a check on the same tree, record that invocation rather
than repeating its components.

`Taskfile.yml` includes the implementation files in `tasks/`. Includes and tasks
explicitly run at the repository root; cross-file dependencies use absolute
public Task names. Use `task --list-all` to discover public targets. The ownership
map is in [development architecture](docs/maintainers/development/architecture.md#tasks-generators-and-assets).

Integration needs Docker and Pebble from `mise install`. The Task targets use
Testcontainers for Go in the separate `tools/testharness` Go module to create
and remove digest-pinned disposable databases; it is not a product binary
dependency. Each PostgreSQL-backed invocation shares one PostgreSQL container
while each test creates its own database. The same harness drives the runtime
load topology and fault sweeps without a TypeScript container runner.
The complete runtime tier has a 20-minute budget, including real lease-cycle
tests; a shell running the full multi-package integration tier needs a longer
deadline than an individual package. CI runs four state shards, four runtime
shards, and three ordinary CLI shards in parallel. Reproduce one with:

```console
mise exec -- task go:test:integration:state:shard SHARD=1/4
mise exec -- task go:test:integration:runtime:shard SHARD=1/4
mise exec -- task go:test:integration:cli:shard SHARD=1/3
```

The harness discovers tests with `go test -list` and assigns each complete
top-level test to one stable name-based shard. New tests enter a shard
automatically; unsupported selectors and empty shards fail. The harness also
discovers and accounts for unsharded and explicit `1/1` selection before starting
a container, rejecting an empty top-level set. Single-shard subtest selectors
pass through unchanged, with accounting at their top-level parent; that count
does not prove a requested subtest ran. Multi-shard selection rejects subtests
and assigns whole top-level tests exactly once. Runtime shards
exclude only the two real-clock proofs, which CI runs separately through
`go:test:integration:runtime:leases` and `go:test:integration:runtime:workload`.
The multi-cycle Git identity proof runs separately through
`go:test:integration:cli:identity`; ordinary CLI shards exclude only that proof.
All matrix jobs contribute to the required `Go integration` result. CLI shards
cover the named-app workflows; the management job adds their unique service
share lookup checks. Native SDK checks run in the provider HTTP job, alongside
its transport checks, rather than repeating in the binary job.

The Node 24 function-artifact fixture runs
only through its explicit `go:test:integration:vercel` target and artifact input.
Run `mise exec -- task generate-check` against the intended committed generated
tree before delivery. It regenerates files, compares the shared generated-path
inventory with `HEAD`, and rejects untracked output. Intentional uncommitted
generated changes therefore appear as drift; successful regeneration is separate
from a clean `HEAD` comparison. `connect:generate-check` separately checks action
bundles. `format-check` only checks; `format` applies fixes. For a Markdown-only
change, use `mise exec -- pnpm exec oxfmt --write <owned-files>` and the same
explicit files with `--check` instead of a repository-wide formatter.

### choose a test tier

| When you need to check                     | Command after `mise exec --`                                 | What you need                                                                                                        |
| ------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| Routine behavior                           | `task test`                                                  | Installed dependencies; builds the JavaScript and Python packages                                                    |
| Go races                                   | `task go:test:race`                                          | No database                                                                                                          |
| Database and service boundaries            | `task go:test:integration`                                   | Docker and Pebble; Task manages PostgreSQL                                                                           |
| Durable control-state boundaries           | `task go:test:integration:state-boundaries`                  | Docker; secret rotation, combined retention workers, pageable admission history, and bounded native inventory        |
| Provider workload authority and selectors  | `task go:test:integration:workload`                          | Docker; disposable PostgreSQL and signed local GitHub, Vercel, Fly, and generic OIDC fixtures                        |
| Workload visitor transports                | `task go:test:integration:workload-runtime`                  | Docker and Pebble; two ingress/two relay topology, native PostgreSQL, HTTP/mTLS, and two real 90-second lease cycles |
| Native connection owner and prepared IPC   | `task go:test:connections`                                   | Local TLS fixtures and native subprocesses, without a human sign-in                                                  |
| Ad-hoc registration and publication        | `task go:test:invocations`                                   | Local control/TLS fixtures, real SQLite workers, and visitor request limits, without a human sign-in                 |
| Configured local app workflows             | `task go:test:app-workflows`                                 | Local owner, SQLite, enrollment, TLS mount and readiness fixtures                                                    |
| Built CLI local identity and selection     | `task go:test:integration:app-workflows`                     | Linux and Docker; disposable PostgreSQL, real CLI owners, app registration, and Git transitions                      |
| Drizzle Kit and native connection options  | `task go:test:integration:connections`                       | Docker; Task owns disposable PostgreSQL and a real Drizzle Kit migration                                             |
| Local Vercel Node function artifacts       | `task go:test:integration:vercel`                            | Docker and Pebble; Node 24.20.0 on PATH, installed tarballs, workload-owned native startup and real PostgreSQL       |
| Shared native workload HTTP boundary       | `task go:test:integration:provider-http`                     | Docker and Pebble; SDK/native IPC fixtures plus real workload HTTP certificates and separated runtime processes      |
| services and groups                        | `task go:test:integration:services`                          | Docker; saved services, applied groups, grants, and audit in PostgreSQL                                              |
| Control-state lock ordering                | `task go:test:integration:state-locks`                       | Docker; deterministic lock gates and wait-graph checks in disposable PostgreSQL                                      |
| Private claim recovery and capacity        | `task go:test:integration:service-claims`                    | Docker; committed HTTP response loss through relay, mixed public/private claims, and certificate deadlines           |
| HTTP services                              | `task go:test:integration:http-services`                     | Docker and Pebble; applied HTTP settings, visitor admission, OIDC, grants, and streams                               |
| Fixed-list cross-team publishers           | `task go:test:integration:publisher-groups`                  | Linux and Docker; one real CLI process, independent group identities, managed TLS and disposable PostgreSQL          |
| Signed-human service access and CLI lookup | `task go:test:integration:service-access`                    | Docker; configured signed issuer, current management/source checks, and exact-service invitations in PostgreSQL      |
| Publisher egress evidence                  | `task go:test:integration:publisher-egress`                  | Docker; signed runtime leases and trusted proxy metadata, without public IP lookups                                  |
| Private runtime topology                   | `task go:test:integration:service-topology`                  | Docker and Pebble; separated and standalone private visitor lifecycle                                                |
| Real database clients                      | `task go:test:integration:tcp-clients`                       | Docker CLI, uv and Python; disposable TLS providers, installed Node drivers and an isolated psycopg consumer         |
| CLI and OpenSSH stdio                      | `task go:test:integration:cli`                               | Isolated Linux, Docker, sshd/ssh/ssh-keygen, writable `/etc/hosts` or passwordless sudo for that fixture only        |
| Existing OpenSSH target                    | `task go:test:integration:sshd`                              | System `sshd`, `ssh`, and `ssh-keygen`; no root tnl process                                                          |
| Binary behavior                            | `task go:test:integration:binary`                            | Integration prerequisites and Linux with local DNS/HTTPS ports available                                             |
| Compose target discovery                   | `task go:test:integration:compose`                           | Docker; disposable HTTP and TCP targets with container replacement                                                   |
| Ubuntu and Compose publisher installation  | `task go:test:integration:publisher-install`                 | Docker; privileged disposable Ubuntu/systemd, private trust, and disposable PostgreSQL; never installs on the host   |
| Authoritative DNS                          | `task go:test:integration:dns`                               | Docker Compose; runs DNS on port 53 inside Linux containers                                                          |
| Public Route 53 and ACME staging           | `task go:test:integration:route53 ZONE_ID=<staging-zone-id>` | Disposable PostgreSQL and staging AWS OIDC under `test.tnl.wtf`; opt-in                                              |
| Fuzz targets                               | `task go:test:fuzz`                                          | Go toolchain                                                                                                         |
| npm exports and tarballs                   | `pnpm run pack`                                              | Built package dependencies                                                                                           |
| Python ASGI and socket contract            | `task py:check`                                              | Go, pinned Python, uv, and pnpm; locked dependencies, real native owner, and wheel source/type-marker checks         |
| Local release snapshot                     | `task package`                                               | Builds and checks packages; does not publish                                                                         |
| Actual npm release tarballs                | `task release:npm-package`                                   | `task release:snapshot` first; installs the generated tarballs with npm and pnpm                                     |
| Deployed release check                     | `task release:check:plan` / `task release:check:run`         | Saved login, released `tnl`, test team, ready custom domain                                                          |

For native client trace propagation and bounded flush, run
`task go:test:client-tracing` and `task js:test:client-tracing` through `mise exec --`.
The existing connection tier also checks the real CLI-to-detached-owner trace chain.

For native owner concurrency and shutdown, run `task go:test:owner-lifecycle -- -race`.
`task go:test:integration:owner-lifecycle` owns disposable PostgreSQL and checks
one native owner serving real HTTP and PostgreSQL while another request stalls.
Prepared reads publish metadata and transport identity together; they never wait
for another service's preparation or an assertion exchange.

For config serialization, evaluated native-owner snapshots, resolved target trust,
service references, and local status protocols, run `task go:test:config-contracts`
through `mise exec --`. `task js:typecheck` checks the same reference restrictions
in config literals and synchronous/asynchronous factories, along with SDK types.

When editing a complete configuration example, check it with `tnl check` using
the selected source format. Normalized control API examples also need the
production `NormalizeProjectConfiguration` validator: OpenAPI field validation
alone does not enforce named-group endpoint ownership. Keep example checks at
that existing boundary rather than copying its rules into a documentation test.

For configured local publication, no Git repository or origin is required.
`LocalPublicationIdentity` and `LocalWorktreeKey` bind the canonical directory;
portable `SourceIdentity` still requires Git for apply, AWS generation, and
workload manifests. Owner discovery and named leases compare the evaluated
snapshot digest, including configuration provenance and server/team selection.
After changing configuration, stop and restart all apps and named local
publishers for the project together. The app-workflows tier covers these fences
and once-per-run automatic readiness with its bounded retry budget.

For public HTTP live authorization, run `task go:test:live-authorization`, then
`task go:test:live-authorization -- -race`. These use deterministic clocks for
long HTTP/WebSocket renewal, denial, outage deadlines, and HTTP/2 isolation.
`task go:test:integration:live-authorization` owns disposable PostgreSQL for
browser and alias handoffs, current visitor authorization, and HTTP logout.

For ingress production wiring, pool selection, lifetime traffic totals, pending
promotion, private relay fallback, and server-first half-closes, run
`task go:test:ingress`, then `task go:test:ingress -- -race`.
`task go:test:integration:ingress` owns disposable PostgreSQL for terminal
retirement evidence and real split/standalone forwarding.
`task go:test:integration:local-oidc` checks the actual UID-65532 provider with a
mode-0600 key on a Linux-native filesystem, including on Docker Desktop.

For native HTTP forwarding, run `task go:test:http-streaming` and
`task go:test:http-streaming -- -race` through `mise exec --`. these use local
HTTP/1 and HTTP/2 wires for early responses during uploads, upload deadlines,
trailers, long responses, upgrades, cancellation, and inspection outcomes.

For native observability, run `task go:test:observability` and
`task go:test:server` through `mise exec --`. these include disabled-startup
subprocesses with malformed ambient settings, decoded OTLP exemplars and gauge
types, safe audit reporter causes, and metric collection during ingress
construction. `task go:test:integration:runtime RUN='^TestIntegrationServiceAuditCleanupObservedOnce$'`
checks the cleanup worker's exact count against an instrumented disposable
PostgreSQL database.

For native database TLS and authentication, run `task go:test:database-native -- -race`.
`task go:test:integration:tcp-clients` owns disposable TLS PostgreSQL and MySQL,
installs the Node SDK and Python wheel into isolated consumers, and checks real
queries, selected connection lifetimes, and the
[native cancellation boundary](docs/maintainers/publisher/database-cancellation.md).

For SDK connection lifetimes and owned HTTP transport, run
`task js:test:connections` through `mise exec --`. Its installed ESM/CommonJS
fixture runs actual Node and Bun processes against local TLS, including the
managed Host/SNI and loopback dial boundary. This is local transport evidence;
deployed provider freeze/thaw remains open. For action OIDC cancellation and
late-result rejection, run `task connect:check`. The Python lifecycle checks in
`task py:check` cover joined publication cleanup, fork ownership, and bounded
native exchange.

Use `RUN` to select an integration test, for example:

```console
mise exec -- task go:test:integration RUN='^TestIntegrationPublicURLRecovery$'
mise exec -- task go:test:focused PACKAGES='./internal/publisher/app ./internal/publisher/target' RUN='^TestAutomaticReadiness'
```

Binary integration changes subprocess trust and binds privileged ports. Run it
only on Linux; the [integration workflow](.github/workflows/integration.yml)
shows its setup. For database and runtime load tests, see the
[local workloads](docs/benchmarks/local-workloads.md). Large runs are opt-in.

When Linux tests run inside a Docker host-network container, mount the Docker
socket and a shared temporary directory at the same absolute path on the runner
and Docker host. Set `TMPDIR` to that shared directory so the built-binary Compose
test can mount its binaries, CA roots, and project files into sibling containers.
Keep client-state socket directories short. Install `sshd` and create `/run/sshd`
inside the disposable runner before the CLI tier. The binary tier also builds
the JavaScript package, so use a writable checkout snapshot with Linux npm
dependencies rather than the host's platform-specific `node_modules`.

If Docker Desktop's `host-gateway` points outside the host-network runner, pass
its bridge address explicitly with
`task go:test:integration:binary COMPOSE_HOST_ADDRESS=172.17.0.1` (use the address
reported by `docker network inspect bridge`). This only selects the disposable
test ingress address; TLS names and certificate verification remain unchanged.

The DNS e2e job in Checks uses one fresh name under `test.tnl.wtf`, a disposable
Let's Encrypt staging account, and at most one order per `main` push. It
checks real Route 53 change propagation and DNS-01 issuance, then removes
only the test-owned TXT record. Keep the fake Route 53 and Pebble tests in
routine and DNS integration CI; they cover retries and crashes without
depending on an external service.

Use the pinned Go toolchain for direct commands:

```console
mise exec -- go test ./internal/transport/tunnel
```

Go unit and white-box integration tests stay beside the owning implementation,
including daemon composition proofs. Built-CLI black-box suites live under
`tests/integration/<boundary>`; shared subprocess/Compose assets live under
`tests/integration/fixtures`. Package-local `testdata` moves with its parser or
runtime. Shared test helpers stay in test-only `internal/testutil` children.

### test the javascript package

All TypeScript tests use Vitest. `pnpm test` and `pnpm typecheck` build first.
Their `:run` variants and direct Vitest runs reuse an existing build. For one
focused test:

```console
mise exec -- pnpm --filter @tnldotdev/tnl build
mise exec -- pnpm exec vitest run packages/ts/test/frameworks/vite.test.ts
```

Run `mise exec -- task js:check` to build once and run the JavaScript checks
used in CI, including package verification.

`task js:pack` checks a source npm pack. to check the release packer and its
installed consumers without publishing, run:

```console
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task release:snapshot
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task release:npm-package
```

the second Task builds the SDK, packages all four native targets from the real
snapshot archives, and installs the release launcher and host native tarball in
independent npm and pnpm consumers. both consumers check every public export,
including Node ESM/CommonJS workload imports and browser restrictions. native
dependencies resolve from local tarballs; third-party runtime dependencies need
registry access. packing checks all manifest export targets, executable modes,
binary hashes, and legal files. only the host native executable runs locally.
the Checks workflow reuses its Python job's snapshot for this release-package check.
the Vercel fixture builds its own packages and does not qualify this release path.

For the opt-in emitted Vercel Node function check, see
[local Vercel qualification](docs/maintainers/connector/vercel-functions.md). its Tasks use
Node `24.20.0` from `PATH`, including on CI; they do not invoke mise internally.
the root mise environment defaults to Node 22, so select Node 24 explicitly:

```console
mise exec node@24.20.0 -- task go:test:integration:vercel
```

the artifact check starts its own packaged native owner with signed local Vercel
request context and a generated manifest. it checks shared HTTP/PostgreSQL,
incremental preparation, concurrent cold/warm budgets, assertion failures, and
real revocation against local server roles. optional Linux x64 container execution
uses `LINUX_NODE_IMAGE`; deployed provider sandbox lifetime remains a separate
qualification boundary described in the maintainer guide.

The feedback toolbar source and Vitest tests live in `internal/publisher/toolbar`.
Its committed `toolbar.js` is generated by `task generate` for Go embedding.
Install Chromium with `mise exec -- pnpm exec playwright install chromium`, then
run `mise exec -- task js:test:browser` to test that bundle under browser CSP.

SDK tests and helpers live under `packages/ts/test`, grouped by publisher,
connector, project, frameworks, native, helpers, types, and fixtures. Focused
`js:test:{connections,frameworks,client-tracing}` targets select those paths and
build first. Normal tests use built modules; coverage aliases instrument the
matching source owners. Positive/negative compiler assertions stay in
`test/types` and their explicit package-level TypeScript projects.

Keep the package root safe to import in a browser. Public exports are the root,
`/config`, `/next`, `/vite`, and Node-only `/workload`. The root supports ESM,
CommonJS, and browser import/require; workload supports Node ESM/CommonJS with
one shared configuration singleton. The lazy connector bridge is built at
`dist/internal/connector/connection.cjs`; its errors retain public `TnlError`
identity. Browser imports must not load native credentials or startup, and
`/workload` must fail under browser conditions. The public export conditions live in
`packages/ts/package.json`; the private development socket is not an extension
API. Write npm runtime code and tooling in TypeScript. Validate external data
before treating it as a known type. The
[compatibility workflow](.github/workflows/checks.yml) checks supported
framework versions.

### test the python binding

Run `mise exec -- task py:check` for Ruff, mypy, and pytest. The Python
distribution source is under `packages/py/`; uv uses its committed `uv.lock`.
The test Task builds the native CLI and a local connection owner, then exercises
the prepared-read contract and verified Python TLS without a sign-in or database.
`task py:package-check` verifies wheel sources and the `py.typed` marker without
building release artifacts.
After `task release:snapshot`, `task py:build` verifies four platform wheels
against those artifacts. The ASGI tests cover
lifespan startup, streamed responses, WebSockets, private HTTP bounds,
and cleanup without a deployed server.

## edit generated sources

Edit the source, then run `mise exec -- task generate` and
`mise exec -- task format`. Do not edit committed generated files by hand.

The client uses `v1.db` in its state directory, without reading or importing
older client databases. Its one Goose migration creates the fresh baseline;
future compatible migrations may advance that version. The server's PostgreSQL
baseline requires a fresh database and a coordinated stop/start of all serving
roles. Control checks both the exact migration version and baseline identity
before serving.

The single PostgreSQL baseline includes durable publisher certificate-plan
checkpoints. Fresh identities have an empty plan inventory; submitted plans
remain required after order cleanup. See [publisher groups](docs/maintainers/publisher/publisher-groups.md).

For local services, an explicit `publicURL` block (`public_url` in static files)
enables public HTTPS. Without it, the service is private, including `protocol: http`.
Named groups use their own `public` setting for reachability and always require
current HTTP credentials. Their service `http.access` and `http.limits` settings
control restricted HTTP/IP access and request limits on the group's endpoint.
The protocol defaults to `http`; `tcp` carries opaque bytes, and `mysql` and
`postgres` select private database handling. A service's saved `name` defaults
to its configuration key on either path. `access: {team: true}` declares team
access. `target.tls` enables verified publisher-to-target TLS for every protocol;
the protocol selects direct TLS or PostgreSQL/MySQL negotiation. It accepts
optional `server_name` and project-relative `ca_file` (`serverName` and `caFile`
in TypeScript); an empty block uses system roots. Omitting it permits a plaintext
target and never disables managed visitor TLS. Service-level `tls` and
`target.tls.mode` are rejected. An existing sshd is an
ordinary private `tcp` target. See [service boundaries](docs/maintainers/control/services.md).

Project configuration stays in Git. `tnl apply` stores an evaluated revision in
control; named group publishers pull and acknowledge only their assignments.
The reserved `local` publisher handles app-reported development listeners by
default. Starting an app does not apply production configuration. Group entries
accept `description`, `domain`, and `public`, plus an optional `aws: {replicas: 2}`
deployment declaration. `tnl generate` writes a trackable group stack; detailed
AWS settings remain CloudFormation deployment parameters. AWS capacity is excluded
from control assignments. See [applied projects](docs/maintainers/control/applied-projects.md) and
the [publisher infrastructure templates](deploy/publisher/fargate/readme.md).

| Authoritative source                                              | Generator / configuration                                                                  | Committed generated output                                                                                  |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `api/control/public/v1/openapi.yaml` and its fragments            | `scripts/generate/openapi.ts`; `pkg/api/control/public/v1/{generate.go,oapi-codegen.yaml}` | `pkg/api/control/public/v1/openapi.gen.go`                                                                  |
| `api/control/authority/v1/openapi.yaml` and fragments             | Same generator; `pkg/api/control/authority/v1` configuration                               | `pkg/api/control/authority/v1/openapi.gen.go`                                                               |
| `api/control/private/ingress/v1/openapi.yaml` and fragments       | Same generator; `pkg/api/control/private/ingress/v1` configuration                         | `pkg/api/control/private/ingress/v1/openapi.gen.go`                                                         |
| `api/control/private/relay/v1/openapi.yaml` and fragments         | Same generator; `pkg/api/control/private/relay/v1` configuration                           | `pkg/api/control/private/relay/v1/openapi.gen.go`                                                           |
| `api/integrations/public-url-usage/v1/openapi.yaml` and fragments | Same generator; `pkg/api/integrations/public-url-usage/v1` configuration                   | `pkg/api/integrations/public-url-usage/v1/openapi.gen.go`                                                   |
| `api/publisher/browser/v1/openapi.yaml` and fragments             | Same Go generator plus `scripts/generate/publisher-model.ts`                               | `pkg/api/publisher/browser/v1/openapi.gen.go`, `internal/publisher/browserapi/model.gen.ts`                 |
| `api/publisher/local/v1/openapi.yaml` and fragments               | Same Go generator; `pkg/api/publisher/local/v1` configuration                              | `pkg/api/publisher/local/v1/openapi.gen.go`                                                                 |
| `internal/control/state/{migrations,queries,sqlc.yaml}`           | `internal/control/state/generate.go`, sqlc                                                 | `internal/control/state/controlstatedb/*.go`                                                                |
| `internal/client/state/{migrations,queries,sqlc.yaml}`            | `internal/client/state/generate.go`, sqlc                                                  | `internal/client/state/clientstatedb/*.go`                                                                  |
| `internal/config` types and project key mappings                  | `internal/config/cmd/configgen`, `scripts/generate/config-types.ts`                        | `schema/v1.json`, `internal/client/project/keys.gen.json`, `packages/ts/src/config.gen.ts`                  |
| `internal/client/project/loader.ts`                               | `scripts/generate/projectconfig-loader.ts`                                                 | Neighboring `loader.mjs`, embedded by Go                                                                    |
| `internal/publisher/toolbar` TS/TSX/CSS                           | `scripts/build/feedback-toolbar.ts`                                                        | Neighboring `toolbar.js`, embedded by Go                                                                    |
| `internal/publisher/deployment` renderer                          | Its `cmd/fixture` and `generate.go`                                                        | `deploy/publisher/fargate/fargate.{yaml,parameters.example.json,manifest.example.json,storage-policy.json}` |
| `internal/failure/diagnostic/catalog.json`                        | `scripts/generate/diagnostic-codes.ts`                                                     | Neighboring `codes.gen.go`; sibling sync generates public diagnostic pages                                  |
| `internal/failure/reasons.go`                                     | `internal/failure/cmd/cataloggen`                                                          | `internal/failure/catalog.gen.json`; sibling sync generates public error pages                              |
| `internal/observability` declarations                             | Its vocabulary generator                                                                   | `api/observability/v1/vocabulary.json`, shared with tnl.dev                                                 |
| `scripts/installer/install.sh.in` and CLI renderer                | `scripts/installer/generate.go`, `internal/clioutput/generate.go`                          | `scripts/install.sh`, whose public download path is preserved                                               |
| `connect/src` and its build inputs                                | `connect/scripts`, `task connect:check`                                                    | `connect/dist`, checked separately by `connect:generate-check`                                              |

Edit OpenAPI fragments and generator
configuration before regenerating; never patch generated public models. Reference
identical control schemas instead of copying them. The handwritten
`pkg/protocol/tunnelv1` remains the only tunnel wire source.

`task generate` first runs the seven Go API generators, then browser validators,
then other Go directives while skipping those two scripts. `tasks/generate.yml`
owns the committed-output inventory used for both `HEAD` comparison and untracked
output detection. OpenAPI bundles are disposable generator inputs. External source
consumers can run `node scripts/generate/openapi.ts --bundle-dir <absolute-dir>`
through `mise exec --` to obtain all seven portable, cross-referencing bundles;
copying an entrypoint alone omits its fragments.

`packages/ts/dist` is disposable build output. `tnl generate` writes portable
`.tnl/generated/project.d.ts` and applicable publisher AWS artifacts for source
control. The runtime writes ignored `.tnl/local/project.json` values; it never
writes declarations. Ignore only `/.tnl/local/` at the selected project root.
See [portable generation](docs/maintainers/development/portable-generation.md) and the
[framework guide](https://tnl.dev/docs/frameworks) for their use.

## try the local stack

The local stack builds this checkout and runs PostgreSQL, Pebble, a development
OIDC provider, and standalone `tnld`. It uses `127.0.0.1.nip.io` for public URL hostnames and binds host
ports on localhost. With Docker running:

```console
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
mise exec -- task local:tnl -- team current
```

`local:trust` asks macOS to trust the local certificate roots in your login
keychain. `local:login` saves a session in this repo's `.local/client-state`,
separate from your usual tnl state. To use it from another project, set these
values while still in the tnl repo:

```console
export TNL_SERVER=https://control.127.0.0.1.nip.io:8445
export TNL_STATE_DIR="$(pwd)/.local/client-state"
```

Then start the app normally from that project's directory. `task local:down` preserves
PostgreSQL state; `task local:reset` removes trust, containers, volumes, and
`.local`. Run both through `mise exec --` from this repo.

Hosted Fly manifests, rollout tooling, and staging qualification belong to
[tnl.dev](https://github.com/tnldotdev/tnl.dev/tree/main/deploy/server). Run their
offline manifest checks in that repository. This repository owns generic
self-hosted Compose and publisher infrastructure templates. The baseline
PostgreSQL migration needs a fresh database. Releases publish immutable image
digests; deploying and qualifying them requires separate operator approval.

## find the right reference

- [Architecture](docs/maintainers/architecture.md) explains package ownership,
  APIs, and runtime boundaries. [AGENTS.md](AGENTS.md) defines the terms and CLI
  output rules used in this repo.
- [Observability](docs/maintainers/development/metrics.md) lists the shared vocabulary, OTel
  process ownership, optional export settings, and instrument boundaries.
- [Benchmarks](docs/benchmarks/readme.md) covers local results and deployed
  workloads. Deployed runs require explicit approval.
- [Releasing](docs/maintainers/releases/releasing.md) covers maintainer release rules.

Prefer the smallest change that solves the problem. Reuse the package that owns
the behavior, and test its boundaries instead of adding tests that only repeat
the implementation.

Dependencies need a compatible license and a clear purpose. Add attribution for
direct runtime dependencies to `NOTICE`; release archives and native npm
packages must include `LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`.
