# contributing

Run commands from the repository root. The tool versions are pinned in `mise.toml`:

```console
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- uv sync --frozen --project packages/py
```

## check your change

Run the checks that fit your change. Before sending a broad change, use the full
sequence:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task generate-check
mise exec -- task format-check
mise exec -- task lint
mise exec -- task test
mise exec -- task go:test:race
mise exec -- task go:test:integration
mise exec -- task build
```

Integration needs Docker and Pebble from `mise install`. The Task targets use
Testcontainers for Go in the separate `tools/testharness` Go module to create
and remove digest-pinned disposable databases; it is not a product binary
dependency. Each PostgreSQL-backed invocation shares one PostgreSQL container
while each test creates its own database. The same harness drives the runtime
load topology and fault sweeps without a TypeScript container runner.
`generate-check` regenerates files and compares them with `HEAD`, so intentional
uncommitted generated changes also appear as drift. `format-check` only checks;
`format` applies fixes.

### choose a test tier

| When you need to check           | Command after `mise exec --`                                 | What you need                                                                                                 |
| -------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Routine behavior                 | `task test`                                                  | Installed dependencies; builds the JavaScript and Python packages                                             |
| Go races                         | `task go:test:race`                                          | No database                                                                                                   |
| Database and service boundaries  | `task go:test:integration`                                   | Docker and Pebble; Task manages PostgreSQL                                                                    |
| Private services and groups      | `task go:test:integration:private-services`                  | Docker; saved services, applied groups, grants, and audit in PostgreSQL                                       |
| Publisher egress evidence        | `task go:test:integration:publisher-egress`                  | Docker; signed runtime leases and trusted proxy metadata, without public IP lookups                           |
| Private runtime topology         | `task go:test:integration:private-topology`                  | Docker and Pebble; separated and standalone private visitor lifecycle                                         |
| Real database clients            | `task go:test:integration:tcp-clients`                       | Docker CLI; disposable TLS providers also run psql and mysql                                                  |
| CLI and OpenSSH stdio            | `task go:test:integration:cli`                               | Isolated Linux, Docker, sshd/ssh/ssh-keygen, writable `/etc/hosts` or passwordless sudo for that fixture only |
| Existing OpenSSH target          | `task go:test:integration:private-sshd`                      | System `sshd`, `ssh`, and `ssh-keygen`; no root tnl process                                                   |
| Binary behavior                  | `task go:test:integration:binary`                            | Integration prerequisites and Linux with local DNS/HTTPS ports available                                      |
| Compose target discovery         | `task go:test:integration:compose`                           | Docker; disposable HTTP and TCP targets with container replacement                                            |
| Authoritative DNS                | `task go:test:integration:dns`                               | Docker Compose; runs DNS on port 53 inside Linux containers                                                   |
| Public Route 53 and ACME staging | `task go:test:integration:route53 ZONE_ID=<staging-zone-id>` | Disposable PostgreSQL and staging AWS OIDC under `test.tnl.wtf`; opt-in                                       |
| Fuzz targets                     | `task go:test:fuzz`                                          | Go toolchain                                                                                                  |
| npm exports and tarballs         | `pnpm run pack`                                              | Built package dependencies                                                                                    |
| Python ASGI and socket contract  | `task py:check`                                              | Pinned Python and uv; uses the locked dependencies in `packages/py`                                           |
| Local release snapshot           | `task package`                                               | Builds and checks packages; does not publish                                                                  |
| Deployed release check           | `task release:check:plan` / `task release:check:run`         | Saved login, released `tnl`, test team, ready custom domain                                                   |

Use `RUN` to select an integration test, for example:

```console
mise exec -- task go:test:integration RUN='^TestIntegrationPublicURLRecovery$'
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
mise exec -- go test ./internal/tunnel
```

### test the javascript package

All TypeScript tests use Vitest. `pnpm test` and `pnpm typecheck` build first.
Their `:run` variants and direct Vitest runs reuse an existing build. For one
focused test:

```console
mise exec -- pnpm --filter @tnldotdev/tnl build
mise exec -- pnpm exec vitest run packages/ts/vite.test.ts
```

Run `mise exec -- task js:check` to build once and run the JavaScript checks
used in CI, including package verification.

The feedback toolbar source and Vitest tests live in `internal/feedbacktoolbar`.
Its committed `toolbar.js` is generated by `task generate` for Go embedding.
Install Chromium with `mise exec -- pnpm exec playwright install chromium`, then
run `mise exec -- task js:test:browser` to test that bundle under browser CSP.

Keep the package root safe to import in a browser. The public exports live in
`packages/ts/package.json`; the private development socket is not an extension
API. Write npm runtime code and tooling in TypeScript. Validate external data
before treating it as a known type. The
[compatibility workflow](.github/workflows/checks.yml) checks supported
framework versions.

### test the python binding

Run `mise exec -- task py:check` for Ruff, mypy, and pytest. The Python
distribution source is under `packages/py/`; uv uses its committed `uv.lock`.
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

For local services, an explicit `publicURL` block (`public_url` in static files)
enables public HTTPS. Without it, the service is private, including `protocol: http`.
Named groups use their own `public` setting for reachability and always require
current HTTP credentials. Their service `publicURL` blocks hold only restricted
HTTP/IP settings and HTTP request limits; they cannot change the group's endpoint.
The protocol defaults to `http`; `tcp` carries opaque bytes, and `mysql` and
`postgres` select private database handling. A service's saved `name` defaults
to its configuration key on either path. `access: {team: true}` declares team
access. `target.tls` enables verified publisher-to-target TLS for every protocol;
the protocol selects direct TLS or PostgreSQL/MySQL negotiation. It accepts
optional `server_name` and project-relative `ca_file` (`serverName` and `caFile`
in TypeScript); an empty block uses system roots. Omitting it permits a plaintext
target and never disables managed visitor TLS. Service-level `tls` and
`target.tls.mode` are rejected. An existing sshd is an
ordinary private `tcp` target. See [private service boundaries](docs/maintainers/private-services.md).

Project configuration stays in Git. `tnl apply` stores an evaluated revision in
control; named group publishers pull and acknowledge only their assignments.
The reserved `local` publisher handles app-reported development listeners by
default. Starting an app does not apply production configuration. Group entries
accept `description`, `domain`, and `public`, plus an optional `aws: {replicas: 2}`
deployment declaration. `tnl generate` writes a trackable group stack; detailed
AWS settings remain CloudFormation deployment parameters. AWS capacity is excluded
from control assignments. See [applied projects](docs/maintainers/applied-projects.md) and
the [publisher infrastructure templates](deploy/publishers/readme.md).

| Source                                                                                    | Generated output                                                                          |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Seven HTTP OpenAPI contracts under `api/*/v1`                                             | `pkg/api/*`; publisher browser validators under `internal/publisherapi`                   |
| PostgreSQL migrations and queries under `internal/controlstate`                           | `internal/controlstate/controlstatedb`                                                    |
| SQLite migrations and queries under `internal/clientstate`                                | `internal/clientstate/clientstatedb`                                                      |
| `internal/config`, project configuration mappings, and `scripts/generate-config-types.ts` | `schema/v1.json`, `internal/projectconfig/keys.gen.json`, `packages/ts/src/config.gen.ts` |
| `internal/projectconfig/loader.ts`                                                        | `internal/projectconfig/loader.mjs`, embedded by Go                                       |
| `internal/publisherdeployment`                                                            | `deploy/publishers/fargate.yaml` and its example manifest/parameters                      |
| `internal/diagnostic/catalog.json`                                                        | `internal/diagnostic/codes.gen.go` and the tnl.dev diagnostic pages                       |
| `internal/failure/reasons.go`                                                             | `internal/failure/catalog.gen.json` and the tnl.dev client-error pages                    |
| `internal/observability` vocabulary and instrument declarations                           | `api/observability/v1/vocabulary.json`, shared with tnl.dev                               |

`packages/ts/dist` is disposable build output. `tnl generate` writes portable
`.tnl/generated/project.d.ts` and applicable publisher AWS artifacts for source
control. The runtime writes ignored `.tnl/local/project.json` values; it never
writes declarations. Ignore only `/.tnl/local/` at the selected project root.
See [portable generation](docs/maintainers/portable-generation.md) and the
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
- [Observability](docs/maintainers/metrics.md) lists the shared vocabulary, OTel
  process ownership, optional export settings, and instrument boundaries.
- [Benchmarks](docs/benchmarks/readme.md) covers local results and deployed
  workloads. Deployed runs require explicit approval.
- [Releasing](docs/maintainers/releasing.md) covers maintainer release rules.

Prefer the smallest change that solves the problem. Reuse the package that owns
the behavior, and test its boundaries instead of adding tests that only repeat
the implementation.

Dependencies need a compatible license and a clear purpose. Add attribution for
direct runtime dependencies to `NOTICE`; release archives and native npm
packages must include `LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`.
