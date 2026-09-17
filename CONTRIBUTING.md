# Contributing

## Development

Run commands from the repository root with the toolchain pinned in `mise.toml`:

```console
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
```

The full local sequence is:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task generate-check
mise exec -- task format-check
mise exec -- task lint
mise exec -- task test
mise exec -- task go:test-race
mise exec -- task go:test-integration
mise exec -- task build
```

Prepare the integration prerequisites below before running that tier.
`generate-check` regenerates files and compares committed generated paths to
`HEAD`; intentional uncommitted generated changes also appear as drift.
`format-check` is read-only. `format` applies Goimports and Oxfmt.

### Test Tiers

| Tier               | Command after `mise exec --`                                 | Prerequisites and scope                                                                     |
| ------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Routine            | `task test`                                                  | Installed JavaScript dependencies; includes a package build                                 |
| Race               | `task go:test-race`                                          | Go race detector; integration tests remain opt-in                                           |
| Integration        | `task go:test-integration`                                   | Disposable PostgreSQL, Pebble from `mise install`, installed dependencies, and `pnpm build` |
| Binary integration | `env TNL_TEST_BINARY_INTEGRATION=1 task go:test-integration` | Integration prerequisites plus disposable Linux with local DNS/HTTPS ports available        |
| DNS integration    | `task go:test-integration-dns-linux`                         | Docker; runs the authoritative DNS test with isolated Linux port 53 and PostgreSQL          |
| Package checks     | `pnpm run pack`                                              | Checks JavaScript exports and tarball contents                                              |
| Release snapshot   | `task package`                                               | Builds native archives and npm packages, then verifies installations; does not publish      |

Integration tests require `TNL_TEST_POSTGRES_URL`. It must point to a disposable
PostgreSQL server whose user can create databases. The fixtures create and
forcibly drop databases, so never use a production server.

Binary tests change subprocess trust and configuration and bind privileged
ports. They run only on Linux; use the
[integration workflow](.github/workflows/integration.yml) as the setup
reference. The DNS integration task creates separate Linux and PostgreSQL
containers without exposing their ports on the host. This lets the test DNS
server use port 53 inside its container on any Docker host.

Task supplies `GOFLAGS=-tags=ts_omit_ssh`. Preserve it for direct Go commands:

```console
mise exec -- env GOFLAGS=-tags=ts_omit_ssh go test ./internal/tunnel
```

### JavaScript Package

`pnpm test` and `pnpm typecheck` build through lifecycle hooks. Their `:ci`
variants and direct Vitest runs do not. Build once before focused tests:

```console
mise exec -- pnpm --filter @tnldotdev/tnl build
mise exec -- pnpm exec vitest run packages/tnl/vite.test.ts
```

Keep the root package safe to run in a browser. Keep Node-only discovery and
framework code internal. `packages/tnl/package.json` defines the public exports;
the private development socket is not an extension API. The
[compatibility matrix](.github/workflows/checks.yml) tests supported framework
versions.

`packages/tnl/lib/native-targets.mjs` lists the native npm targets. When adding a
target, also add its native package template, GoReleaser artifact, launcher test
expectations, and package checks. Preserve checks for archive equality, license
files, public exports, and publishing native packages before the launcher.

### Generated Sources

Edit source contracts, then run `task generate` and `task format` through mise.
Do not hand-edit generated output.

| Source                                                                                                          | Committed output                                                                         |
| --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Five HTTP OpenAPI sources under `api/*/v1`                                                                      | Models, clients, and server interfaces under `pkg/api/*`                                 |
| `internal/controlstate/migrations` and `queries`                                                                | `internal/controlstate/controlstatedb`                                                   |
| `internal/clientstate/migrations` and `queries`                                                                 | `internal/clientstate/clientstatedb`                                                     |
| `internal/config` and its generator, `internal/projectconfig` key mappings, `scripts/generate-config-types.mjs` | `schema/v1.json`, `internal/projectconfig/keys.gen.json`, `packages/tnl/lib/config.d.ts` |

`packages/tnl/src` is handwritten; `packages/tnl/dist` is disposable build
output. Project-local `.tnl/project.json` and `.tnl/project.d.ts` are generated
by the CLI, not repository code generation. Their user workflow belongs in the
[package guide](packages/tnl/README.md).

## Local Stack

The local stack builds this checkout and runs PostgreSQL, Pebble, and standalone
`tnld`. It uses `127.0.0.1.nip.io` for public route namespaces and publishes ports
only on localhost. With Docker running:

```console
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
mise exec -- task local:tnl -- team current
```

`local:trust` modifies the macOS login keychain to trust the local certificate
roots. `mise exec -- task local:down` preserves PostgreSQL state;
`mise exec -- task local:reset` removes trust, containers, volumes, and `.local`.

Fly benchmarks are separate from local validation. Execution requires explicit
approval and the [benchmark gates](docs/benchmarks/README.md).

## Engineering Rules

- Follow [Architecture](docs/ARCHITECTURE.md) for package and API ownership and
  [AGENTS.md](AGENTS.md) for canonical terminology and CLI presentation rules.
- Prefer the smallest design that completes the current phase.
- Reuse the service that already owns a behavior, along with generated
  contracts, schema-derived types, and shared fixtures. Do not create a second
  implementation of the same rule.
- Use a maintained library instead of hand-rolling a capability. Ask before
  introducing a custom implementation when the tradeoff is unclear.
- Keep portable server packages independent of hosted protocol and domain types.
- Add tests for behavior, boundaries, and regressions. Do not add tautological
  tests solely to increase test counts.
- Keep release approval and publishing procedures in the
  [release guide](docs/RELEASES.md), not local development recipes.

## Dependencies And Notices

Every dependency must have a compatible license and a clear purpose. Direct
runtime dependencies that require attribution must add their notices to
`NOTICE`; generated release archives and native npm packages must include
`LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`.
