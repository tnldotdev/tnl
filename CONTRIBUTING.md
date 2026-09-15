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
| Package checks     | `pnpm run pack`                                              | Checks JavaScript exports and tarball contents                                              |
| Release snapshot   | `task package`                                               | Builds native archives and npm packages, then verifies installations; does not publish      |

Integration tests require `TNL_TEST_POSTGRES_URL` pointing to a disposable
PostgreSQL server with permission to create databases. Fixtures create and
forcibly drop test databases; never use a production server. Binary tests also
change subprocess trust/configuration and bind low ports. Use the
[integration workflow](.github/workflows/integration.yml) as the Linux setup
reference; the binary tier cannot run on macOS.

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

Keep the root runtime browser-safe and Node-only discovery and framework code
internal. Public exports are defined by `packages/tnl/package.json`; the private
development socket is not an extension API. Framework versions are exercised by
the [compatibility matrix](.github/workflows/checks.yml).

Native npm targets are owned by `packages/tnl/lib/native-targets.mjs`. Adding a
target also requires its native template, GoReleaser artifact support, independent
launcher test expectations, and package verification. Keep archive equality,
license contents, public exports, and native-first publishing checks intact.

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
only on loopback. With Docker running:

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
- Reuse authoritative domain services, generated contracts, schema-derived
  types, and shared fixtures instead of creating parallel implementations.
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
