# contributing

Use [architecture](architecture.md) to find the owner of a change and
understand its dependencies. Read [AGENTS.md](AGENTS.md) for repository policies.

## get set up

Install [mise](https://mise.jdx.dev), then run these from the repository root:

```sh
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- uv sync --frozen --project packages/py
```

Run repository commands through `mise exec --` to use the versions in `mise.toml`.
CI installs selected tools from the same file. `flyctl` remains available for
operator work but is not installed by routine CI jobs.

## check your change

Pick the checks for the code you changed:

```sh
mise exec -- task go:test
mise exec -- task go:lint
mise exec -- task js:check
mise exec -- task py:check
mise exec -- task connect:check
```

For one Go package or test:

```sh
mise exec -- task go:test:focused PACKAGES=./internal/publisher/target RUN=Test
```

Dependency checks keep the service tree and shared publisher packages from
importing publisher root. For HTTP changes, use `internal/publisher/httpaccess`
for visitor policy and browser authorization, `internal/publisher/requestlimit`
for per-run budgets, and `internal/publisher/service/http.go` for service frontend
composition. See [package dependencies](architecture.md#how-packages-fit-together)
for those boundaries.

Repeat a race-sensitive case without changing its test tier:

```sh
mise exec -- task go:test:focused PACKAGES=./internal/connector/stream RUN='^TestPreparedConnector' FLAGS='-race -shuffle=on -cpu=1,2,4' COUNT=50
```

`COUNT` defaults to one; use it instead of putting `-count` in `FLAGS`.
Keep real-clock lease and network tests out of high-count repetitions. Prove
their ordering rules with synchronized owner tests, then run the real boundary.

Find integration, race, load, and packaging checks with
`mise exec -- task --list-all`. Integration tests use Docker, Pebble, and kind
as needed; mise installs Pebble and kind. Tasks that need test databases create
and clean up their own. Some CLI integration tests need Linux. The full CI matrix
lives in [the workflows](.github/workflows/).

PostgreSQL-backed suites and the connector suite compile their test executables
before starting disposable services, then discover, shard, and run those same
executables. CLI and connector
suites also build the native client once and pass it with `-tnl-cli-binary`;
individual tests do not rebuild it.

CI downloads and verifies both Go modules before running checks. Only transient
dependency downloads retry; tests do not. Go module caches are shared across
build variants, while compiled caches stay separate for ordinary and race builds.

For warm PostgreSQL latency, run `mise exec -- task go:test:load:postgres`.
It compares a direct database connection with the connector/publisher path using
the same query and retained sessions. The task owns its disposable databases;
it does not use a deployed server. Keep baseline runs unprofiled, then repeat
with `DIAGNOSTICS=metrics`, `cpu`, `contention`, or `trace` to inspect the
publisher. Profiling changes timing, so compare like-for-like runs.
The default `off` mode omits the publisher's metrics owner; use `metrics` for
a recording-enabled comparison. `trace` captures a short Go execution trace,
not SQL text or per-query distributed spans.

Docker Hub images use `docker.io` directly and stay pinned by digest. Docker,
Compose, and the test harness use existing Docker credentials, including credential
helpers. Use `docker login` if you need authenticated pulls locally. GitHub-hosted
runners pulling public images are
[exempt from Docker Hub's pull rate limit](https://docs.github.com/en/actions/reference/limits#docker-hubs-rate-limit-for-github-actions).

## edit generated sources

Edit the source named in a generated file's header, then regenerate:

```sh
mise exec -- task generate
mise exec -- task format
```

OpenAPI sources live in `contracts/`. SQL sources live beside each state package's
`sqlc.yaml`. [Generation tasks](tasks/generate.yml) list the generated paths.
The tunnel protocol in `pkg/protocol/tunnelv1` is handwritten.

Hey API generates the browser and telemetry TypeScript validators. Its supported
Zod resolvers keep closed request objects strict and JSON counters numeric; server
authorization and validation remain authoritative. The generator uses a pinned
TypeScript 6 compiler API without changing the TypeScript 7 application checks.

The HTTP management SDK is generated from the nine approved operations by
`scripts/generate/management-sdk.ts`. Its stock Fetch helpers are built in a
separate referenced TypeScript project: strict mode stays enabled, with only
`exactOptionalPropertyTypes` disabled for generated code because Hey API 0.99
assigns `undefined` to optional helper properties. Handwritten code and public
consumer tests retain all repository checks. Only the stock `client`/`core`
helpers are excluded from authored-code lint rules; generated operations,
validators, and models remain linted, except the stock validator's escaped
regex delimiters. Do not patch the generated runtime.

The control baseline requires a fresh PostgreSQL database and a coordinated
stop/start of all server roles. `tnld migrate` accepts only
`TNLD_DATABASE_DIRECT_URL`; serving roles use pooled `TNLD_DATABASE_URL` and
require the exact schema version and baseline identity. Connector session
rebinding and the post-quantum public URL policy are part of the version 1
baseline, including provider-qualified ingress and relay regions and saved run
preferences. Logical project declarations, deployment-scoped bindings, and
encrypted serving snapshots, captured publisher setup approvals, and scoped
independent deployment manage/connect approvals also require this fresh baseline.
Selected deployment desired state uses `tnl-control-fresh-v1-selected-deployments`;
each apply reconciles only its selected deployment against the project revision.
Use a fresh database, run `tnld migrate`, and start matching server,
publisher, and connector binaries. Databases from previous baselines are rejected.
A publisher restart does not restore its application sockets.

The client telemetry baseline also requires a fresh client state directory. Use
`TNL_STATE_DIR` to select a new directory and sign in again; do not copy an older
`v1.db` or its publisher credentials into it.

tnl-owned formats also start at version 1: project metadata, tunnel snapshots,
inspection JSON, and workload metadata. Regenerate project metadata
with matching native and SDK versions when replacing an earlier build.

`task format-check` checks without editing. `task generate-check` regenerates
files and compares them with `HEAD`, so commit intended generated changes first.
For Markdown edits, format just the files you changed:

```sh
mise exec -- pnpm exec oxfmt --write contributing.md
mise exec -- pnpm exec oxfmt --check contributing.md
```

## build release packages

```sh
mise exec -- task package
```

This builds the four Go release archives, then packages the same native client
binaries for npm and Python. npm metadata is generated from the launcher's target
catalog; Hatchling builds the platform wheels. The checks install the actual
packages and run public API and native CLI smoke tests. SDK tests own browser
boundaries and Node/Bun compatibility rather than repeating them in the packers.

`task release:npm-package` and `task py:build` reuse an existing
`task release:snapshot`. Both accept `OUTPUT` and an optional expected `VERSION`,
so tag releases and local snapshots use the same packaging and checks.

## try the local stack

With Docker running:

```sh
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
mise exec -- task local:tnl -- team current
```

`local:trust` adds development certificates to the macOS login keychain.
The stack keeps its data and login in `.local/`. `local:down` stops it and keeps
that data; `local:reset` removes the data, containers, volumes, and local trust.

## send a pull request

Explain what changes, why, and which checks you ran. Use a title such as
`fix: reconnect after a relay restart`. Keep tests beside the code they check.

Add notices for new runtime dependencies to `NOTICE`. Release archives, native
npm packages, and Python wheels include `LICENSE`, `NOTICE`, and
`THIRD_PARTY_LICENSES.txt`.
