# contributing

## get set up

Install [mise](https://mise.jdx.dev), then run these from the repository root:

```sh
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- uv sync --frozen --project packages/py
```

Run repository commands through `mise exec --` to use the versions in `mise.toml`.

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

Find integration, race, load, and packaging checks with
`mise exec -- task --list-all`. Integration tests need Docker and Pebble
(installed by mise); their tasks create and clean up test databases. Some CLI
integration tests need Linux. The full CI matrix lives in
[the workflows](.github/workflows/).

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

## try the experimental wasm connector

Build the connector with the pinned Go JS/WASM runtime and check its host adapters:

```sh
mise exec -- task wasm:build
mise exec -- task wasm:check
```

The experiment lives in `development/connector-wasm`; it does not replace the
TypeScript SDK's native backend. Its local PostgreSQL fixture reuses control, two
relays, a publisher, and a signed workload issuer. With Docker running, qualify
the fixture separately through the native connector:

```sh
mise exec -- task go:test:integration:connector-wasm:native
mise exec -- task go:test:integration:connector-wasm RUNTIME=node
mise exec -- task go:test:integration:connector-wasm RUNTIME=bun
mise exec -- task go:test:integration:connector-wasm RUNTIME=workerd
```

This target owns disposable PostgreSQL and keeps credentials in a private
temporary file outside the checkout. It verifies an open transaction survives an
interrupted relay carrier without changing the database session or replaying a
write. The WASM targets also require an independently exchanged workload to renew
and revoke before the runner exits. The workerd target uses two concurrent
requests to check request-owned sockets. These local checks do not establish
deployed Workers reachability, egress behavior, or resource limits.

For a longer query comparison without Go race instrumentation:

```sh
mise exec -- task go:test:load:connector-wasm RUNTIME=node QUERIES=1000
```

Use `bun` or `workerd` for the other runtimes. The native baseline is an already
prepared Go connector in the same topology, not the SDK's native helper process;
its query timings do not measure helper startup, IPC, CPU, or memory.

To compare the byte bridge changes under the same local topology:

```sh
mise exec -- task go:test:load:connector-wasm-profile
mise exec -- task go:test:load:connector-wasm-profile CPU=true
mise exec -- task wasm:benchmark:crypto
```

The first command runs `baseline`, `buffers`, `promises`, and `optimized` in forward
and reverse order. Each sample uses a fresh Node process, 100 warm-up queries,
and the same native connector baseline. `buffers` reuses Go application buffers
and views the returned, independently owned JS array without another copy;
`promises` reuses Go callback dispatchers and creates Promise resolvers in JS,
avoiding per-operation Go executor callbacks.
`optimized` combines them. All variants still use verified TLS and the same
transaction/fault proof. No variant changes the SDK's backend selection.
To qualify the combined variant on a runtime, pass `VARIANT=optimized` to
`go:test:integration:connector-wasm` alongside `RUNTIME=node`, `bun`, or `workerd`.

`CPU=true` samples only the baseline and combined WASM query intervals, using
a separate module with function names. It saves private `.cpuprofile` files in
the ignored `development/connector-wasm/dist/profiles` directory. Do not compare
those instrumented timings to ordinary runs. The reports include byte/call
counts, Go allocation/GC deltas, negotiated ciphers, and heuristic CPU stack
categories; raw profiles are needed to audit the categories. The crypto target
compares synthetic AEAD operations natively, with Go assembly disabled, and in
WASM. Primitive speed ratios do not measure crypto's share of a query.

To compare persistent byte pumps against the optimized Promise bridge:

```sh
mise exec -- task go:test:load:connector-wasm-profile STREAMING=true
mise exec -- task go:test:load:connector-wasm-profile STREAMING=true CPU=true
mise exec -- task go:test:load:connector-wasm-profile STREAMING=true QUERIES=100 PAYLOAD_BYTES=16384
mise exec -- task go:test:integration:connector-wasm VARIANT=streaming RUNTIME=workerd
```

The streaming comparison runs `optimized`, `application-pump`, `socket-pump`,
and `streaming` in forward and reverse order. The middle cases enable one
boundary at a time; `streaming` enables both. Pumps use bounded queues, read
credits, and persistent callbacks. Write completion still means the underlying
write finished. TLS, authorization, and relay recovery stay with Go.
`PAYLOAD_BYTES` adds a checked response string to each measured SQL query;
the same query and warm-up count run through WASM and the native baseline.
Use `VARIANTS=optimized,streaming` for a smaller forward/reverse comparison.
With `STREAMING=true CPU=true`, profiling samples only `optimized` and `streaming`.

## edit generated sources

Edit the source named in a generated file's header, then regenerate:

```sh
mise exec -- task generate
mise exec -- task format
```

OpenAPI sources live in `api/`. SQL sources live beside each state package's
`sqlc.yaml`. [Generation tasks](tasks/generate.yml) list the generated paths.
The tunnel protocol in `pkg/protocol/tunnelv1` is handwritten.

The control baseline requires a fresh PostgreSQL database and a coordinated
stop/start of all server roles. `tnld migrate` accepts only
`TNLD_DATABASE_DIRECT_URL`; serving roles use pooled `TNLD_DATABASE_URL` and
require the exact schema version and baseline identity. The baseline without
public URL usage accounting cannot open a database created by the previous
baseline.

`task format-check` checks without editing. `task generate-check` regenerates
files and compares them with `HEAD`, so commit intended generated changes first.
For Markdown edits, format just the files you changed:

```sh
mise exec -- pnpm exec oxfmt --write contributing.md
mise exec -- pnpm exec oxfmt --check contributing.md
```

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
