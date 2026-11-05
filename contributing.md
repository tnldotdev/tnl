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

## edit generated sources

Edit the source named in a generated file's header, then regenerate:

```sh
mise exec -- task generate
mise exec -- task format
```

OpenAPI sources live in `api/`. SQL sources live beside each state package's
`sqlc.yaml`. [Generation tasks](tasks/generate.yml) list the generated paths.
The tunnel protocol in `pkg/protocol/tunnelv1` is handwritten.

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
