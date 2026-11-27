# contributing

Use [architecture](architecture.md) to find the code and [AGENTS.md](AGENTS.md)
for repository rules.

## get set up

Install [mise](https://mise.jdx.dev), then run from the repository root:

```sh
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- uv sync --frozen --project packages/py
```

Run repository commands through `mise exec --` to use the pinned tools.

## check your change

Run the checks for the code you changed:

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

For a race-sensitive test, add `FLAGS='-race -shuffle=on' COUNT=10`.
Keep tests beside the code they check.

Inspect server configuration without starting it:

```sh
mise exec -- go run ./cmd/tnld config show --config path/to/tnl.yml
```

The JSON shows resolved values and their source, with credentials redacted.
Explicit settings for another server role are rejected. Split ingress reads its
port inventory from control; it does not need a second copy of those ranges.

Find other checks with `mise exec -- task --list-all`. Integration tasks create
and clean up their own services; they need Docker. Some CLI suites require Linux.
`go:test:integration:deployment-database` also needs `psql` 16 or newer on `PATH`.
Browser tests need Chrome. Hosted Worker tests also need a Wrangler login:
`mise exec -- wrangler login --device --browser=false`.
`task js:keepalive:test:browser` checks Keepalive's built page in Chrome with
protocol fixtures; it does not need a deployed server.
`task js:keepalive:coordination` runs an opt-in virtual-time gossip simulation;
`task js:keepalive:coordination:check` checks its complete and memory-bounded reports.
`task js:keepalive:load:check` checks the reader load generator on loopback.
See [Keepalive checks](demos/keepalive/tests/readme.md) for workload settings and
the separate live-ramp safety requirements.

For example, to check PostgreSQL migrations:

```sh
mise exec -- task go:test:integration:state:shard RUN='^TestIntegration.*Migration'
```

## edit generated sources

Edit the source, then regenerate and format:

```sh
mise exec -- task generate
mise exec -- task format
```

```text
contracts/                 -> HTTP APIs and validators
state migrations + queries -> SQL access code
internal/config            -> configuration schema and SDK types
```

Generated file headers name their source. [Generation tasks](tasks/generate.yml)
list the full pipeline. `pkg/protocol/tunnelv1` is handwritten.
Go embeds `internal/client/project/loader.ts` directly, so edits to the loader
do not need generation.

Add numbered SQL migrations and test supported upgrades with existing data.
Rewriting an initial migration and its pinned hash requires an explicitly
approved schema reset under [AGENTS.md](AGENTS.md#stability).

`task format-check` is read-only. `task generate-check` regenerates and compares
with `HEAD`; commit intended generated changes first.

For Markdown-only changes, format just the edited files:

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
State lives in `.local/`. `local:down` stops the stack and keeps its data;
`local:reset` removes the data, containers, volumes, and local trust.

## build packages

```sh
mise exec -- task package
```

This builds and checks native archives, npm packages, and Python wheels.
The npm step lints the packed launcher with `publint`, then installs the tarballs
with npm and pnpm to check the CLI and SDK.
All include `LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`. Add dependency
licenses only to `THIRD_PARTY_LICENSES.txt`.

For publishing, use the [release skill](.opencode/skills/release/SKILL.md).

## send a pull request

Open a PR for each change. Use semantic commit messages and a title such as
`fix: reconnect after a relay restart`. Explain what changes, why, and which
checks passed.
