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

Find other checks with `mise exec -- task --list-all`. Integration tasks create
and clean up their own services; they need Docker. Some CLI suites require Linux.
Browser tests need Chrome. Hosted Worker tests also need a Wrangler login:
`mise exec -- wrangler login --device --browser=false`.

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

Add new numbered SQL migrations. Existing migrations are frozen, including
migration 1 in both state packages. Test upgrades with existing data.

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
All include `LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`. Add dependency
licenses only to `THIRD_PARTY_LICENSES.txt`.

For publishing, use the [release skill](.opencode/skills/release/SKILL.md).

## send a pull request

Open a PR for each change. Use semantic commit messages and a title such as
`fix: reconnect after a relay restart`. Explain what changes, why, and which
checks passed. Follow the compatibility starting point in [AGENTS.md](AGENTS.md);
preserve behavior from that point forward. Deprecate an API with its release
version and replacement while keeping it working.
