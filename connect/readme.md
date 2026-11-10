# connect from github actions

Run migrations or deploy commands against your services from GitHub Actions.
`tnldotdev/tnl/connect` opens the connections once and keeps them available to
later steps in the same job.

## run a migration

This example uses a pnpm project with a PostgreSQL service named `database` and a
GitHub workload named `deploy`. Before running it:

- Declare `services.database` in this project's configuration, assign it to a
  named publisher group, and have a publisher in that group serving it.
- Declare `workloads.deploy` with `github: { workflow: ".github/workflows/deploy.yml" }`, `grants: { visit: [{ service: "database" }] }`, and
  GitHub rules matching `.github/workflows/deploy.yml`, `refs/heads/main`, and the
  `push` event. Save that policy with `pnpm exec tnl apply` from your signed-in
  checkout. For a private repository, the first apply also needs `gh` authenticated
  with read access to that repository. The action uses the saved policy.
- Pin pnpm 11 or newer in `package.json`, for example
  `"packageManager": "pnpm@11.28.7"`, with a matching committed `pnpm-lock.yaml`.
- Use an existing PostgreSQL Drizzle migration setup with `@tnldotdev/tnl`,
  `drizzle-kit`, `drizzle-orm`, and `pg` in the committed manifest and lockfile.
  Keep the native platform optional dependency enabled.
- Add `DB_USER`, `DB_PASSWORD`, and `DB_NAME` as repository secrets. tnl grants
  access to the service; PostgreSQL still checks the database account.

Save this as `.github/workflows/deploy.yml`:

```yaml
name: migrate
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  migrate:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: pnpm/setup@fbda4c85fc2e1e08721cd8763afea8f48d60f024 # v3.0.0
        with:
          runtime: node@22.23.2
          require-lockfile: true
      - run: pnpm install --frozen-lockfile
      - uses: tnldotdev/tnl/connect@7b95306b02aadc34f77c7db3ac116c4030adf8c6
        with:
          workload: deploy
          services: database
      - run: pnpm exec drizzle-kit migrate
        env:
          DB_USER: ${{ secrets.DB_USER }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          DB_NAME: ${{ secrets.DB_NAME }}
```

`contents: read` lets checkout read the repository. `id-token: write` lets the
action request a GitHub OIDC assertion, which control checks against the saved
workload policy. Use a Linux GitHub-hosted runner on x64 or arm64.

In your existing Drizzle configuration, read the prepared connection settings:

```ts
import { tnl } from "@tnldotdev/tnl";
import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  dbCredentials: {
    ...tnl.connect("database"),
    user: process.env.DB_USER!,
    password: process.env.DB_PASSWORD!,
    database: process.env.DB_NAME!,
  },
});
```

Run `pnpm exec tnl generate` locally for service-specific TypeScript declarations.
Keep your existing migration directory and schema settings in the Drizzle config.

## inputs

| Input               | Purpose                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `workload`          | Required key under `workloads`, with a `github` provider block                                  |
| `working-directory` | Project directory relative to the workspace; default `.`                                        |
| `services`          | Optional newline-separated service keys; narrows the workload's service list                    |
| `timeout`           | Seconds allowed for each of OIDC acquisition and native startup; default `90`, range `1`-`300`  |
| `version`           | Exact npm version to install instead of using the project package; no `v` prefix or ranges      |
| `cli-path`          | Native executable path, absolute or relative to `working-directory`; for locally built binaries |

Choose at most one of `version` and `cli-path`. By default, the action uses the
installed `@tnldotdev/tnl` package in the selected project and checks its native
binary's version and digest. Install dependencies before this step. `timeout`
does not extend the workload's fixed deadline.

## later steps and cleanup

The action exports these environment variables to later steps:

| Variable                | Use                                                       |
| ----------------------- | --------------------------------------------------------- |
| `TNL_CONNECTION_HANDLE` | Private connection handle read by `tnl.connect(...)`      |
| `TNL_PROJECT_RUNTIME`   | Service metadata used by `tnl.services`                   |
| `KUBECONFIG`            | Session kubeconfig, when the workload includes Kubernetes |

Connections belong to this job. Its steps run as the same user and can read the
private handle. The action's post step stops its connector process and removes
its temporary directory after cleanup succeeds. It uses a saved copy of the
binary, so later installs or checkout changes do not break cleanup. A cleanup
failure is reported and retains the temporary files.

Before a GitHub proof expires, the native connector process requests a fresh
proof from this job's runtime API and attaches it to the same workload session.
Later steps do not need to request another proof or reopen their connections.
Each proof must still match the saved policy and the original GitHub job.

Refresh does not extend the workload's fixed deadline or remove permission-lease
limits. If GitHub cannot supply an accepted proof before the current proof or
lease expires, the connections stop at that accepted expiry. Another job's proof
cannot replace the session. The connector keeps its copy of the runtime credential
only in memory, not in the handle, action state, or exported environment.

## work on the action

Edit [src/](src/); [scripts/build.ts](scripts/build.ts) generates the committed
`dist/` bundles. From the repository root:

```sh
mise exec -- task connect:check
mise exec -- task go:test:integration:action-background-refresh
mise exec -- task connect:generate-check
mise exec -- actionlint connect/test/workflow.yml
mise exec -- zizmor connect
```

[test/workflow.yml](test/workflow.yml) is an offline runner fixture for setup,
later-step access, and post cleanup.
