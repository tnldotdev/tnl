# connect from github actions

run migrations or deploy commands against your services from GitHub Actions.
`tnldotdev/tnl/connect` opens the connections once and keeps them available to
later steps in the same job.

## run a migration

this example uses a pnpm project with a PostgreSQL service named `database` and a
GitHub workload named `deploy`. before running it:

- declare `services.database` in this project's configuration, assign it to a
  named publisher group, and have a publisher in that group serving it.
- declare `workloads.deploy` with `provider: github`, `services: [database]`, and
  GitHub rules matching `.github/workflows/deploy.yml`, `refs/heads/main`, and the
  `push` event. save that policy with `pnpm exec tnl apply` from your signed-in
  checkout. for a private repository, the first apply also needs `gh` authenticated
  with read access to that repository. the action uses the saved policy.
- pin pnpm 11 or newer in `package.json`, for example
  `"packageManager": "pnpm@11.28.7"`, with a matching committed `pnpm-lock.yaml`.
- use an existing PostgreSQL Drizzle migration setup with `@tnldotdev/tnl`,
  `drizzle-kit`, `drizzle-orm`, and `pg` in the committed manifest and lockfile.
  keep the native platform optional dependency enabled.
- add `DB_USER`, `DB_PASSWORD`, and `DB_NAME` as repository secrets. tnl grants
  access to the service; PostgreSQL still checks the database account.

save this as `.github/workflows/deploy.yml`:

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
workload policy. use a Linux GitHub-hosted runner on x64 or arm64.

in your existing Drizzle configuration, read the prepared connection settings:

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

run `pnpm exec tnl generate` locally for service-specific TypeScript declarations.
keep your existing migration directory and schema settings in the Drizzle config.

## inputs

| input               | purpose                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `workload`          | required key under `workloads`, with `provider: github`                                         |
| `working-directory` | project directory relative to the workspace; default `.`                                        |
| `services`          | optional newline-separated service keys; narrows the workload's service list                    |
| `timeout`           | seconds allowed for each of OIDC acquisition and native startup; default `90`, range `1`-`300`  |
| `version`           | exact npm version to install instead of using the project package; no `v` prefix or ranges      |
| `cli-path`          | native executable path, absolute or relative to `working-directory`; for locally built binaries |

choose at most one of `version` and `cli-path`. by default, the action uses the
installed `@tnldotdev/tnl` package in the selected project and checks its native
binary's version and digest. install dependencies before this step. `timeout`
does not extend the workload's fixed deadline.

## later steps and cleanup

the action exports these environment variables to later steps:

| variable                | use                                                       |
| ----------------------- | --------------------------------------------------------- |
| `TNL_CONNECTION_HANDLE` | private connection handle read by `tnl.connect(...)`      |
| `TNL_PROJECT_RUNTIME`   | service metadata used by `tnl.services`                   |
| `KUBECONFIG`            | session kubeconfig, when the workload includes Kubernetes |

connections belong to this job. its steps run as the same user and can read the
private handle. the action's post step stops its connector process and removes
its temporary directory after cleanup succeeds. it uses a saved copy of the
binary, so later installs or checkout changes do not break cleanup. a cleanup
failure is reported and retains the temporary files.

## work on the action

edit [src/](src/); [scripts/build.ts](scripts/build.ts) generates the committed
`dist/` bundles. from the repository root:

```sh
mise exec -- task connect:check
mise exec -- task connect:generate-check
mise exec -- actionlint connect/test/workflow.yml
mise exec -- zizmor connect
```

[test/workflow.yml](test/workflow.yml) is an offline runner fixture for setup,
later-step access, and post cleanup.
