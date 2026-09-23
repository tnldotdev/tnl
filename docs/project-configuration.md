# project configuration

Project configuration keeps service names, local commands, targets, and route
settings beside your application. Use it when you want repeatable `tnl dev` or
`tnl publish` commands across a project and its Git worktrees.

Run `tnl init` to create the initial setup. You can then use TypeScript, YAML, or
JSON.

## configure a typescript project

TypeScript configuration uses camel-case field names. It is a good default for
JavaScript and TypeScript projects because it provides editor types and can use
the current worktree when needed.

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  team: "Example Team",
  tunnel: {
    allowIP: ["198.51.100.0/24"],
  },
  services: {
    web: {
      directory: "apps/web",
      dev: { command: ["pnpm", "dev"] },
    },
    api: {
      directory: "apps/api",
      publish: { target: 3001 },
    },
  },
});
```

Root settings apply to every service. A service can replace individual root
settings. Commands run from the service directory, which must stay inside the
project root.

When a value must depend on the current checkout, use a configuration factory:

```ts
export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["pnpm", "dev"], startupTimeout: "90s" },
}));
```

`worktree.label` is stable for one worktree and client state directory. It is
different for other worktrees and installations.

TypeScript configuration runs as trusted local code. It is not sandboxed. The
factory receives read-only `cwd`, `env`, and `worktree` values. `env` omits
`TNL_*` and `TNLD_*` variables, but it can still contain other application
secrets.

## configure yaml or json

Static configuration uses snake-case fields and requires `version: 1`:

```yaml
$schema: https://tnl.dev/schema/v1.json
version: 1
tnl:
  team: Example Team
  tunnel:
    allow_ip: [198.51.100.0/24]
  services:
    web:
      directory: apps/web
      dev:
        command: [pnpm, dev]
        startup_timeout: 90s
    api:
      directory: apps/api
      publish:
        target: 3001
```

JSON uses the same versioned document and snake-case field names. The
[JSON Schema](https://tnl.dev/schema/v1.json) describes both static formats.

## name services

A project service is one named local service, such as `web` or `api`. The name
appears in commands, status output, generated metadata, and default hostnames.

Service names:

- start with a lowercase ASCII letter;
- contain only lowercase letters, digits, and hyphens;
- do not end with a hyphen;
- contain at most 32 characters.

A project can define up to 32 services. With one service, tnl selects it
automatically. With several services, name the one you want:

```console
tnl dev web
tnl publish api
```

## worktree urls

By default, each Git worktree and named service gets its own HTTPS URL. tnl
derives the name from the worktree's directory, its location on disk, and saved
client state. The app's port and the branch checked out in that worktree do not
affect the name.

Restarting the same worktree with the same client state reuses its URL. Moving
the worktree, clearing client state, or using a different machine can change it.
Changing the selected account, team, domain, or service can also change the URL.
Explicit `host` or `subdomain` settings override automatic naming.

A stable URL does not keep the app running. Keep tnl and the app running while
you use it. The Next.js and Vite integrations follow each app's actual port,
so separate worktrees can use different ports without changing their URLs.

## understand the sections

| Section    | Purpose                                                     |
| ---------- | ----------------------------------------------------------- |
| `server`   | Select the control URL for this project or service.         |
| `team`     | Select a team by ID or unambiguous display name.            |
| `tunnel`   | Configure hostname, IP policy, lifetime, and request limit. |
| `publish`  | Configure the target used by `tnl publish`.                 |
| `dev`      | Configure the child command, port, and startup timeout.     |
| `services` | Define named local services and their overrides.            |

Common tunnel fields are:

| TypeScript     | YAML / JSON     | Meaning                                   |
| -------------- | --------------- | ----------------------------------------- |
| `host`         | `host`          | Complete authorized hostname.             |
| `subdomain`    | `subdomain`     | One label beneath the member namespace.   |
| `allowIP`      | `allow_ip`      | Additional visitor addresses or prefixes. |
| `allowAllIPs`  | `allow_all_ips` | Accept visitors from every address.       |
| `ephemeral`    | `ephemeral`     | Delete the route when the tunnel stops.   |
| `requestLimit` | `request_limit` | Maximum concurrent publisher requests.    |

Choose either `host` or `subdomain`. Choose either `allowAllIPs` or `allowIP`.
An override of one choice clears the inherited alternative.

`publish.target` accepts a port, `localhost:<port>`, or a loopback HTTP origin.
`dev.command` is an argument array, not a shell command string. `dev.port`
requires the application to use that exact port. `dev.startupTimeout` defaults
to two minutes and accepts values up to ten minutes.

## find the configuration

tnl looks upward from the current directory for the nearest recognized file:

```text
tnl.config.ts
tnl.yml
tnl.yaml
tnl.json
```

Discovery stops at the Git worktree root. Outside Git, tnl checks only the
current directory. More than one recognized file in the same directory is an
error.

Select a file explicitly or disable discovery for one command:

```console
tnl dev --config config/tnl.preview.yml
tnl publish 3000 --no-config
```

`TNL_CONFIG` also selects an explicit file. An explicitly selected TypeScript
file must be named `tnl.config.ts`.

## understand precedence

The most explicit value wins:

```text
command-line option
        |
        v
supported TNL_* environment variable
        |
        v
project service setting
        |
        v
project root setting
        |
        v
saved selection or built-in default
```

Hostname and IP policy are each resolved as one choice. For example,
`--subdomain` clears a lower-priority configured `host`, and `--allow-ip` clears
a lower-priority `allow_all_ips` value.

An explicit access token must have an explicit destination. When you provide
`--access-token` or `TNL_ACCESS_TOKEN`, also provide `--server` or `TNL_SERVER`.
tnl will not send an explicit token to a control URL found only in project
configuration.

## check the result

Inspect and validate configuration before starting a tunnel:

```console
tnl config path
tnl config check
```

`config path` shows the selected file without evaluating it. `config check`
loads the file, evaluates TypeScript when selected, validates all services, and
resolves service directories. It does not contact a tnl server.

Run `tnl config generate` when framework code needs project metadata. The
[JavaScript package guide](../packages/tnl/readme.md) explains the generated
files and runtime API.
