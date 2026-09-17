# `@tnldotdev/tnl`

This package installs the `tnl` client for macOS or Linux on arm64 or x64 and
provides its browser-safe project runtime plus official Next.js and Vite
integrations. It does not include the `tnld` server process.

## Install

```console
pnpm add --save-dev @tnldotdev/tnl@next
```

The package selects an exact-version native optional dependency for the current
platform. It has no install script and does not download executable code from a
third-party host. Node.js 22.18 or newer is required by the launcher,
integrations, and TypeScript configuration loader.

The native CLI enables pseudonymous telemetry by default. Use
`TNL_NO_TELEMETRY=true` or `--no-telemetry` to disable it; see the
[telemetry disclosure](../../README.md#telemetry).

## Configuration

Run `tnl init` to add the package and missing project/framework configuration.
It preserves existing Next.js, Vite, and TypeScript configuration and reports
remaining integration actions. Configure an integration below before starting
a framework-discovered tunnel.

For a project with existing `apps/api` and `apps/web` directories:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  dev: { command: ["pnpm", "dev"] },
  services: {
    api: { directory: "apps/api", publish: { target: 3001 } },
    web: { directory: "apps/web" },
  },
});
```

Each project service inherits the root settings and can override them. Commands
run in the service directory, which must be inside the project root. If the
project has several services, choose one with a command such as `tnl dev web` or
`tnl publish api`. A project with one service selects it automatically.

Service names must start with a lowercase ASCII letter. They may contain
lowercase letters, digits, and hyphens, cannot end with a hyphen, and may be up
to 32 characters long. A project may define up to 32 services.

`defineConfig` also accepts a synchronous or asynchronous factory:

```ts
export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["pnpm", "dev"], startupTimeout: "90s" },
}));
```

`worktree.label` combines a readable name with an eight-character hash. It stays
the same for a worktree and client state directory, but differs across worktrees
and installations. The private value used to create the hash is not exposed.

Factories receive read-only `cwd`, `env`, and `worktree` values. `cwd` is the
directory where the command started. Node runs the configuration file from its
own directory. The loader and `context.env` omit `TNL_*` and `TNLD_*` variables,
but they do not remove other application secrets.

TypeScript configuration runs as trusted project code. It is not sandboxed.
`defineConfig` provides type checking; the native client still validates the
result at runtime. TypeScript uses camel-case fields and is always version 1.
Static YAML and JSON require `version: 1` and snake-case fields; see
[discovery and precedence](../../README.md#project-configuration) and the
[JSON Schema](https://tnl.dev/schema/v1.json).

Choose either `tunnel.host` or `tunnel.subdomain`. Choose either `public: true`
or `allowIP`. A project-service override replaces the other inherited choice.
`dev.port` requires the local service to use that port. `dev.startupTimeout`
defaults to two minutes and must be greater than zero and no more than ten
minutes. `dev.command` is an argument array, not a shell command string.

## Project Runtime

Authenticate to the configured server, then generate metadata from the project
root:

```console
tnl login https://control.tnl.example.com --token
tnl config generate
```

Generation selects the current membership and a ready domain for the project and
each service. It also respects service-specific server and team settings. The
command writes `.tnl/project.json` and `.tnl/project.d.ts`.

Regenerate after changing project services, servers, teams, or domains. The
`tnl dev` command also generates metadata when the project has a configuration
file. Keep `.tnl` ignored by Git.

Add the declaration to the application's existing TypeScript `include` list.
For an app at the project root, include `.tnl/project.d.ts`; for the example's
`apps/web/tsconfig.json`, include `../../.tnl/project.d.ts`:

```json
{
  "include": ["**/*.ts", "**/*.tsx", "../../.tnl/project.d.ts"]
}
```

Keep any other entries required by the framework. The generated declaration
adds the configured service names and their exact hostname and URL types. Without
it, service names use a general string type, so check that a service exists
before reading it.

The integrations expose this browser-safe runtime during development:

```ts
import { tnl } from "@tnldotdev/tnl";

if (tnl) {
  tnl.memberNamespace;
  tnl.services.api.hostname;
  tnl.services.api.url;
  tnl.runningUnderTnlDev;
}
```

The `tnl` value is undefined during builds, previews, and production. During
development, behavior depends on discovery:

| Development context                                 | Runtime and network behavior                                                              |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| No generated metadata or `tnl dev` environment      | `tnl` is undefined; no tunnel configuration                                               |
| Metadata without a matching development socket      | Frozen metadata, `runningUnderTnlDev: false`; no tunnel configuration                     |
| `tnl dev` environment or discovered matching socket | Assigned metadata, `runningUnderTnlDev: true`; configure and register the actual listener |

You can start `tnl dev web` in one terminal and start the framework from the
service directory in another. The integration looks for the development socket
when the framework configuration loads; it does not keep searching afterward.

Project metadata is a snapshot. It does not show whether the route or local
service is healthy. The values are read-only, and malformed metadata causes an
error. `tnl publish` cannot add metadata to an application that is already
running.

## Next.js

```ts
// next.config.ts
import { withTnl } from "@tnldotdev/tnl/next";

export default withTnl({
  reactStrictMode: true,
});
```

`withTnl` accepts every Next.js configuration form: an object, a promise, or a
synchronous or asynchronous function. During `tnl dev`, it:

- Adds the assigned hostname to `allowedDevOrigins`.
- Injects the project runtime.
- Registers the listener after Next.js reports the port it actually used.

The integration preserves existing host and port settings. If no port was
forced, Next.js can retry when its preferred port is occupied. `tnl` waits for
the port Next.js chooses instead of forwarding to another process. A port set by
`tnl dev --port` must match exactly. Host settings remain independent, so the
development server can still be exposed on the LAN.

Next.js 16.3.4 or newer is supported.

## Vite

```ts
// vite.config.ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/tnl/vite";

export default defineConfig({
  plugins: [tnl()],
});
```

During `tnl dev`, the plugin allows the assigned hostname, injects the project
runtime, and registers the listener after Vite chooses its port. Vite keeps its
normal host and port behavior, including retries when a port is occupied. A port
set by `tnl dev --port` must match exactly. Host settings can still expose Vite
on the LAN.

Without a development socket, the plugin only injects generated project
metadata. It does nothing during builds and previews. Vite 6.0.9 or newer is
supported.

Next.js and Vite are optional peers, so only the framework already used by the
project is required. Keep hostname, policy, server, service, and command
settings in project configuration rather than passing integration options.

### Listener Requirements

The listener must accept HTTP on localhost. A wildcard binding (`0.0.0.0` or
`::`) is allowed because it includes localhost. Binding only to a specific LAN
address is not supported. Vite middleware mode does not provide a supported
listener. Next.js must report an HTTP listener URL.

When a port is forced, the integration checks the actual listener instead of
trusting configuration alone. The integration preserves Vite's
`allowedHosts: true` and will not re-enable host filtering.

Deploy `tnld` with the release container or install it from Homebrew or a
release archive.
