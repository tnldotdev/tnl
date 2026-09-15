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

Each service overrides root defaults. Commands run in the service directory,
which must exist within the project root. Choose explicitly when several
services exist: `tnl dev web` or `tnl publish api`. A single service is selected
automatically. Service names are 1-32 lowercase ASCII letters/digits/hyphens,
begin with a letter, and cannot end with a hyphen; at most 32 services are allowed.

`defineConfig` also accepts a synchronous or asynchronous factory:

```ts
export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["pnpm", "dev"], startupTimeout: "90s" },
}));
```

`worktree.label` combines a readable name with an eight-character hash, stable
for one client state directory but distinct across worktrees and installations.
Its private random input is not exposed. Factories receive deeply frozen
`cwd`, `env`, and `worktree` context. `cwd` is the invocation directory; Node
executes from the configuration directory. Both the loader environment and
`context.env` omit `TNL_*` and `TNLD_*`, not arbitrary application secrets.

Configuration executes trusted project code, not a sandbox. `defineConfig` is
type assistance, not runtime validation; the native client validates the result.
TypeScript uses camel-case fields and implicitly version 1. Static YAML/JSON
requires `version: 1` and snake-case fields; see
[discovery and precedence](../../README.md#project-configuration) and the
[JSON Schema](https://tnl.dev/schema/v1.json).

`tunnel.host` and `tunnel.subdomain` are alternatives, as are `public: true` and
`allowIP`. Service overrides replace the corresponding inherited alternative.
`dev.port` forces the exact listener port. `dev.startupTimeout` defaults to two
minutes and must be positive and at most ten minutes. `dev.command` is an
argument array, not a shell command string.

## Project Runtime

Authenticate to the configured server, then generate metadata from the project
root:

```console
tnl login https://control.tnl.example.com --token
tnl config generate
```

Generation resolves the authenticated membership and ready domain for the root
and every service, including services with server/team overrides. It writes
`.tnl/project.json` and `.tnl/project.d.ts`. Regenerate after changing service,
server, team, or domain configuration; `tnl dev` also generates metadata when
project configuration is present. Keep `.tnl` ignored by Git.

Add the declaration to the application's existing TypeScript `include` list.
For an app at the project root, include `.tnl/project.d.ts`; for the example's
`apps/web/tsconfig.json`, include `../../.tnl/project.d.ts`:

```json
{
  "include": ["**/*.ts", "**/*.tsx", "../../.tnl/project.d.ts"]
}
```

Preserve other framework-required includes. The augmentation gives exact
service keys and literal hostname/URL types. Without it, types remain broad;
check that a service exists before accessing it.

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

| Development context                                        | Runtime and network behavior                                                              |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| No generated metadata or explicit bootstrap                | `tnl` is undefined; no tunnel configuration                                               |
| Metadata without a matching development socket             | Frozen metadata, `runningUnderTnlDev: false`; no tunnel configuration                     |
| Explicit bootstrap or discovered matching `tnl dev` socket | Assigned metadata, `runningUnderTnlDev: true`; configure and register the actual listener |

Socket discovery supports starting `tnl dev web` first and the framework from
its service directory in another terminal. Discovery happens when framework
configuration loads, not continuously. Metadata is a snapshot, not route
readiness or service health. Values are deeply frozen; malformed metadata throws
rather than silently becoming undefined. `tnl publish` cannot inject metadata
into an already-running application.

## Next.js

```ts
// next.config.ts
import { withTnl } from "@tnldotdev/tnl/next";

export default withTnl({
  reactStrictMode: true,
});
```

`withTnl` preserves object, promised, synchronous-function, and
asynchronous-function configuration. During `tnl dev`, it adds the assigned
hostname to `allowedDevOrigins`, injects the project runtime, and registers the
actual listener target reported by Next.js after it binds. Existing host and
port choices, including Next.js defaults and custom values, are preserved. An
unforced port may use Next.js's normal occupied-port retry behavior without
tunneling a different process on the preferred port. A port forced by
`tnl dev --port` remains exact. Host settings remain independent, so a project
can intentionally expose its development server on the LAN as well as through
tnl.

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
runtime, and registers Vite's actual post-bind target. It preserves Vite's
default or configured host and port behavior, including occupied-port retries;
a port forced by `tnl dev --port` remains exact. User host settings can
independently expose Vite on the LAN. Without a development socket the plugin
only injects generated metadata. Builds and previews remain inert. Vite 6.0.9
or newer is supported.

Next.js and Vite are optional peers, so only the framework already used by the
project is required. Keep hostname, policy, server, service, and command
settings in project configuration rather than passing integration options.

### Listener Requirements

The target must be loopback HTTP. Wildcard bindings (`0.0.0.0` or `::`) allow
LAN exposure while tnl connects through loopback; binding only a specific LAN
address is rejected. Vite middleware mode has no supported listening target.
Next.js must report an HTTP listener origin. Forced ports are checked against
the actual listener, not assumed from configuration. Vite's `allowedHosts: true`
is preserved; the integration does not re-enable host filtering you disabled.

Deploy `tnld` with the release container or install it from Homebrew or a
release archive.
