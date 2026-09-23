# `@tnldotdev/tnl`

This package installs the native `tnl` client and provides project configuration
types, a browser-safe project runtime, and official Next.js and Vite
integrations. It does not include the `tnld` server process.

## install

```console
pnpm add --save-dev @tnldotdev/tnl@next
```

The package selects an exact-version native dependency for macOS or Linux on
arm64 or x64. It does not run an install script or download executable code from
another host. Node.js 22.18 or newer is required.

The native client enables pseudonymous telemetry by default. Disable it with
`TNL_NO_TELEMETRY=true` or `--no-telemetry`; see the
[telemetry disclosure](../../docs/cli-reference.md#telemetry).

## initialize a project

Run the initializer from your project root:

```console
pnpm exec tnl init
```

The initializer detects supported package managers and frameworks. It creates
missing tnl and framework configuration, preserves existing configuration, and
lists any changes you need to make yourself.

Once you've completed those steps, start your app:

```console
pnpm exec tnl dev
```

tnl starts the configured command and prints its HTTPS URL. Sign in when
prompted; tnl uses the hosted service by default. The integration follows the
port your app actually uses, even if another app has taken its preferred port.
Live reload works through the URL.

Each Git worktree gets its own URL by default. Restarting the same worktree
with the same local tnl state reuses the URL. See the integration examples for
[Next.js](#integrate-nextjs) and [Vite](#integrate-vite).

Keep service names, commands, targets, route policy, and team selection in
[project configuration](../../docs/project-configuration.md). Framework
integrations do not accept separate route options.

## generate project metadata

Sign in, then generate project metadata:

```console
tnl login
tnl config generate
```

The command writes:

```text
.tnl/project.json   browser-safe project and service addresses
.tnl/project.d.ts   exact TypeScript service and hostname types
```

Add `.tnl/` to `.gitignore`. Regenerate after changing services, servers, teams,
or domains. `tnl dev` also regenerates metadata when the project has a
configuration file.

Include the declaration in the application's existing TypeScript inputs. For a
service in `apps/web`, for example:

```json
{
  "include": ["**/*.ts", "**/*.tsx", "../../.tnl/project.d.ts"]
}
```

Keep every other entry required by the framework.

## read project metadata

Framework integrations expose the generated, browser-safe metadata through the
root package export:

```ts
import { tnl } from "@tnldotdev/tnl";

if (tnl) {
  tnl.memberNamespace;
  tnl.services.api.hostname;
  tnl.services.api.url;
  tnl.runningUnderTnlDev;
}
```

The value describes assigned addresses. It does not prove that a route or local
service is currently healthy.

| Development context                            | Result                                                   |
| ---------------------------------------------- | -------------------------------------------------------- |
| No metadata and no `tnl dev` environment       | `tnl` is undefined.                                      |
| Metadata without a matching development socket | Metadata is available and `runningUnderTnlDev` is false. |
| A matching `tnl dev` environment or socket     | Metadata is available and `runningUnderTnlDev` is true.  |
| Build, preview, or production                  | `tnl` is undefined.                                      |

The values are read-only. Malformed metadata causes an error. No control access
token or saved login is included.

## integrate next.js

Next.js 16.3.4 or newer is supported.

```ts
// next.config.ts
import { withTnl } from "@tnldotdev/tnl/next";

export default withTnl({
  reactStrictMode: true,
});
```

`withTnl` accepts a configuration object, promise, or synchronous or asynchronous
configuration function. During `tnl dev`, it:

- adds the assigned hostname to `allowedDevOrigins`;
- injects project metadata;
- reports the actual listener after Next.js binds.

The integration preserves existing host and port settings. Without
`tnl dev --port`, Next.js can choose another port when its preferred port is
occupied. With `--port`, the reported port must match exactly.

## integrate vite

Vite 6.0.9 or newer is supported.

```ts
// vite.config.ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/tnl/vite";

export default defineConfig({
  plugins: [tnl()],
});
```

During `tnl dev`, the plugin:

- adds the assigned hostname to Vite's allowed hosts;
- injects project metadata;
- reports the actual listener after Vite binds.

Vite keeps its normal host and port behavior, including next-port fallback. A
port set by `tnl dev --port` must match exactly. Middleware mode is not
supported because it does not provide a listener to register.

## run the framework separately

The framework does not have to be a child of `tnl dev`. You can start
`tnl dev web` in one terminal and start the framework from the service directory
in another.

The integration looks for the matching private development socket when the
framework configuration loads. It does not keep searching afterward. Start
`tnl dev` first when you use this workflow.

## listener requirements

The listener must accept HTTP on localhost. A wildcard binding such as
`0.0.0.0` or `::` is allowed because it includes localhost. Binding only to a
specific LAN address is not supported.

Host settings remain independent. Your framework can still listen on the LAN,
but tnl does not require or enable that exposure.
