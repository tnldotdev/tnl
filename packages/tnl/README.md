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

## Project Runtime

The framework integrations expose generated project metadata through the root
module during development:

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
`tnl dev`, `runningUnderTnlDev` is true and the integration receives complete
project metadata from the private protocol. During an ordinary framework
development server, the integration reads the generated `.tnl/project.json`
file without changing network configuration and sets `runningUnderTnlDev` to
false. If generated metadata is absent, `tnl` is undefined.

The tnl client also generates `.tnl/project.d.ts`. Include that directory in the
application's TypeScript inputs to get exact service keys and literal hostname,
URL, and common member-namespace values. Without the generated declaration,
the root module uses safe broad string and service-record types.

`tnl publish` cannot inject metadata into an application process that is already
running. Metadata generated earlier can still be available to ordinary local
development, with `runningUnderTnlDev` remaining false.

## Configuration

The package exports `defineConfig` and project configuration types:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["pnpm", "dev"] },
}));
```

`tnl.config.ts` is implicitly configuration version 1. Static `tnl.yml`,
`tnl.yaml`, and `tnl.json` files require `version: 1`; the JSON Schema is
available at `https://tnl.dev/schema/v1.json`.

`tnl init` adds this package and automatically edits recognized Next.js, Vite,
and TypeScript configuration shapes. When multiple files or an ambiguous shape
make an edit unsafe, it preserves the files and reports the exact action still
needed.

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
independently expose Vite on the LAN. During ordinary development the plugin
only injects generated metadata. Builds and previews remain inert. Vite 6.0.9
or newer is supported.

Next.js and Vite are optional peers, so only the framework already used by the
project is required. Keep hostname, policy, server, service, and command
settings in project configuration rather than passing integration options.

Deploy `tnld` with the release container or install it from Homebrew or a
release archive.
