# `@tnldotdev/vite`

This package connects a Vite development server to `tnl dev`.

## Install

```console
pnpm add --save-dev @tnldotdev/tnl@next @tnldotdev/vite@next
```

## Configure

```ts
// vite.config.ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/vite";

export default defineConfig({
  plugins: [tnl()],
});
```

Put route and development-command settings in a project `tnl.ts` instead of the
Vite plugin:

```ts
// tnl.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["vite"] },
}));
```

Vite retains its normal behavior of trying the next port when its preferred port
is occupied; the plugin reports the final listening port to `tnl`.

## Run

Add a project script so the project-local `tnl` client is on `PATH`:

```json
{
  "scripts": {
    "dev:public": "tnl dev -- pnpm dev"
  }
}
```

```console
pnpm dev:public
```

Ordinary `pnpm dev` remains local.

## Public Environment

During `tnl dev`, app code receives `VITE_TNL_URL`, `VITE_TNL_HOSTNAME`, and
`VITE_TNL_TUNNEL_ID` through `import.meta.env`. The plugin does not define them
during ordinary local development, builds, or previews.

For typed values, add `/// <reference types="@tnldotdev/vite/env" />` to
`vite-env.d.ts`.

## Configuration

`tnl()` accepts no arguments. Keep Vite settings in `vite.config.ts` and tunnel
settings in project tnl configuration. Vite uses `server.port`; the `--port`
flag on `tnl dev` overrides it and enables strict port handling. Existing
`server.allowedHosts` entries and other settings remain in place. During `tnl
dev`, the server is bound to loopback and its actual listening port is reported
after startup. Outside `tnl dev`, the plugin makes no changes.

## Requirements

Vite 6.0.9 or newer and Node.js 22.18 or newer are required.
