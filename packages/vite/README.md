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

Pass static options or a synchronous or asynchronous factory to select route
settings from runtime context. Reserve a managed base once with `tnl host add
myapp`, then give every Git worktree its own child name:

```ts
// vite.config.ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/vite";

export default defineConfig({
  plugins: [
    tnl(({ worktree }) => ({
      name: `${worktree.label}.myapp`,
      allowCurrentIP: true,
    })),
  ],
});
```

The factory runs only for a Vite development server beneath `tnl dev`, not for
ordinary development, builds, or previews. It receives a frozen environment
snapshot, the process working directory, and worktree metadata. Vite retains
its normal behavior of trying the next port when its preferred port is occupied;
the plugin reports the final listening port to `tnl`.

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

## Tunnel Options

`tnl` accepts these project options:

```ts
tnl({
  server: "https://tnl.example.com",
  name: "feature.chase.example.com",
  allowIP: ["198.51.100.0/24", "2001:db8::/64"],
  allowCurrentIP: true,
});
```

`allowCurrentIP` is additive with `allowIP`. When `allowIP` is omitted,
`allowCurrentIP: true` restricts access to the current public IP only. The Go
client performs server authentication, hostname authorization, and IP
canonicalization. CLI `--server`/`TNL_SERVER` and `--name`/`TNL_NAME` take
precedence over project options.

The signed-in user must own the configured custom domain or an eligible parent
hostname. Separate users cannot currently share one parent hostname.

## Configuration

Keep Vite settings in `vite.config.ts`. Vite uses `server.port`. The `--port`
flag on `tnl dev` overrides it and enables strict port handling. Existing
`server.allowedHosts` entries and other settings remain in place. During
`tnl dev`, the server is bound to loopback and its actual listening port is
registered after startup. Outside `tnl dev`, the plugin makes no changes.

## Requirements

Vite 6 or newer and Node.js 22.15 or newer are required.
