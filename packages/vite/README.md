# `@tnldotdev/vite`

This package connects a Vite development server to `tnl dev`.

## Install

```console
pnpm add --save-dev @tnldotdev/vite
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

## Run

```console
tnl dev -- pnpm dev
```

Ordinary `pnpm dev` remains local.

## Custom Hostname

Set a hostname for your local shell:

```console
export TNL_NAME=chase.example.com
tnl dev -- pnpm dev
```

Or pass it directly:

```console
tnl dev --name chase.example.com -- pnpm dev
```

The signed-in user must own the custom domain or an eligible parent claim.
Separate users cannot currently share one parent claim.

## Configuration

Keep Vite settings in `vite.config.ts`. Vite uses `server.port`. The `--port`
flag on `tnl dev` overrides it. Existing `server.allowedHosts` entries and other
settings remain in place. During `tnl dev`, the server is bound to loopback and
strict port handling is enabled. Outside `tnl dev`, the plugin makes no changes.

## Requirements

Vite 6 or newer and Node.js 20.9 or newer are required.
