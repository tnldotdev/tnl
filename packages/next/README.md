# `@tnldotdev/next`

This package connects a Next.js development server to `tnl dev`.

## Install

```console
pnpm add --save-dev @tnldotdev/tnl@next @tnldotdev/next@next
```

## Configure

```ts
// next.config.ts
import { withTnl } from "@tnldotdev/next";

export default withTnl({
  reactStrictMode: true,
});
```

`withTnl` also accepts promised configuration and synchronous or asynchronous
Next.js configuration functions. Put route and development-command settings in
a project `tnl.ts`:

```ts
// tnl.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["next", "dev"] },
}));
```

Next.js retains its normal behavior of trying the next port when its default is
occupied; the integration reports the resolved listening port to `tnl`.

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

During `tnl dev`, app code receives `NEXT_PUBLIC_TNL_URL`,
`NEXT_PUBLIC_TNL_HOSTNAME`, and `NEXT_PUBLIC_TNL_TUNNEL_ID`. The adapter does
not define them during ordinary local development or production builds.

For typed values, add `/// <reference types="@tnldotdev/next/env" />` to a
project declaration file.

## Configuration

`withTnl` accepts only the Next.js configuration value. Your existing settings
are preserved. During `tnl dev`, the assigned hostname is added to
`allowedDevOrigins` and the resolved development port is reported to `tnl`.
Outside `tnl dev`, the wrapper makes no changes.

## Requirements

Next.js 16.3.4 or newer and Node.js 22.18 or newer are required.
