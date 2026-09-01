# `@tnldotdev/next`

This package connects a Next.js development server to `tnl dev`.

## Install

```console
pnpm add --save-dev @tnldotdev/next
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
configuration functions.

## Run

```console
tnl dev -- next dev
```

Ordinary `next dev` remains local.

## Custom Hostname

Set a hostname for your local shell:

```console
export TNL_NAME=chase.example.com
tnl dev -- next dev
```

Or pass it directly:

```console
tnl dev --name chase.example.com -- next dev
```

The signed-in user must own the custom domain or an eligible parent claim.
Separate users cannot currently share one parent claim.

## Configuration

Your existing Next.js settings are preserved. During `tnl dev`, the assigned
hostname is added to `allowedDevOrigins` and the resolved development port is
registered. Outside `tnl dev`, the wrapper makes no changes.

## Requirements

Next.js 15.2 or newer and Node.js 20.9 or newer are required.
