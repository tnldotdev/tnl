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
configuration functions. Its second argument accepts static tunnel options or
a synchronous or asynchronous factory. Reserve a managed base once with
`tnl host add myapp`, then give every Git worktree its own child name:

```ts
// next.config.ts
import { withTnl } from "@tnldotdev/next";

export default withTnl({ reactStrictMode: true }, ({ worktree }) => ({
  name: `${worktree.label}.myapp`,
  allowCurrentIP: true,
}));
```

The options factory runs only for a Next.js development server beneath
`tnl dev`. It receives a frozen environment snapshot, the process working
directory, and worktree metadata. Next.js retains its normal behavior of trying
the next port when its default is occupied; the integration registers the final
listening port exposed by Next.js.

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

## Tunnel Options

The available route options mirror `tnl publish` and server selection:

```ts
withTnl(
  {},
  {
    server: "https://tnl.example.com",
    name: "feature.chase.example.com",
    allowIP: ["198.51.100.0/24", "2001:db8::/64"],
    allowCurrentIP: true,
  },
);
```

`allowCurrentIP` is additive with `allowIP`. When `allowIP` is omitted,
`allowCurrentIP: true` restricts access to the current public IP only. The Go
client performs server authentication, hostname authorization, and IP
canonicalization. CLI `--server`/`TNL_SERVER` and `--name`/`TNL_NAME` take
precedence over project options.

The signed-in user must own the configured custom domain or an eligible parent
hostname. Separate users cannot currently share one parent hostname.

## Configuration

Your existing Next.js settings are preserved. During `tnl dev`, the assigned
hostname is added to `allowedDevOrigins` and the resolved development port is
registered. Outside `tnl dev`, the wrapper makes no changes.

## Requirements

Next.js 15.2 or newer and Node.js 22.15 or newer are required.
