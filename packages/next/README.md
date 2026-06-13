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
a synchronous or asynchronous factory. Claim a managed hostname once with
`tnl host claim myapp`, then give every Git worktree its own child hostname:

```ts
// next.config.ts
import { withTnl } from "@tnldotdev/next";

export default withTnl({ reactStrictMode: true }, ({ worktree }) => ({
  host: `${worktree.label}.myapp`,
  allowCurrentIP: true,
}));
```

The options factory runs only for a Next.js development server beneath
`tnl dev`. It receives a read-only environment copy, the process working
directory, and worktree metadata. Next.js retains its normal behavior of trying
the next port when its default is occupied; the integration reports the final
listening port with `registerLocalPort`.

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

The available `TnlTunnelOptions` mirror `tnl publish` and server selection:

```ts
withTnl(
  {},
  {
    controlURL: "https://tnl.example.com",
    host: "feature.chase.example.com",
    allowIP: ["198.51.100.0/24", "2001:db8::/64"],
    allowCurrentIP: true,
  },
);
```

`allowCurrentIP` is additive with `allowIP`. When `allowIP` is omitted,
`allowCurrentIP: true` restricts access to the current public IP only. The Go
client performs server authentication, hostname authorization, and IP
normalization. CLI `--server`/`TNL_SERVER` and `--host`/`TNL_HOST` take
precedence over project options.

The selected server-local identity must own a managed hostname or custom domain
with active status. The `host` hostname must match it exactly or add no more
than eight labels to its left. A temporary hostname authorizes only itself. An
identity cannot publish beneath a hostname owned by another identity.

## Configuration

Your existing Next.js settings are preserved. During `tnl dev`, the assigned
hostname is added to `allowedDevOrigins` and the resolved development port is
reported with `registerLocalPort`. Outside `tnl dev`, the wrapper makes no
changes.

## Requirements

Next.js 16.3.4 or newer and Node.js 22.15 or newer are required.
