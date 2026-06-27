# `@tnldotdev/tnl`

This package installs the `tnl` client for macOS or Linux on arm64 or x64. It
does not include the `tnld` server daemon.

## Install

Install the client:

```console
pnpm add --save-dev @tnldotdev/tnl@next
```

Add `@tnldotdev/next` or `@tnldotdev/vite` for framework integration.

The package also exports `defineConfig` and the project configuration types:

```ts
// tnl.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  dev: { command: ["pnpm", "dev"] },
}));
```

`tnl.ts` is implicitly configuration version 1. Static `tnl.yml`, `tnl.yaml`,
and `tnl.json` files require `version: 1`; the JSON Schema is available at
`https://tnl.dev/schema/v1.json`.

Then invoke `tnl` from a package script:

```json
{
  "scripts": {
    "dev:public": "tnl dev -- pnpm dev"
  }
}
```

Use `tnl publish 3000 --open` or `tnl dev --open -- pnpm dev` to launch the
public URL once it is ready.

The package selects an exact-version native optional dependency for the current
platform. It does not run an install script or download executable code from a
third-party host. Node.js 22.18 or newer is required by the launcher and the
TypeScript configuration loader.

Deploy `tnld` with the release container or install it from Homebrew or a
release archive.
