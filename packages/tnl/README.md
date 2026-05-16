# `@tnldotdev/tnl`

This package installs the `tnl` client for macOS or Linux on arm64 or x64. It
does not include the `tnld` server daemon.

## Install

Install the client:

```console
pnpm add --save-dev @tnldotdev/tnl@next @tnldotdev/vite@next
```

Then invoke `tnl` from a package script:

```json
{
  "scripts": {
    "dev:public": "tnl dev -- pnpm dev"
  }
}
```

The package selects an exact-version native optional dependency for the current
platform. It does not run an install script or download executable code from a
third-party host. Node.js 22.15 or newer is required by the launcher.

Deploy `tnld` with the release container or install it from Homebrew or a
release archive.
