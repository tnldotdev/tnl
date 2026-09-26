# tnl

**public urls for every worktree.**

tnl starts your app and gives it an HTTPS URL. Each Git worktree gets its own,
so you can open changes side by side. Use [tnl.dev](https://tnl.dev), put the
URLs on a domain you own, or run the tnl server yourself.

## start developing

In a Next.js or Vite project with a `dev` script:

```console
pnpm add -D @tnldotdev/tnl@next
pnpm exec tnl init
```

`tnl init` creates `tnl.config.ts` with the command that starts your app. If
your existing framework config needs a change, it tells you what to add.

```console
pnpm exec tnl dev
```

Sign in when prompted. Your app starts, and tnl prints its URL:

```text
+--[ tnl dev ]-- ready ----------------------------------------+
|                                                              |
|  https://app-checkout-a1b2c3d4.busy-toast.tnl.dev            |
|     |                                                        |
|     v                                                        |
|  tnl                                                         |
|     |                                                        |
|     v                                                        |
|  http://127.0.0.1:5173                                       |
|                                                              |
|  route version             1                                 |
|  framework                 vite                              |
|  automatically allowed IP  192.0.2.10                        |
|                                                              |
+-- ctrl+c to stop --------------------------------------------+
```

[Follow the quickstart](https://tnl.dev/docs) for the configuration and
[Next.js and Vite setup](https://tnl.dev/docs/frameworks). The integration
follows the port your app actually opens, including when another worktree
already uses the preferred port. Live reload works through the URL.

## already running an app?

On macOS or Linux, Homebrew installs the native client. Publish an HTTP app
already listening on port 3000 without any project configuration:

```console
brew install tnldotdev/tap/tnl
tnl publish 3000
```

tnl.dev is free now. Accounts and teams created while it is free will keep a
free plan if paid options arrive. We'll announce usage limits before they apply.

## why tnl?

ngrok and Cloudflare Tunnel can also give apps stable URLs and custom domains.
tnl combines worktree-aware URLs, Next.js and Vite integrations, and a server
you can run yourself. Visitor HTTPS stays encrypted until it reaches tnl beside
your app.

[Use your own domain](https://tnl.dev/docs/domains) ·
[Run your own server](https://tnl.dev/docs/self-hosting) ·
[Commands and visitor access](https://tnl.dev/docs/cli) ·
[Contribute](contributing.md)

## telemetry and license

tnl sends usage telemetry by default, even with a self-hosted server. Disable
it with `TNL_NO_TELEMETRY=true`. [See what is sent](https://tnl.dev/docs/cli#telemetry).
The client and server are [MIT-licensed](LICENSE); see the
[dependency notices](THIRD_PARTY_LICENSES.txt).
