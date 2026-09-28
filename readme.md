# tnl

`tnl` gives your local app an end-to-end encrypted HTTPS URL. By default, every
Git worktree gets its own unique URL, so you can easily work on multiple development
tracks in parallel.

```text
                           browser
                              |
                            HTTPS
                              v
                 tnld (hosted or self-hosted)
                              |
                      encrypted traffic
                              |
+-----------------------------v-----------------------------+
|                       your machine                        |
|                                                           |
|  main repo                    perf worktree               |
|  web URL -> :5173             web URL -> :5174            |
|  api URL -> :3001             api URL -> :3002            |
|                                                           |
+-----------------------------------------------------------+
```

## start developing

First, install the NPM package:

```bash
npm install -D @tnldotdev/tnl@next
```

Then, initialize with the helper:

```bash
npx tnl init
```

`tnl init` walks you through creating a `tnl.config.ts` with the command
that starts your app. For example, in a Vite project:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    app: {
      directory: ".",
      dev: { command: ["vite", "dev"] },
    },
  },
});
```

Then run:

```bash
npx tnl dev
```

Sign in to GitHub when prompted. Your app will start on the next available port,
and `tnl` publishes to its unique URL, with only your current IP whitelisted:

```text
+--[ tnl dev ]-- ready ----------------------------------------+
|                                                              |
|  https://app-example-abcd1234.ecstatic-penguin.tnl.dev       |
|     |                                                        |
|     v                                                        |
|    tnl                                                       |
|     |                                                        |
|     v                                                        |
|  http://127.0.0.1:5173                                       |
|                                                              |
|  framework                 vite                              |
|  automatically allowed IP  122.151.3.101                     |
|                                                              |
+-- ctrl+c to stop --------------------------------------------+
```

Hot reloading works automatically, as well as SSE/websockets/streaming responses.

You can [allow reviewers or webhooks](https://tnl.dev/docs/publish#who-can-visit) when
you need them.

[Follow the quickstart](https://tnl.dev/docs) or read about
[framework setup](https://tnl.dev/docs/frameworks).

## give your services their own urls

If your project has multiple separate services, you can put both startup commands
in `tnl.config.ts`:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    web: {
      directory: "apps/web",
      dev: { command: ["vite", "dev"] },
    },
    api: {
      directory: "apps/api",
      dev: { command: ["pnpm", "dev"] },
    },
  },
});
```

Start both services either together or individually:

```bash
npx tnl dev
# or
npx tnl dev web
npx tnl dev api
```

These will have separate URLs:

| service | URL                                                     |
| ------- | ------------------------------------------------------- |
| `web`   | `https://web-example-abcd1234.ecstatic-penguin.tnl.dev` |
| `api`   | `https://api-example-abcd1234.ecstatic-penguin.tnl.dev` |

Use the API URL assigned to this project in the frontend:

```ts
import { tnl } from "@tnldotdev/tnl";

const apiURL = tnl.services?.api?.url;
// https://api-example-abcd1234.ecstatic-penguin.tnl.dev
```

Read about [project configuration](https://tnl.dev/docs/configuration) and
[framework metadata](https://tnl.dev/docs/frameworks#use-a-service-url-in-your-app).
For a Node or Bun API, use `tnl.port` and `tnl.register(server)` so worktrees
can listen on different ports. See [API server setup](https://tnl.dev/docs/frameworks#api-servers).

## open changes side by side

Create another Git worktree. The project configuration comes with it:

```bash
git worktree add -b perf ../perf
```

Then start the two services:

```bash
npx tnl dev
# or
npx tnl dev web
npx tnl dev api
```

The same frontend is now running from two checkouts:

| worktree | frontend URL                                             |
| -------- | -------------------------------------------------------- |
| `main`   | `https://web-example-abcd1234.ecstatic-penguin.tnl.dev`  |
| `perf`   | `https://web-checkout-e5f6a7b8.ecstatic-penguin.tnl.dev` |

For Next.js and Vite, there is no port bookkeeping. If another worktree already
uses the preferred port, the framework can choose another and `tnl` follows the
listener it actually opens. Restarting the same worktree reuses its URL.

See what is running across your local worktrees from any of them:

```bash
npx tnl status --all
```

## custom domain

Claim a development subdomain and make it the default for new public URLs:

```bash
npx tnl domain claim dev.example.com --default
npx tnl domain list
```

Delegate the subdomain with the NS records. Then, dev URLs will look like:

```text
https://web-example-abcd1234.chase.dev.example.com
```

[Use a custom domain](https://tnl.dev/docs/domains).

## self-host

After deploying the `tnl` server, update your config with it:

```ts
export default defineConfig({
  server: "https://control.example.com",
  services: {
    // ...
  },
});
```

The same config works with hosted tnl.dev or your own server.

[Run your own server](https://tnl.dev/docs/self-hosting).

## not using typescript/javascript, or don't want config?

You can use Homebrew to install the `tnl` client. Publish an HTTP app
already listening on port 3000 without any configuration:

```bash
brew install tnldotdev/tap/tnl
tnl publish 3000
```

This works very similarly to `tnl dev`. [Read about `tnl publish`](https://tnl.dev/docs/publish).

## how much does it cost?

tnl.dev is free for now. Teams have a soft limit of 50 GiB of transfer per
month across their public URLs, counting traffic in both directions.

Accounts and teams created while it is free will keep a free plan
if paid options arrive.

## license

The client and server are [MIT-licensed](LICENSE). See the
[dependency notices](THIRD_PARTY_LICENSES.txt), browse the
[command reference](https://tnl.dev/docs/cli), or [contribute](contributing.md).
