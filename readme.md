# tnl

**public urls for every worktree.**

tnl gives your local app an end-to-end encrypted HTTPS URL. By default, every
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
npm install -D @tnldotdev/tnl
```

Then, initialize it with the helper:

```bash
npx tnl init
```

`tnl init` creates a `tnl.config.ts` with the command that starts your
app. It also sets up a missing framework config or tells you what to add to an
existing one.

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    app: {
      directory: ".",
      dev: { command: ["npm", "run", "dev"] },
    },
  },
});
```

Then run:

```bash
npx tnl dev
```

Sign in to GitHub when prompted. Your app starts on any available local port,
and tnl publishes to its unique URL, with only your current IP whitelisted:

```text
+--[ tnl dev ]-- ready ----------------------------------------+
|                                                              |
|  https://app-billing-abcd1234.ecstatic-penguin.tnl.dev       |
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

If your project has a separate API, you can put both startup commands
in `tnl.config.ts`:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    web: {
      directory: "apps/web",
      dev: { command: ["pnpm", "dev"] },
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

These now have separate URLs:

| service | example URL                                             |
| ------- | ------------------------------------------------------- |
| `web`   | `https://web-billing-abcd1234.ecstatic-penguin.tnl.dev` |
| `api`   | `https://api-billing-abcd1234.ecstatic-penguin.tnl.dev` |

Use the API URL assigned to this project in the frontend:

```ts
import { tnl } from "@tnldotdev/tnl";

const apiURL = tnl?.services.api.url;
// https://api-billing-abcd1234.ecstatic-penguin.tnl.dev
```

Read about [project configuration](https://tnl.dev/docs/configuration) and
[framework metadata](https://tnl.dev/docs/frameworks#use-a-service-url-in-your-app).

## open changes side by side

Create another Git worktree. The project configuration comes with it:

```bash
git worktree add -b perf ../perf
cd ../perf
npm install
npx tnl dev web
```

The same frontend is now running from two checkouts:

| worktree  | example frontend URL                                     |
| --------- | -------------------------------------------------------- |
| `billing` | `https://web-billing-abcd1234.ecstatic-penguin.tnl.dev`  |
| `perf`    | `https://web-checkout-e5f6a7b8.ecstatic-penguin.tnl.dev` |

Open both URLs. Change the checkout page in one. The other keeps running its
own code.

For Next.js and Vite, there is no port bookkeeping. If another worktree already
uses the preferred port, the framework can choose another and tnl follows the
listener it actually opens. Restarting the same worktree reuses its URL.

See what is running across your local worktrees from any of them:

```console
pnpm exec tnl status --all
```

## custom domain

Claim a development subdomain and make it the default for new public URLs:

```console
pnpm exec tnl domain claim dev.example.com --default
pnpm exec tnl domain list
```

Delegate the subdomain with the NS records from `domain list`. Once it is
ready, new public URLs can look like this:

```text
https://web-checkout-e5f6a7b8.alex.dev.example.com
```

[Use a custom domain](https://tnl.dev/docs/domains).

## self-host

After deploying the MIT-licensed tnl server, point the same project at it:

```ts
export default defineConfig({
  server: "https://control.example.com",
  services: {
    // ...
  },
});
```

The same client and project configuration work with hosted tnl.dev or your own
server. Visitor HTTPS stays encrypted through ingress and relay and terminates
in tnl beside your app.

[Run your own server](https://tnl.dev/docs/self-hosting).

## already running an app?

On macOS or Linux, Homebrew installs the native client. Publish an HTTP app
already listening on port 3000 without any project configuration:

```console
brew install tnldotdev/tap/tnl
tnl publish 3000
```

This gives the app a URL without project configuration or a child command.
[Read about `tnl publish`](https://tnl.dev/docs/publish).

tnl saves the public URL for your next publish run. To see or remove saved
public URLs, use `tnl url list` or `tnl url delete <public-url-id>`.

## how much does it cost?

tnl.dev is free now. Accounts and teams created while it is free will keep a
free plan if paid options arrive. We'll announce usage limits before they apply.

## license

The client and server are [MIT-licensed](LICENSE). See the
[dependency notices](THIRD_PARTY_LICENSES.txt), browse the
[command reference](https://tnl.dev/docs/cli), or [contribute](contributing.md).
