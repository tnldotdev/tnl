<p align="center">
  <img src="docs/logo.svg" width="200" alt="tnl" />
</p>
<p align="center">
  easy tunnels for dev and prod
  <br/>
  by <a href="https://github.com/0xcadams">@0xcadams</a>
</p>
<br/>

> `tnl` is not ready yet - first release is coming November 23.

`tnl` allows you to take a shortcut through the internet. It's like if Tailscale
and Cloudflare Tunnels had a baby. And that baby had great devex.

## `tnl` where?

In dev, `tnl` gives every Git worktree its own HTTPS URL. Traffic stays
encrypted from the browser to the `tnl` process on your laptop. Here's the
shape of it, with shortened URL names:

```text
           your browser
                |
              HTTPS
                v
           tnl ingress -----------------> tnl relay
      (hosted/self-hosted)          (hosted/self-hosted)
                                              |
                                      encrypted traffic
                                              |
+---------------------------------------------v---------------+
|                         your laptop                         |
|                                                             |
|  tnl (main repo)               tnl (perf worktree)          |
|  web.calm-otter.tnl.dev       web-perf.calm-otter.tnl.dev   |
|            |                              |                 |
|            v                              v                 |
|      localhost:5173                  localhost:5174         |
|                                                             |
+-------------------------------------------------------------+
```

In prod, connect to private services from your laptop or GitHub Actions.
A `tnl` publisher inside your VPC connects out to the relays, so your
database and Kubernetes API don't need public endpoints:

```text
     tnl (your laptop)         or      tnl (github actions)
             |                                   |
             +-----------------+-----------------+
                               |
                               v
                           tnl relay
                     (hosted/self-hosted)
                               |
                       encrypted tunnel
                               |
+------------------------------v------------------------------+
|                      aws / private vpc                      |
|                              |                              |
|                        tnl publisher                        |
|                              |                              |
|                +-------------+-------------+                |
|                v                           v                |
|            postgres                   kubernetes            |
|                                                             |
+-------------------------------------------------------------+
```

## start developing

First, install the npm package and initialize your project:

```bash
npm install -D @tnldotdev/tnl
npx tnl init
npx tnl auth login
```

For Vite, add `tnl()` alongside your existing plugins. `tnl init` creates a
missing config or tells you where to update an existing one:

```ts
// vite.config.ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/tnl/vite";

export default defineConfig({ plugins: [tnl()] });
```

It also creates your project configuration:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  feedback: true,
  services: {
    app: { publicURL: {}, target: { type: "app" } },
  },
});
```

Start your app with `npm run dev`. Run `npx tnl status` in another terminal
to find its URL. Hot reloading, WebSockets, SSE, and streaming responses work
through it. By default, visitors need a current sign-in, share link, or token.

Already have an app listening on port 3000? Run `npx tnl publish 3000`.
See [installation options](https://tnl.dev/docs/publish), the
[quickstart](https://tnl.dev/docs), and [framework integrations](https://tnl.dev/docs/frameworks).

## open changes side by side

Have a frontend and an API? Give each one a public URL in `tnl.config.ts`:

```ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  feedback: true,
  services: {
    web: { publicURL: {} },
    api: { publicURL: {} },
  },
});
```

Select `tnl({ service: "web" })` in Vite. For the API, call
`await tnl.prepare({ service: "api" })`, then register the bound server with
the returned handle. Start each app with its usual development command.
See [API server setup](https://tnl.dev/docs/frameworks#api-servers) and [worktrees](https://tnl.dev/docs/development).

Create another checkout with `git worktree add ../perf` and start the apps
there too. Each checkout gets its own URLs, reused across restarts:

```text
shop
+-- main
|   web -> https://web-shop-k7n2p9.calm-otter.tnl.dev
|   api -> https://api-shop-k7n2p9.calm-otter.tnl.dev
|
+-- perf
    web -> https://web-shop-perf-m4q8s2.calm-otter.tnl.dev
    api -> https://api-shop-perf-m4q8s2.calm-otter.tnl.dev
```

Vite and Next.js report the port they actually opened, including when another
worktree already has the preferred port. In the frontend, read this worktree's
API URL instead of hardcoding it:

```ts
import { tnl } from "@tnldotdev/tnl";

const apiURL = tnl.services?.api?.url;
```

## share it and get feedback

Send someone a link to your running preview. Using your web app's hostname:

```bash
npx tnl share link create web-shop-k7n2p9.calm-otter.tnl.dev \
  --preview --expires-in 7d
```

The link includes the preview's current public URLs and can be revoked early.
With `feedback: true`, reviewers can leave comments right on the page:

```text
share link -> your app -> click an element -> leave feedback
```

Use `tnl feedback list` to read feedback from the CLI. Reply and resolve from
either interface; reports keep submitted context and source state.
[Sharing and feedback](https://tnl.dev/docs/development#share-a-preview).

## register your callbacks once

New worktree, same OAuth callback and webhook addresses. Add to the config above:

```ts
oauth: true,
webhooks: {
  payments: { service: "api", path: "/webhooks/stripe", provider: "stripe" },
},
```

Use `tnl.oauth.url` with your auth library's callback path, and register
`tnl.webhooks.payments.url` with Stripe:

```text
oauth callback -> the worktree that started login

                         +-> main
stripe webhook ----------+
                         +-> perf
```

Stripe events fan out to ready worktrees; you can also select one receiver.
Your app still handles OAuth state and webhook signature checks.
[OAuth setup](https://tnl.dev/docs/development#register-one-oauth-callback-for-your-worktrees)
and [webhook providers](https://tnl.dev/docs/webhooks).

## connect to prod

Apply your private service configuration and run a publisher group in your VPC.
Then connect from your laptop:

```bash
npx tnl connect orders
```

Use the printed connection settings with `psql` or your database driver.
Kubernetes works with `kubectl` and your cluster's existing credentials.
[Set up private services](https://tnl.dev/docs/private-services) or
[generate AWS publisher infrastructure](https://tnl.dev/docs/aws-publishers).

Your CI job can connect too. After approving a `deploy` workload for your
GitHub workflow, add the action to your existing job:

```yaml
permissions: { contents: read, id-token: write }
timeout-minutes: 20
steps:
  # your checkout (persist-credentials: false) and npm ci steps go here
  - uses: tnldotdev/tnl/connect@f8a012673058b09a24f81be9f57927c5b5c18fb7
    with:
      workload: deploy
  - run: npm run db:migrate
```

The action uses GitHub's identity to prepare connections for later steps.
Your migration script uses the SDK's connection settings and your normal
database credentials. [GitHub Actions setup](https://tnl.dev/docs/workloads#connect-a-github-actions-job).

## custom domain

Bring a subdomain you own. `tnl domain claim` prints the NS records to add;
once delegated and verified, tnl manages its public URL DNS and certificates.
[Use a custom domain](https://tnl.dev/docs/domains).

## self-host

Use hosted tnl.dev or run your own server. Set `server` in `tnl.config.ts`
to your control URL; the same app integrations work with either.
[Run your own server](https://tnl.dev/docs/self-hosting).

## how much does it cost?

tnl.dev is free for now. Teams have a soft limit of 50 GiB of transfer per
month across their public URLs, counting traffic in both directions.
Accounts and teams created while it is free will keep a free plan if paid options arrive.

## license

The client and server are [BSD-3-Clause licensed](LICENSE). See the
[dependency notices](THIRD_PARTY_LICENSES.txt), browse the
[command reference](https://tnl.dev/docs/cli), or [contribute](contributing.md).
