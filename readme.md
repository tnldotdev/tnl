<p align="center">
  <img src=".github/logo.svg" width="100" alt="tnl" />
</p>
<p align="center">
  tunnels for local apps and private services.
  <br/>
  by <a href="https://github.com/0xcadams">@0xcadams</a>
  <br/><br/>
  <i>hosted <code>tnl</code> is in private beta. email <a href="mailto:chase@tnl.dev?subject=tnl.dev%20beta%20access&amp;body=I'd%20like%20to%20try%20https%3A%2F%2Ftnl.dev.%20My%20email%20is%3A">chase@tnl.dev</a> for access,
  or feel free to <a href="#custom-domains-or-self-hosting">self-host</a>.</i>
</p>
<br/>

Give your local app an HTTPS URL you can share, or connect to a service on a private network. It's like if Tailscale and Cloudflare Tunnel had a baby. And that baby came with a great devex.

## `tnl` where?

### in dev

`tnl` gives every Git worktree its own unique HTTPS URL. Traffic stays encrypted from the browser to your laptop.

Chase and Aya work on `zelda` at Nintendo. Nintendo has added
`dev.nintendo.com`, so each checkout gets its own URL:

```text
https://app-zelda.chase.dev.nintendo.com       -> Chase's main checkout
https://app-zelda-perf.chase.dev.nintendo.com  -> Chase's perf worktree
https://app-zelda.aya.dev.nintendo.com         -> Aya's main checkout
```

Without a custom domain, Nintendo gets a generated suffix on `tnl.dev`, such as
`copper-otter.tnl.dev`. Chase and Aya use member labels within Nintendo only.
Chase's main URL would be `https://app-zelda.chase.copper-otter.tnl.dev`.

### in prod

Connect to your services from anywhere (laptop, CI, etc.).

For instance, you can run a `tnl` publisher inside your VPC. Traffic between the `tnl` client and publisher uses end-to-end [post-quantum encryption](https://tnl.dev/docs/security#post-quantum-encryption) based on publicly trusted TLS certificates (from Let's Encrypt).

The connection will attempt P2P hole-punched UDP and fall back to using relays (which can't read your encrypted traffic). Your db or Kubernetes API aren't publicly exposed:

```text
    tnl (your laptop)    tnl (GitHub Actions)    tnl (Node.js/Python)
            |                      |                      |
            +----------------------+----------------------+
                                   |
                +------------------+------------------+
                |                                     |
           direct UDP                             tnl relay
        (when possible)                           (fallback)
                |                                     |
                +------------------+------------------+
                                   |
+----------------------------------v----------------------------------+
|                           your private vpc                          |
|                                  |                                  |
|                            tnl publisher                            |
|                                  |                                  |
|                 +----------------+-----------------+                |
|                 v                                  v                |
|           db (e.g. RDS)                  kubernetes (e.g. EKS)      |
+---------------------------------------------------------------------+
```

If you can't install `tnl` on a client, you can give your service a public hostname and port instead. For example:

```text
               your app or database client
                            |
                db.dev.nintendo.com:15443
                   (or your subdomain)
                            v
                       tnl ingress
                            |
                +-----------+-----------+
                |                       |
           direct UDP               tnl relay
        (when possible)             (fallback)
                |                       |
                +-----------+-----------+
                            |
+---------------------------v---------------------------+
|                     your private VPC                  |
|                            |                          |
|                      tnl publisher                    |
|                            |                          |
|                            v                          |
|                        API or db                      |
+-------------------------------------------------------+
```

Browsers/HTTP clients can use sign-in, a share link, or a token. PostgreSQL and MySQL clients use a `tnl`-issued client certificate alongside their normal database credentials.

## start developing

First, install the package with pnpm and initialize your project:

```bash
pnpm add -D @tnldotdev/tnl
pnpm exec tnl init
```

For example, with Vite, `pnpm exec tnl init` adds `tnl()` alongside your existing plugins:

```ts
// vite.config.ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/tnl/vite";

export default defineConfig({
  plugins: [tnl()],
});
```

It also creates a project configuration. In Zelda, Chase and Aya add `team`
so they publish to Nintendo even when another team is selected locally:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  team: "nintendo",
  feedback: true,
  services: { app: {} },
  deployments: {
    local: { targets: { app: { public: true } } },
  },
});
```

Start your app (for example, `vite dev`). It runs locally without a `tnl` account - you can [connect to local dependencies](https://tnl.dev/docs/private-services) without opening a tunnel.

To get a public URL, sign in:

```bash
pnpm exec tnl auth login
```

By default, visitors need a sign-in, share link, or token. Hot reloading, WebSockets, SSE, and streaming responses are all supported.

Already have an app listening on port 3000? Run `pnpm exec tnl publish 3000`.
On hosted `tnl.dev`, it gives you a fresh, restricted URL under `preview.tnl.dev`
without putting your name, team, or project in DNS. Ctrl+C stops serving.
To use that URL again, run the `--public-url` command printed by `tnl`. Use
`--ephemeral` if you want the service removed after it stops.

Opaque URLs from one publisher share a random DNS parent and reuse that
publisher's wildcard certificate. The URLs are visibly related, but the
parent doesn't identify the publisher. The wildcard covers only that parent,
not all of `preview.tnl.dev`. A replacement publisher can serve a saved URL
with a new certificate for just that hostname.
New publishers and replacements still need issuance capacity:
`preview.tnl.dev` does not get a separate [Let's Encrypt limit](https://letsencrypt.org/docs/rate-limits/#new-certificates-per-registered-domain)
from `tnl.dev`.

See [installation options](https://tnl.dev/docs/publish), the
[quickstart](https://tnl.dev/docs), and [framework integrations](https://tnl.dev/docs/frameworks).

## run worktrees side by side

Chase leaves Zelda running in his main checkout. In another terminal:

```bash
git worktree add ../perf
cd ../perf
pnpm install --frozen-lockfile
pnpm dev
```

This would end up looking like:

```text
app-zelda.chase.dev.nintendo.com       -> tnl -> localhost:5173
app-zelda-perf.chase.dev.nintendo.com  -> tnl -> localhost:5174
```

Vite and Next.js can choose another port when the preferred one is taken.
Restarting a checkout, changing its port, or moving it with `git worktree move`
keeps its URL. A fresh checkout at the old path gets a different address.
Set `naming: "opaque"` in the project configuration to keep project and member
names out of new app URLs. Read [more about worktrees](https://tnl.dev/docs/development#develop-in-parallel-worktrees).

## share it and get feedback

You can leave inline feedback in your app for your agent to review. Or, send someone on your team a link:

```bash
pnpm exec tnl share --expires-in 7d
```

The link expires after a week and can be revoked early. Similar to how Vercel comments work, reviewers can leave inline feedback:

```text
share link -> your app -> click an element -> leave feedback
```

Then you (or your agent) can use `pnpm exec tnl feedback list` to read feedback from the CLI. See [sharing and feedback](https://tnl.dev/docs/development#share-a-preview).

## register your callbacks once

To add OAuth or webhook support, add the following to your config:

```ts
export default defineConfig({
  // ...existing configuration
  oauth: true,
  // and/or
  webhooks: {
    payments: {
      service: "app",
      path: "/webhooks/stripe",
      provider: "stripe",
    },
  },
});
```

Chase registers one URL for each integration across his Zelda worktrees.

OAuth automatically returns the browser to the worktree that started login:

```text
https://app-zelda-perf.chase.dev.nintendo.com
    |
    v
  GitHub
    |
    v
https://oauth-zelda-k7n2p9.chase.dev.nintendo.com/auth/callback
    |
    v
https://app-zelda-perf.chase.dev.nintendo.com
```

Or, for webhooks, the same event fans out to all running worktrees:

```text
Stripe
  |
  v
https://hooks-zelda-m5p7v2k4t3q6a.chase.dev.nintendo.com/webhooks/stripe
  |
  +---> Chase's main checkout
  +---> Chase's perf worktree
```

You can also select a single webhook receiver, instead of fanning out. See [OAuth setup](https://tnl.dev/docs/development#register-one-oauth-callback-for-your-worktrees)
and [webhook providers](https://tnl.dev/docs/webhooks).

## connect to prod

### from your laptop

For example, connect to a private PostgreSQL instance in Amazon RDS:

```ts
export default defineConfig({
  // ...existing config
  services: {
    orders: { protocol: "postgres" },
  },
  deployments: {
    production: {
      targets: {
        orders: {
          address: {
            type: "rds",
            instance: "orders",
            region: "us-east-1",
          },
          access: { team: true },
        },
      },
    },
  },
});
```

Use your RDS instance name and region. Save the deployment and approve a publisher for this service:

```bash
pnpm exec tnl apply --deployment production
pnpm exec tnl publisher setup --deployment production --service orders
```

Deliver the enrollment key privately to a `production` publisher in your VPC. From your laptop:

```bash
pnpm exec tnl connect orders --deployment production
```

Team members use the printed connection settings with `psql` or their database driver and their normal database credentials. Kubernetes works with `kubectl` and your cluster's existing credentials.

Read about [setting up private services](https://tnl.dev/docs/private-services) or [generating AWS publisher infrastructure](https://tnl.dev/docs/aws-publishers).

### or from ci

Let a GitHub Actions workflow connect to `orders`:

```ts
export default defineConfig({
  // ...existing config
  workloads: {
    migrate: {
      provider: "github",
      deployment: "production",
      services: ["orders"],
      github: {
        workflow: ".github/workflows/deploy.yml",
        branch: "main",
        events: ["push"],
      },
    },
  },
});
```

Apply with `pnpm exec tnl apply --deployment production`, then add the action to your deploy job. For example, with Drizzle:

```yaml
# .github/workflows/deploy.yml
permissions:
  contents: read
  id-token: write
steps:
  # git checkout or package installation...
  - uses: tnldotdev/tnl/connect@<sha>
    with:
      workload: migrate
  - run: pnpm exec drizzle-kit migrate
    env:
      DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
```

The action uses GitHub's OIDC with secure, short-lived tokens to connect to the `orders` service. Then, in your Drizzle config:

```ts
// drizzle.config.ts
import { defineConfig } from "drizzle-kit";
import { connect, deployment } from "@tnldotdev/tnl/node";

const production = deployment("production", {
  project: "nintendo/zelda",
  services: { orders: { protocol: "postgres" } },
});
const database = await connect(production, "orders");

export default defineConfig({
  dialect: "postgresql",
  dbCredentials: {
    ...database,
    user: "postgres",
    database: "orders",
    password: process.env.DB_PASSWORD!,
  },
});
```

The deployment handle reads the job's prepared connection settings without stopping
the job-owned connector. The db password comes from GitHub secrets. In an
application, close the deployment handle after the database client has closed.

See [GitHub Actions setup](https://tnl.dev/docs/workloads#connect-a-github-actions-job).

## custom domains or self-hosting

Claim only a domain you control. For example, Nintendo can delegate
`dev.nintendo.com` without changing the nameservers for `nintendo.com`.

Use `tnl domain claim` to get the DNS records to add; once verified, `tnl` manages its public URL DNS and certificates. See [setting up a custom domain](https://tnl.dev/docs/domains).

Choose the owner at claim time:

```sh
tnl domain claim dev.nintendo.com --personal
# or, to claim it for Nintendo instead:
tnl domain claim dev.nintendo.com --team nintendo --default
tnl domain status dev.nintendo.com --team nintendo
```

With a personal claim, Chase's named `app` uses `app.dev.nintendo.com`.
With a Nintendo claim, Chase and Aya get `app.chase.dev.nintendo.com` and
`app.aya.dev.nintendo.com`. Changing the default affects new services, not
saved URLs. Deployments have their own branch, for example
`app.production.zelda.deploy.dev.nintendo.com`.

Chase can later run `tnl domain transfer dev.nintendo.com --to-team nintendo`.
If he owns both teams, the move needs one command. Otherwise the destination
owner runs the printed accept command. The same DNS delegation stays in place;
saved services, publisher grants, and outstanding certificates must be cleared
first. The reverse move uses `--to-personal`.

Or, you can even run the whole stack yourself (control, ingress, and relays), forever free. See [running your own server](https://tnl.dev/docs/self-hosting).

## how much does it cost?

tnl.dev is free during private beta. Accounts and teams keep a free plan if paid plans arrive.

## how does it compare?

Here's how `tnl` compares to Tailscale, Cloudflare, and ngrok.

### in dev

|                                                    | tnl                             | tailscale             | cloudflare        | ngrok                              |
| -------------------------------------------------- | ------------------------------- | --------------------- | ----------------- | ---------------------------------- |
| Open your app in a browser w/o installing a client | Yes                             | w/ Funnel             | Yes               | Yes                                |
| Control who can visit                              | Sign-in, share links, or tokens | Access rules w/ Serve | Cloudflare Access | OAuth/passwords                    |
| Where TLS is terminated                            | Your device                     | Your device           | Cloudflare        | Your device (but you manage certs) |
| Unique worktree URLs                               | Yes                             | Set up yourself       | Set up yourself   | Set up yourself                    |
| One dynamic OAuth callback URL across worktrees    | Yes                             | Set up yourself       | Set up yourself   | Set up yourself                    |
| Send one webhook event to all worktrees            | Yes                             | Set up yourself       | Set up yourself   | Set up yourself                    |
| Leave inline feedback and read it from the CLI     | Yes                             | Set up yourself       | Set up yourself   | Set up yourself                    |

### in prod

|                                               | tnl                     | tailscale              | cloudflare                   | ngrok                   |
| --------------------------------------------- | ----------------------- | ---------------------- | ---------------------------- | ----------------------- |
| Connect without a publicly reachable endpoint | `tnl connect`           | WireGuard mesh network | Cloudflare One/`cloudflared` | `ngrokd` or Kubernetes  |
| Use your own domain for public HTTPS          | Yes                     | No, only `*.ts.net`    | Yes                          | Yes                     |
| Built-in web firewall (WAF)                   | Yes                     | No                     | Yes                          | Yes                     |
| Run the server infrastructure yourself        | Yes                     | w/ Headscale           | No                           | No                      |
| Route a whole subnet                          | No, individual services | Yes                    | Yes                          | No, individual services |

## contributing

External pull requests are not accepted. Please open an issue to report a bug or suggest a change.

## license

This project is [BSD-3-Clause licensed](LICENSE).
