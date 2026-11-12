<p align="center">
  <img src=".github/logo.svg" width="100" alt="tnl" />
</p>
<p align="center">
  easy tunnels for dev and prod
  <br/>
  by <a href="https://github.com/0xcadams">@0xcadams</a>
  <br/><br/>
  <i>tnl.dev is in private beta. <a href="mailto:beta@tnl.dev?subject=tnl.dev%20beta%20access&amp;body=I'd%20like%20to%20try%20tnl.%20My%20sign-in%20email%20is%3A">email beta@tnl.dev for access</a>.</i>
</p>
<br/>

`tnl` helps you connect to local and/or private services through end-to-end encrypted tunnels. It's like if Tailscale and Cloudflare Tunnel had a baby. And that baby came with a great devex.

## `tnl` where?

### in dev

`tnl` gives every Git worktree its own unique HTTPS URL. Traffic stays encrypted from the browser to your laptop.

For example, take a repo named `demo` with an `app` service. The main checkout and a `perf` worktree each get their own URL:

```text
                             your browser
                                   |
                         https://*.example.com
                      (tnl.dev or your subdomain)
                                   v
                              tnl ingress
                         (hosted/self-hosted)
                                   |
                +------------------+------------------+
                |                                     |
           direct UDP                             tnl relay
        (when possible)                           (fallback)
                |                                     |
                +------------------+------------------+
                                   |
+----------------------------------v----------------------------------+
|                             your laptop                             |
|                                  |                                  |
|                +-----------------+----------------+                 |
|                v                                  v                 |
|       tnl (main checkout)                tnl (perf worktree)        |
|       app-demo.example.com            app-demo-perf.example.com     |
|                |                                  |                 |
|                v                                  v                 |
|         localhost:5173                     localhost:5174           |
+---------------------------------------------------------------------+
```

The Next.js and Vite plugins automatically handle port conflicts. And OAuth and webhooks get one consistent URL that works across all worktrees.

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
                  api.example.com:15443
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
pnpm exec tnl auth login
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

It also creates a project configuration:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  feedback: true,
  services: {
    app: {
      publicURL: {},
      target: { type: "app" },
    },
  },
});
```

Start your app (e.g. with `vite dev`) and get its URL. By default, any visitor needs to sign in or have a share link.

Hot reloading, WebSockets, SSE, and streaming responses are all supported.

_Already have an app listening on port 3000? Run `pnpm exec tnl publish 3000`._

See [installation options](https://tnl.dev/docs/publish), the
[quickstart](https://tnl.dev/docs), and [framework integrations](https://tnl.dev/docs/frameworks).

## run worktrees side by side

Once your `tnl` setup is committed to Git, you can leave the app running in your main checkout, and in another terminal, create a worktree and start the app there too:

```bash
git worktree add ../perf
cd ../perf
pnpm install --frozen-lockfile
pnpm dev
```

This would end up looking like:

```text
your browser
|
+-- https://app-demo.example.com
|          |
|          v
|   main checkout -> localhost:5173
|
+-- https://app-demo-perf.example.com
           |
           v
    perf worktree -> localhost:5174
```

Vite and Next.js can choose another port when the preferred one is taken, and `tnl` will publish the port they actually open. Restarting either checkout reuses its URL. Read [more about worktrees](https://tnl.dev/docs/development#develop-in-parallel-worktrees).

## share it and get feedback

You can leave inline feedback in your app for your agent to review. Or, send someone on your team a link:

```bash
pnpm exec tnl share link create app-demo.example.com \
  --expires-in 7d
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

The OAuth and webhook URLs do not change when you work across multiple checkouts. They "just work" across all your worktrees.

OAuth automatically returns the browser to the worktree that started login:

```text
                   https://app-demo-perf.example.com
                                   |
                                   | start login
                                   v
                                 GitHub
                                   |
                                   v
+--[ oauth callback url ]---------------------------------------------+
|             https://oauth-demo.example.com/auth/callback            |
+---------------------------------------------------------------------+
                                   |
                                   | redirect browser
                                   v
                   https://app-demo-perf.example.com
```

Or, for webhooks, the same event fans out to all running worktrees:

```text
                         webhook (e.g. Stripe)
                                   |
                                   v
+--[ webhook url ]----------------------------------------------------+
|            https://hooks-demo.example.com/webhooks/stripe           |
+---------------------------------------------------------------------+
                                   |
                       +-----------+-----------+
                       |                       |
                       v                       v
                 main checkout            perf worktree
```

You can also select a single webhook receiver, instead of fanning out. See [OAuth setup](https://tnl.dev/docs/development#register-one-oauth-callback-for-your-worktrees)
and [webhook providers](https://tnl.dev/docs/webhooks).

## connect to prod

### from your laptop

For example, connect to a private PostgreSQL instance in Amazon RDS:

```ts
export default defineConfig({
  // ...existing config
  publisherGroups: {
    production: {},
  },
  services: {
    orders: {
      publisherGroup: "production",
      protocol: "postgres",
      target: {
        type: "rds",
        instance: "orders",
        region: "us-east-1",
      },
      access: { team: true },
    },
  },
});
```

Use your RDS instance name and region. Apply it with `pnpm exec tnl apply`, then run a `production` publisher in your VPC. From your laptop:

```bash
pnpm exec tnl connect orders
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
      services: ["orders"],
      github: {
        // your GitHub repo details
        repository: "acme/demo",
        workflow: ".github/workflows/deploy.yml",
        ref: "refs/heads/main",
      },
    },
  },
});
```

Apply the config, then add the action to your deploy job. For example, with Drizzle:

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
import { tnl } from "@tnldotdev/tnl";

export default defineConfig({
  dialect: "postgresql",
  dbCredentials: {
    ...tnl.connect("orders"),
    user: "postgres",
    database: "orders",
    password: process.env.DB_PASSWORD!,
  },
});
```

`tnl.connect("orders")` reads the local host, port, and TLS settings prepared by the action. The db password comes from GitHub secrets.

See [GitHub Actions setup](https://tnl.dev/docs/workloads#connect-a-github-actions-job).

## custom domains or self-hosting

You can also add a subdomain you own, for URLs like `https://app.alex.dev.example.com`.

Use `tnl domain claim` to get the DNS records to add; once verified, `tnl` manages its public URL DNS and certificates.
See [setting up a custom domain](https://tnl.dev/docs/domains).

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
| Built-in web firewall (WAF)                   | No                      | No                     | Yes                          | Yes                     |
| Run the server infrastructure yourself        | Yes                     | w/ Headscale           | No                           | No                      |
| Route a whole subnet                          | No, individual services | Yes                    | Yes                          | No, individual services |

## license

This project is [BSD-3-Clause licensed](LICENSE).
