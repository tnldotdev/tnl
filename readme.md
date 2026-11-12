<p align="center">
  <img src=".github/logo.svg" width="100" alt="tnl" />
</p>
<p align="center">
  easy tunnels for dev and prod
  <br/>
  by <a href="https://github.com/0xcadams">@0xcadams</a>
  <br/><br/>
  <i><code>tnl</code> is not ready yet - first release is coming November 23.</i>
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
    app: { protocol: "http" },
  },
  environments: {
    local: {
      targets: {
        app: { publicURL: {} },
      },
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

For example, give staging and production separate PostgreSQL instances in Amazon
RDS. Declare the protocol once; each environment owns its target:

```ts
export default defineConfig({
  services: {
    orders: { protocol: "postgres" },
  },
  environments: {
    staging: {
      targets: {
        orders: {
          discovery: {
            type: "rds",
            instance: "orders-staging",
            region: "us-east-1",
          },
        },
      },
    },
    production: {
      targets: {
        orders: {
          discovery: {
            type: "rds",
            instance: "orders-production",
            region: "us-east-1",
          },
        },
      },
    },
  },
});
```

Use your RDS instance names and regions. This is a separate remote-service
configuration; the local app configuration above keeps its own listener and
preview settings. Check the configuration, then apply staging:

```bash
pnpm exec tnl check
pnpm exec tnl apply --environment staging
```

Apply production separately with `pnpm exec tnl apply --environment production`
when you intend to change it. Saving a shared definition changes no installed
environment; applying staging does not update production or a local worktree.
Targets, TLS trust, settings, saved service IDs, and the applied definition revision
belong to each environment. An environment can select its own control server;
names and server-qualified references select resources, not permission.

Enroll independent publisher replicas into that exact environment and explicitly
approve the services they can publish. Run them in the VPC with their own AWS
discovery permissions. Preserve each replica's original signing key and durable
TLS/certificate state across replacement; it does not sign in or reenroll.

Approve visitor access separately. An environment name, successful apply, or
publisher enrollment gives no visitor permission. Once authorized, select the
production `orders` service's saved ID from its environment response:

```bash
pnpm exec tnl connect svc_REPLACE_WITH_PRODUCTION_ORDERS_ID
```

Use the printed settings with `psql` or your database driver and normal database
credentials. Kubernetes works with `kubectl` and your cluster's existing credentials.
An acknowledged apply is not a successful database query; check the target through
a real client. Existing connections are not replayed or transferred between replicas.

Read about [setting up environments](https://tnl.dev/docs/environments),
[private services](https://tnl.dev/docs/private-services), or
[running publishers in AWS](https://tnl.dev/docs/aws-publishers).

### or from ci

Give a deployment its own approved identity rather than your personal tnl login.
Approve a visitor permission for the exact environment or explicitly scoped
collection and a fixed service allowlist, such as `orders`. At runtime, use the
shared generated `services` snapshot with the normal SDK, selected environment,
and current identity proof. Database migrations still use the database's own
username and password; close the driver before the tnl client.

If automation also creates installations or issues publisher enrollment, approve
a separate provisioning grant with explicit scope, services, operations, expiry,
and enrollment budget. That grant cannot visit services. Publishing requires its
own exact publisher grants; adding a service or rolling back a definition cannot
mint or restore them automatically.

`tnl apply` never creates or restores workload permissions. Approve one workload
declared under `environments.production.workloads` explicitly:

```bash
pnpm exec tnl auth approve --environment production --workload migrations \
  --intent production-migrations-1 --expires-at 2026-12-01T00:00:00Z
```

Keep the intent and expiry unchanged when retrying a lost reply. The server
returns the original machine and permission IDs without looking up provider names
again. A revoked or expired permission stays revoked or expired; granting access
again requires a new explicit intent. The receipt contains no credential.

The explicit provider setup and canonical admission checks still need final
qualification before this is a supported CI recipe. See
[workload access](https://tnl.dev/docs/workloads) and the intended
[GitHub identity requirements](https://tnl.dev/docs/workloads#github-actions).

## custom domains or self-hosting

You can also add a subdomain you own, for URLs like `https://app.alex.dev.example.com`.

Use `tnl domain claim` to get the DNS records to add; once verified, `tnl` manages its public URL DNS and certificates.
See [setting up a custom domain](https://tnl.dev/docs/domains).

Or, you can even run the whole stack yourself (control, ingress, and relays), forever free. See [running your own server](https://tnl.dev/docs/self-hosting).

## how much does it cost?

The hosted tnl.dev is free for now. Accounts and teams created while it is free will keep a free plan if paid options arrive.

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
