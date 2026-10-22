# tnl

> tnl is in prerelease. the first release is coming november 1.

`tnl` gives your local app an end-to-end encrypted HTTPS URL. By default, every
Git worktree gets its own unique URL, so you can easily preview multiple
development tracks in parallel.

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

## try tnl

Try the built-in demo without installing a project dependency or signing in:

```bash
npx --yes @tnldotdev/tnl publish --demo
```

On tnl.dev, the guest link opens in your browser when ready. Click **ping** and
match the URL and count with the terminal running `tnl`. The browser shows the
round-trip time and when your computer sent the pong. Guests can run one demo
at a time. The link admits this demo without signing in; tnl prints it once
instead of admitting every visitor from your IP. A guest credential lasts 72 hours
and allows 15 minutes ready or about 5 MiB of traffic across runs. Ctrl+C
stops the demo and removes its public URL. Run `tnl auth login` to publish your own
app. CLI telemetry is on by default, including for the demo. Run
`tnl telemetry off` to disable it.

## start developing

From your project directory, install the NPM package:

```bash
npm install -D @tnldotdev/tnl@next
```

Initialize with the helper:

```bash
npx tnl init
```

`tnl init` creates project configuration and helps connect your framework's
development listener. Your usual development script still starts the app:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    app: { publicURL: {} },
  },
});
```

Then run:

```bash
npx tnl auth login
pnpm dev
npx tnl wait
npx tnl status --scope=local
npx tnl status --scope=server
```

Sign in once with `tnl auth login`. The integration prepares public metadata before
framework startup, then reports the listener's actual bound port to a local
`tnl` process. By default, a visitor needs a current sign-in, share link, or
URL-scoped visitor token. To allow anonymous visitors to a service, set
`publicURL: { access: "anonymous" }` for that service. An additional IP list in
`publicURL: { access: { ip: ["192.0.2.0/24"] } }` limits where credentialed visitors may connect;
an IP match does not replace their credential.

`tnl wait` checks a fresh public response. `tnl status` shows every configured
service, including apps that have not started, without sending a request to the
app. `tnl watch --output ndjson` follows ordered local lifecycle events.

Local publication works in a directory without Git or an origin remote. Its
identity stays with the canonical project directory when you initialize Git,
change the origin, or switch branches. Each separate checkout gets its own local
identity. Portable `tnl apply` and workload generation require a Git source.

One local `tnl` process holds the project's evaluated configuration. After changing
it, stop and restart all of that project's apps and named local publishers
together. Reusing an owner with a different configuration fails with restart
instructions. Each routable public publish run gets one automatic readiness
check with a two-minute retry budget; use `tnl wait` for a fresh check afterward.

Hot reloading works automatically, as well as SSE/websockets/streaming responses.

You can [allow reviewers](https://tnl.dev/docs/publish#who-can-visit) or
declare a stable webhook endpoint when you need one. Provider IPs are only
allowed on the declared webhook path and method.

[Follow the quickstart](https://tnl.dev/docs) or read about
[framework setup](https://tnl.dev/docs/frameworks).

## give your services their own urls

If your project has several services, name them in `tnl.config.ts` and
select the service when preparing each app:

```ts
// tnl.config.ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    web: { publicURL: {} },
    api: { publicURL: {} },
  },
});
```

Pass `service: "web"` or `service: "api"` to your framework integration or
`tnl.prepare()` in each app. Start each service with its normal development
command:

```bash
pnpm --dir apps/web dev
pnpm --dir apps/api dev
npx tnl wait
```

These will have separate URLs:

| service | URL                                                   |
| ------- | ----------------------------------------------------- |
| `web`   | `https://web-example-k7n2p9.ecstatic-penguin.tnl.dev` |
| `api`   | `https://api-example-k7n2p9.ecstatic-penguin.tnl.dev` |

Use the API URL assigned to this project in the frontend:

```ts
import { tnl } from "@tnldotdev/tnl";

const apiURL = tnl.services?.api?.url;
// https://api-example-k7n2p9.ecstatic-penguin.tnl.dev
```

Read about [project configuration](https://tnl.dev/docs/configuration) and
[framework metadata](https://tnl.dev/docs/frameworks#use-a-service-url-in-your-app).
An explicit `publicURL` block enables public HTTPS. Omit it to keep a service
private, including HTTP services; use `tnl connect NAME` to reach a private
service. `protocol` defaults to `http`; `tcp`, `mysql`, and `postgres` describe
private targets. Set `access: { team: true }` on a service to allow the team.
For a Node or Bun API, prepare its service before startup and register the bound
listener. Port 0 lets the application choose an available port:

```ts
import { createServer } from "node:http";
import { tnl } from "@tnldotdev/tnl";

const publication = await tnl.prepare({ service: "api" });
const server = createServer((_request, response) => response.end("hello"));
server.listen(0, "127.0.0.1");
await publication.register(server);
```

Registration acknowledges the listener; `tnl wait` checks public readiness.
See [API server setup](https://tnl.dev/docs/frameworks#api-servers).

## open changes side by side

Create another Git worktree. The project configuration comes with it:

```bash
git worktree add -b perf ../perf
```

Then start the two services:

```bash
pnpm --dir apps/web dev
pnpm --dir apps/api dev
```

The same frontend is now running from two checkouts:

| checkout  | frontend public URL                                        |
| --------- | ---------------------------------------------------------- |
| primary   | `https://web-example-k7n2p9.ecstatic-penguin.tnl.dev`      |
| `../perf` | `https://web-example-perf-m4q8s2.ecstatic-penguin.tnl.dev` |

`tnl` names each URL after the service and project, adding the checkout name
for a linked worktree. A short ID keeps names distinct, and switching branches
leaves the URL unchanged.

For Next.js and Vite, there is no port bookkeeping. If another worktree already
uses the preferred port, the framework can choose another and `tnl` follows the
listener it actually opens. Restarting the same worktree reuses its URL.

See what is running across your local worktrees from any of them:

```bash
npx tnl status --all --scope=local
```

## custom domain

Claim a development subdomain and make it the default for new public URLs:

```bash
npx tnl domain claim dev.example.com --default
npx tnl domain list
```

Delegate the subdomain with the NS records. Then, dev URLs will look like:

```text
https://web-example-k7n2p9.chase.dev.example.com
```

[Use a custom domain](https://tnl.dev/docs/domains).

## self-host

Configure a standard OIDC issuer and server client on control, and set
`TNLD_MANAGED_DOMAIN=routes.example.com`. Sign in through the browser approval flow:

```bash
tnl auth login --server https://control.example.com --open
tnl status --scope=server --server https://control.example.com
tnl publish 3000 --server https://control.example.com --name app
# https://app.alex.routes.example.com
```

Without `--name`, `tnl` uses a stable project-and-worktree name. Personal
teams use a readable label, such as `app.alex.routes.example.com`; members of
the `studio` team use `app.alex.studio.routes.example.com`. A shared hosted
server can set `TNLD_MANAGED_URL_MODE=generated` to assign labels such as
`ecstatic-penguin` instead. Publisher certificate issuance requires DNS-01
automation, including for exact-hostname certificates. Namespace wildcard plans
can reuse DNS and certificates; pointing an exact hostname at ingress alone does
not enable issuance. Managed service endpoints also require a ready team domain
with DNS-01 automation.

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

Named publisher groups can run near services on your private network. Keep
their service declarations in Git, then run `tnl apply` to save a revision in
control. Enrolled publishers pull only their group's assignments and report
their observed revision and health. Starting `pnpm dev` still registers only
the local listener; it does not apply production changes. Cloud capacity and
task replacement belong to your infrastructure. The
[Fargate templates](deploy/publishers/readme.md) show that boundary.

[Run your own server](https://tnl.dev/docs/self-hosting).

## not using typescript/javascript, or don't want config?

You can use Homebrew to install the `tnl` client. Publish an HTTP app
already listening on port 3000 without any configuration:

```bash
brew install tnldotdev/tap/tnl
tnl publish 3000
```

Or install with curl:

```sh
curl -fsSL https://tnl.dev/install | sh
```

For an app that is already running, [use `tnl publish`](https://tnl.dev/docs/publish).

## how much does it cost?

tnl.dev is free for now. Teams have a soft limit of 50 GiB of transfer per
month across their public URLs, counting traffic in both directions.

Accounts and teams created while it is free will keep a free plan
if paid options arrive.

## license

The client and server are licensed under [BSD-3-Clause](LICENSE). See the
[dependency notices](THIRD_PARTY_LICENSES.txt), browse the
[command reference](https://tnl.dev/docs/cli), or [contribute](contributing.md).
