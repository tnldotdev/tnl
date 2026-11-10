# `@tnldotdev/tnl`

Give your app an HTTPS URL, or connect it to a private service through tnl.
Includes the tnl CLI and Next.js and Vite integrations. Supports Node.js 22.18+
on macOS and Linux, arm64 and x64.

## start developing

```console
npm install -D @tnldotdev/tnl@next
npx tnl init
npx tnl auth login
npm run dev
```

`tnl init` sets up project and framework configuration, or tells you what to
change in existing files. Start your app with its usual development script.
Each Git worktree gets its own public URL; restarting the app reuses it.
Run `npx tnl wait` in another terminal to check when it can receive visitors.

## publish a node or bun app

Declare an app service in `tnl.config.ts`:

```ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    api: { publicURL: {}, target: { type: "app" } },
  },
});
```

Prepare that service, then register your HTTP server. For example, in Node:

```ts
import { createServer } from "node:http";
import { tnl } from "@tnldotdev/tnl";

const publication = await tnl.prepare({ service: "api" });
const server = createServer((_request, response) => response.end("hello"));
server.listen(0, "127.0.0.1");
await publication.register(server);
console.log(publication.publicURL);
```

Port `0` lets the OS choose a free port. Run from your project directory;
`service` selects an entry in its configuration. Registration reports the local
listener; `npx tnl wait` checks public readiness. Restart the project's apps
together after changing configuration.

For a temporary URL without project configuration, first run
`npx tnl publisher setup --namespace` after signing in:

```ts
import { tnl } from "@tnldotdev/tnl";

const tunnel = await tnl.publish(() => new Response("hello"));
console.log(tunnel.url);
await tunnel.finished();
```

`publish` waits until the public URL can receive visitors. Keep the tunnel open
while using it; call `await tunnel.close()` during shutdown to remove the URL.
By default, visitors need a current sign-in, share link, or token.

`wait()` requests fresh application readiness; `wait({ until: "routable" })`
waits only for traffic routing. `status()` reads without probing, and `watch()`
resumes native events using exclusive cursors. `finished()` waits for termination.
Cancelling a wait or watch does not stop the publication. `prepare().register()`
returns the same publication handle without blocking listener startup on readiness.

## connect to a service

Declare your service in project configuration and start its publisher, then sign
in with an identity that can visit it. The [AWS publisher guide](https://github.com/tnldotdev/tnl/blob/main/deploy/publisher/fargate/readme.md)
shows one way to run a publisher beside your database. For a PostgreSQL service
named `database`:

```console
npm install pg
npm install -D @types/pg
npx tnl generate
```

Include `.tnl/generated/project.d.ts` in your TypeScript configuration for typed
service names and connection settings. Then use the settings with your driver:

```ts
import { Client } from "pg";
import { tnl } from "@tnldotdev/tnl";

const client = new Client({
  ...(await tnl.connect("database")),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
await client.connect();
console.log(await client.query("select 1"));
await client.end();
```

The returned PostgreSQL address points to tnl on your machine:

```text
app --> local tnl --> relay --> publisher --> database
        127.0.0.1
```

tnl supplies the connection address and TLS settings; you supply the database
account. Keep `pg`'s default `enableChannelBinding: false`. Await fresh settings
when creating a replacement client or pool.

Connections run in Node or Bun. Deployed apps need this package as a runtime
dependency, including its platform-specific native package. To use prepared
connections in CI, see the [GitHub Action](https://github.com/tnldotdev/tnl/blob/main/connect/readme.md).

Use `createTnl` for independently owned connection scopes. Each instance pins its
project directory, server, and client state selection without changing process-wide
configuration:

```ts
import { createTnl } from "@tnldotdev/tnl";
import { Pool } from "pg";

const app = createTnl({ directory: "/srv/checkout" });
const getDb = app.client("database", {
  create: (connection) => new Pool({ ...connection, user: "checkout" }),
  close: (pool) => pool.end(),
});

try {
  const db = await getDb();
  await db.query("select 1");
} finally {
  await app.close();
}
```

Each getter selects current access and reuses the client for that exact connection
binding. Renewing expiration alone does not replace a pool. Instance cleanup closes
its factories before stopping its native owners; other instances keep running.
Supply `credential: { workload: "deploy" }` to select a named workload's built-in
provider acquisition. An explicit `token` callback or `tokenFile` belongs inside
that same credential object. Provider callbacks read the current request; they
are not background refresh sources. The former top-level `workload` constructor
option is rejected.

## fetch with an explicit visitor token

Use the Fetch-only entry point in a server runtime without native processes:

```ts
import { createTnl } from "@tnldotdev/tnl/web";

const app = createTnl({ credential: env.TNL_CREDENTIAL });
const api = app.connect("https://preview.example.com");
const response = await api.fetch("/stock", {
  headers: { Authorization: `Bearer ${applicationToken}` },
});

// during application shutdown, after using the response body
await app.close();
```

Store the token printed by `tnl share token create` or `tnl share service token
create` in a server-side secret. Do not put it in browser code. The web entry
requires an explicit HTTPS origin and a visitor token; it does not select named
services, enroll an identity, publish, or connect to databases. The native
`createTnl` accepts the same explicit-token HTTP form without falling back to a
personal session.

`fetch` returns the standard response, preserves application headers and bodies,
and sends the tnl credential separately. It does not follow redirects, send
ambient browser credentials, retry a request, or switch identities. `client(url,
{ create, close })` reuses the same ordinary client factory as native connections.
Close the instance when its work ends; cleanup cancels its remaining Fetch calls
and response streams after closing its clients. Failed client cleanup remains
retryable. See [HTTP runtimes](https://tnl.dev/docs/serverless-http) for the current
boundaries and platform qualification requirements.

The CLI enables pseudonymous telemetry by default. Set `TNL_NO_TELEMETRY=true`
to disable it; see [telemetry](https://tnl.dev/docs/cli#telemetry).
