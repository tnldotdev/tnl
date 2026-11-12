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

const tunnel = await tnl.open(() => new Response("hello"));
console.log(tunnel.url);
await tunnel.wait();
```

`open` waits until the public URL can receive visitors. Keep the tunnel open
while using it; call `await tunnel.close()` during shutdown to remove the URL.
By default, visitors need a current sign-in, share link, or token.

## connect to local postgres

With matching prerelease native and npm builds, `tnl generate` also exports
immutable service facts in `.tnl/generated/services.ts`. Select a local deployment
to connect to a configured loopback PostgreSQL listener without signing in:

```ts
import { createClient } from "@tnldotdev/tnl";
import { services } from "./.tnl/generated/services.js";

const local = createClient({ services }).deployment("local");
const connection = await local.connect("database");
// pass connection to pg, alongside your database credentials.
await local.close();
```

This initial explicit-deployment API supports only local PostgreSQL. It does not
start Docker or publish a tunnel, and it never falls back to a remote service.
See the [local database recipe](https://tnl.dev/docs/private-services#connect-to-local-postgres-without-sign-in)
for Compose port mappings, driver pools, and cleanup. Remote connections still use
the API below.

## connect to a service

Declare your service in project configuration and start its publisher, then sign
in with an identity that can visit it. The [AWS publisher guide](https://tnl.dev/docs/aws-publishers)
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

The CLI enables pseudonymous telemetry by default. Set `TNL_NO_TELEMETRY=true`
to disable it; see [telemetry](https://tnl.dev/docs/cli#telemetry).
