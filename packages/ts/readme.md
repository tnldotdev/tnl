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

## connect to a service

For local development, sign in and use `await tnl.connect("database")`. Local
connections use the project selected from the current directory.

For a deployed app, generate service facts and select one saved environment
with an explicit visitor identity. For a PostgreSQL service named `database`:

```console
npm install pg
npm install -D @types/pg
npx tnl generate
```

Import the generated facts as runtime data. They supply exact service names and
protocols, not authorization, endpoints, or credentials:

```ts
import { Client } from "pg";
import { readFile } from "node:fs/promises";
import { tnl, type IdentitySource } from "@tnldotdev/tnl";
import { services } from "./.tnl/generated/project.js";

// use the reference and visitor permission approved on your tnl server.
const environment = Object.freeze({
  server: "https://control.example",
  project_key: "catalog",
  environment_id: "env_1234567890123456789012",
});
const identity: IdentitySource = {
  kind: "oidc",
  permission_id: "mwp_1234567890123456789012",
  async assertion(_challenge, signal) {
    return (await readFile("/var/run/secrets/tnl/token", { encoding: "utf8", signal })).trim();
  },
};
const connections = tnl.client({ services, environment, identity });
try {
  const database = new Client({
    ...(await connections.connect("database")),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
  await database.connect();
  try {
    console.log(await database.query("select 1"));
  } finally {
    await database.end();
  }
} finally {
  await connections.close();
}
```

The returned PostgreSQL address points to tnl on your machine:

```text
app --> local tnl --> relay --> publisher --> database
        127.0.0.1
```

tnl supplies the connection address and TLS settings; you supply the database
account. Keep `pg`'s default `enableChannelBinding: false`. Await fresh settings
when creating a replacement client or pool.

Each client captures its environment and identity independently. Closing one
does not change another client or local `tnl.connect`. OIDC assertions must match
the saved visitor permission. A `registered-key` source instead signs the
native challenge's `scope` and `audience` with its registered identity key; the
native session key remains inside tnl. Neither source is a publisher credential.

Connections run in Node or Bun. Deployed apps need this package as a runtime
dependency, including its platform-specific native package. To use prepared
connections in CI, see the [GitHub Action](https://github.com/tnldotdev/tnl/blob/main/connect/readme.md).

The CLI enables pseudonymous telemetry by default. Set `TNL_NO_TELEMETRY=true`
to disable it; see [telemetry](https://tnl.dev/docs/cli#telemetry).
