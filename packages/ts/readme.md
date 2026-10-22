# `@tnldotdev/tnl`

The tnl client, plus official Next.js and Vite integrations for project-local
development. Available for macOS and Linux on arm64 and x64 with Node.js 22.18
or newer. The package selects a native binary through optional dependencies;
it does not install the `tnld` server.

```console
npm install -D @tnldotdev/tnl@next
npx tnl init
npx tnl auth login
pnpm dev
npx tnl wait
```

`tnl init` sets up missing project and framework configuration and lists any
actions required for existing files. Start the app with its normal development
script. Its integration prepares metadata and reports the bound listener to a
local tnl publisher process. Hosted tnl.dev is the default server. Each Git
worktree gets its own HTTPS URL; restarting an app reuses that URL.

Local publication also works without Git or an origin. Its identity belongs to
the canonical project directory and survives Git initialization, origin changes,
and branch switches. After editing project configuration, stop and restart all
apps and named local publishers for that project together so they use one
evaluated configuration. An owner with a different configuration rejects reuse.

Node and Bun applications use `await tnl.prepare()`, then
`await publication.register(server)` on the returned handle. Select a service
with `tnl.prepare({ service: "api" })` when the project has more than one app
service. The working directory selects the project, not the service. Registering
a listener acknowledges local ownership; `tnl wait` checks public readiness.

For a temporary public URL from a Fetch handler, set up a namespace publisher
once, then start the handler:

```console
tnl publisher setup --namespace
```

```ts
import { tnl } from "@tnldotdev/tnl";

const tunnel = await tnl.open(() => new Response("hello"));
console.log(tunnel.url);
await tunnel.close();
```

The native publisher selects the locally provisioned namespace identity, or
`TNL_PUBLISHER_FILE` if set. For programmatic selection, pass
`{ publisherFile: "/absolute/private/publisher.json" }` or
`{ publisherID: "pub_..." }`. An invalid selected file is an error; tnl does
not silently use another identity. Enrollment keys belong to setup, not the
SDK. The native publisher keeps its signing key private; project metadata and
status contain no credentials.

## native connections

Use `tnl.connect` from Node or Bun to reach a configured service:

```ts
import { tnl } from "@tnldotdev/tnl";

const database = tnl.connect("database");
const settings = await database;
const credentials = {
  ...settings,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};
```

The immediate handle is awaitable. Awaiting prepares only the requested service
and returns a plain, read-only settings snapshot. PostgreSQL settings contain
`host: "127.0.0.1"`, the actual local `port`, and
`ssl: { servername, rejectUnauthorized: true, ca? }`. MySQL settings use the managed
hostname, `ssl.verifyIdentity: true`, and a `stream` factory that dials loopback;
each returned MySQL `ssl` object remains mutable for ordinary driver setup.
The native connector owns
admission and client certificates, including for public services. The application
supplies its database account settings. `tnl.services` keeps the managed hostname
and public port.

Every protocol requires the matching native `tnl` binary, including HTTP and
Kubernetes. Package its platform dependency with deployed server code; a managed
HTTPS URL alone does not replace the native owner or authorize a connection.

Property reads and `{ ...database }` work synchronously after a human connection's
awaited preparation in this process, or when `TNL_CONNECTION_HANDLE` selects a
prepared native owner. A handle captures an explicitly supplied file when created;
later changes to that environment variable do not rebind it.
This supports an ordinary Drizzle Kit config without top-level await:

```ts
import { tnl } from "@tnldotdev/tnl";
import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  dbCredentials: {
    ...tnl.connect("database"),
    user: process.env.DB_USER!,
    password: process.env.DB_PASSWORD!,
    database: process.env.DB_NAME!,
  },
});
```

Generate project declarations with `tnl generate` for exact service names and
protocol-specific results. Without declarations, narrow the returned protocol
union before using protocol-specific settings. Synchronous reads validate the
prepared owner and its service scope; they never start an owner or
sign in. An unprepared read fails with `sdk.connection_unprepared`.

Each spread reads one coherent snapshot. Await the handle again to revalidate
the owner and expiry before creating a new client; an existing driver keeps its
previous snapshot. The awaitable `then` method is nonenumerable, and expiry and
protocol bookkeeping are not driver options.

An SDK-started human owner follows the application's lifetime. Renewal keeps its
listener stable. Workload session deadlines remain separate from owner lifetime.
If the native process dies early, an await recovers only after native proves its
lifetime lock is released. A failed or denied read from a live owner keeps that
owner; it never starts a second listener. Expired synchronous reads require an
await for fresh settings.

Existing top-level settings remain frozen snapshots; mysql2's SSL copy stays
mutable for its driver. Drain and recreate database pools or connections with
newly awaited settings; tnl does not update an existing pool or replay SQL.
Owners supplied through `TNL_CONNECTION_HANDLE` stay caller-owned,
including fixed-deadline workload sessions. Their caller must prepare and supply
a fresh owner after expiry; the SDK never stops or replaces them.

HTTP settings contain `{ url, fetch }`. The URL retains the managed HTTPS origin;
the SDK's origin-restricted `fetch` dispatcher dials the native loopback listener
with verified TLS and the managed SNI and Host. Workload protocols use this same
native owner, as described below.
TCP returns `{ host, port }`; Kubernetes returns
`{ server, kubeconfig, context }`. Browser connection reads and awaits fail with
`sdk.connection_server_only`.

## provider workload connections

In a Node provider runtime, package the `.tnl/generated/workloads.json` produced by
`tnl generate` and the matching native package beneath the process working directory and select the saved policy
with `TNL_WORKLOAD`. A unique workload matching the runtime provider can also be
selected automatically. Then await a configured service inside
the request:

```ts
import { tnl } from "@tnldotdev/tnl";

export async function GET() {
  const inventory = await tnl.connect("inventory");
  return inventory.fetch("/stock");
}
```

Each await acquires the current provider assertion. Control verifies its identity
before the SDK selects a shared native owner. Rotating assertions attach through
authenticated native IPC; different services share that owner and prepare lazily.
HTTP returns a readonly `{url, fetch}` snapshot. Each fetch resolves the current
verified owner, preserves application `Authorization`, streams bodies, and returns
redirects without following or replaying them.

Keep the awaited settings for that request. A module-shared workload handle has no
synchronous current caller: its property reads and spreads fail with
`sdk.connection_unprepared`, even after an await. An explicit prepared
`TNL_CONNECTION_HANDLE` supports synchronous settings within that owner's scope.
The SDK never treats the last completed request as the next caller's identity.

Generic OIDC callbacks register a fixed request-scoped source during server setup,
before creating connection handles:

```ts
import { configureWorkload } from "@tnldotdev/tnl/workload";
import { requestContext } from "./request-context.js";

configureWorkload({
  name: "worker",
  token: async () => requestContext.getStore().platformAssertion(),
});
```

The callback runs for each request; it must read the current caller's context.
Acquisition stops waiting after ten seconds, including when a callback never
settles. A token returned after that deadline cannot start or select an owner.
`{name, tokenFile}` selects an explicit bounded file that is reread each time.
Issuer trust and permissions come from control's saved workload policy.

HTTP uses the same native owner as the other protocols. The SDK owns its Undici
transport on Node and Bun; it never falls back to dialing the managed address
directly. Canceling a request while preparing its connection releases the upload
body. Browser metadata remains address-only; absent optional services return
`undefined`, and the workload configuration subpath is server-only.

Connection preparation is not a lasting access grant. HTTP responses and
WebSocket upgrades retain live authorization, as do database streams. A new
assertion or session can authorize future connections; it cannot extend an old
stream's original session deadline or replay its application traffic.

Read the [quickstart](https://tnl.dev/docs),
[Next.js and Vite setup](https://tnl.dev/docs/frameworks),
[project configuration](https://tnl.dev/docs/configuration), and
[CLI commands](https://tnl.dev/docs/cli) on tnl.dev.

The client enables pseudonymous telemetry by default. Disable it with
`TNL_NO_TELEMETRY=true` or `--no-telemetry`; see the
[telemetry disclosure](https://tnl.dev/docs/cli#telemetry).
