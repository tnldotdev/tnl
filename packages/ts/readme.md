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
status contain no credentials. With a Compose publisher, the runtime mounts a
scoped endpoint descriptor for the app; start the app normally.

Read the [quickstart](https://tnl.dev/docs),
[Next.js and Vite setup](https://tnl.dev/docs/frameworks),
[project configuration](https://tnl.dev/docs/configuration), and
[CLI commands](https://tnl.dev/docs/cli) on tnl.dev.

The client enables pseudonymous telemetry by default. Disable it with
`TNL_NO_TELEMETRY=true` or `--no-telemetry`; see the
[telemetry disclosure](https://tnl.dev/docs/cli#telemetry).
