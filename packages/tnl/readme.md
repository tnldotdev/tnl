# `@tnldotdev/tnl`

The tnl client, plus official Next.js and Vite integrations for project-local
development. Available for macOS and Linux on arm64 and x64 with Node.js 22.18
or newer. The package selects a native binary through optional dependencies;
it does not install the `tnld` server.

```console
npm install -D @tnldotdev/tnl@next
npx tnl init
npx tnl auth login
npx tnl dev
```

`tnl init` sets up missing project and framework configuration and lists any
actions required for existing files. Sign in explicitly; hosted tnl.dev is
the default server. Each Git worktree gets its own HTTPS URL.

Read the [quickstart](https://tnl.dev/docs),
[Next.js and Vite setup](https://tnl.dev/docs/frameworks),
[project configuration](https://tnl.dev/docs/configuration), and
[CLI commands](https://tnl.dev/docs/cli) on tnl.dev.

The client enables pseudonymous telemetry by default. Disable it with
`TNL_NO_TELEMETRY=true` or `--no-telemetry`; see the
[telemetry disclosure](https://tnl.dev/docs/cli#telemetry).
