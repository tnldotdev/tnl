# tnl

`tnl` publishes a local HTTP service at a public HTTPS hostname. The publisher
keeps two outbound publisher connections through distinct relay services, and
public route TLS terminates in the publisher before traffic reaches the local
service.

The repository contains:

- `tnl`, the client CLI and publisher.
- `tnld`, the server process for standalone, control, ingress, and relay roles.
- `@tnldotdev/tnl`, the npm launcher for the native client.
- `@tnldotdev/dev`, the private `tnl dev` integration protocol.
- `@tnldotdev/next` and `@tnldotdev/vite`, framework integrations.

## Install

Install the client through Homebrew, a release archive, or npm:

```console
brew install tnldotdev/tap/tnl
pnpm add --save-dev @tnldotdev/tnl
```

Release archives contain `tnl` and `tnld` for macOS and Linux on amd64 and
arm64. Releases also publish checksums, SPDX SBOMs, Sigstore bundles, and a
multi-platform image at `ghcr.io/tnldotdev/tnl`.

See [release installation and verification](docs/RELEASES.md) before running a
downloaded artifact. macOS binaries are not Apple-signed or notarized.

## Publish

Authenticate once, then publish a loopback port or URL:

```console
tnl login https://control.tnl.example.com
tnl publish 3000
```

The default hostname is the current membership's namespace under the selected
team's default domain. Select one child label or an exact authorized hostname:

```console
tnl publish 3000 --subdomain api
tnl publish 3000 --host api.dev.example.com
```

By default, tnl restricts the route to the visitor IP observed by the control
API. Repeat `--allow-ip` to add addresses or prefixes to that policy, or use
`--public` to allow every visitor address. Add `--open` to launch the public URL
after the route version becomes routable. Use `--output=ndjson` for
machine-readable lifecycle events.

One tunnel owns one route session and exactly two publisher connections assigned
to distinct relay services. A route version becomes routable after its
certificate is installed and both connections are ready. Existing routing may
continue with one ready connection while the publisher replenishes toward two.

## Teams And Domains

Routes belong to teams. Each identity has a permanent personal team, and may
belong to organization teams:

```console
tnl team current
tnl team list
tnl team create resend --slug chase
tnl team use resend
```

Manage invitations and memberships with `tnl team invite` and `tnl team
member`. Manage claimed domains independently of routes:

```console
tnl domain claim dev.resend.com --default
tnl domain list
tnl route list
tnl route delete route_0123456789abcdef0123456789abcdef
```

Member routes stay within the publishing membership's namespace. Team admins
may create shared routes and manage ordinary member routes, but cannot publish
inside another member's namespace.

## Development Workflow

`tnl dev` supports a fixed port, framework discovery, optional child
supervision, or both:

```console
tnl dev
tnl dev --port 3000
tnl dev -- pnpm dev
tnl dev --port 3000 -- pnpm dev
```

Each worktree uses a deterministic private Unix socket and exclusive lock.
Framework integrations register the actual loopback port without receiving
server access tokens.

### Next.js

```ts
import { withTnl } from "@tnldotdev/next";

export default withTnl({ reactStrictMode: true });
```

### Vite

```ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/vite";

export default defineConfig({ plugins: [tnl()] });
```

Both integrations remain inert outside `tnl dev`. They only connect the
framework's actual loopback port to `tnl dev`; hostname, policy, server, and
command settings belong in project configuration.

## Project Configuration

`tnl publish` and `tnl dev` discover the nearest `tnl.yml`, `tnl.yaml`,
`tnl.json`, or `tnl.ts`, stopping at the Git worktree root. If more than one
candidate exists in the same directory, select one explicitly with `--config`
or `TNL_CONFIG`. Use `--no-config` to disable discovery.

Static YAML and JSON files require `version: 1` and use snake-case field names:

```yaml
$schema: https://tnl.dev/schema/v1.json
version: 1
tnl:
  tunnel:
    subdomain: api
    allow_ip: [198.51.100.0/24]
  publish:
    target: 3000
  dev:
    command: [pnpm, dev]
    startup_timeout: 90s
```

TypeScript configuration is implicitly version 1 and uses camel-case names:

```ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig(({ worktree }) => ({
  tunnel: { subdomain: worktree.label },
  publish: { target: 3000 },
  dev: { command: ["pnpm", "dev"], startupTimeout: "90s" },
}));
```

The TypeScript factory receives a frozen working directory, sanitized
environment without `TNL_*` or `TNLD_*` values, and Git worktree metadata.
Node.js 22.18 or newer is required to evaluate `tnl.ts`.

Command-line values take precedence over supported `TNL_*` environment values,
which take precedence over project configuration. Run `tnl config path` to see
the selected file without evaluating it, and `tnl config check` to load and
validate it.

## Server Architecture

A `tnld` process has one role:

| Role         | Responsibilities                                                                |
| ------------ | ------------------------------------------------------------------------------- |
| `standalone` | Control, ingress, and two logical relay services against PostgreSQL             |
| `control`    | Control API, self-hosted authority API, durable state, certificates, and admin  |
| `ingress`    | Public visitor acceptance, route policy, relay selection, usage, and forwarding |
| `relay`      | Publisher connections and internal forwarding to local publishers               |

Only control and standalone use PostgreSQL. Split ingress and relay processes
register through the private control API using the shared cluster secret and
remain authorized only while their process run IDs and lease revisions are
current. Publishers prefer QUIC over UDP and race a raw TLS/TCP plus yamux
fallback after a short delay.

Ingress creates exactly one PROXY v2 header and forwards each visitor connection
to one concrete connected relay. The relay preserves the metadata and route TLS
bytes unchanged to the publisher.

See [Self-Hosting](docs/SELF-HOSTING.md) for PostgreSQL, DNS, TLS, cluster
authentication, and backup configuration. See
[Observability](docs/OBSERVABILITY.md) for metrics.

## Standalone Quick Start

The reference Compose deployment expects a migrated PostgreSQL database, public
DNS, TCP and UDP 443, and these required standalone settings:

```text
TNLD_MODE=standalone
TNLD_DATABASE_URL=postgres://...
TNLD_SERVER_DOMAIN=tnl.example.com
TNLD_MANAGED_DEPLOYMENT_DOMAIN=tunnels.example.com
TNLD_ACME_EMAIL=operator@example.com
TNLD_ACME_ACCEPT_TERMS=true
TNLD_LOGIN_TOKEN=tnl_login_...
```

`TNLD_SERVER_DOMAIN` derives `control.tnl.example.com`,
`ingress.tnl.example.com`, and `relay.tnl.example.com`. It is independent from
the managed deployment domain used for public route namespaces. Standalone
obtains exact public control and relay certificates through ACME and requires no
certificate files or cluster secret.

`tnld serve --config /path/to/tnl.yml` loads the static file's `tnld` section;
`TNLD_CONFIG` selects the same file through the environment. `tnld` accepts only
versioned YAML or JSON, performs no discovery, and resolves relative control TLS
certificate and private-key paths from the configuration directory. Use `tnld
config check --config /path/to/tnl.yml` to validate configuration without
starting services.

```console
cd deploy
install -m 0600 .env.example .env
```

Replace every placeholder in `.env`. Generate `TNLD_LOGIN_TOKEN` with `tnld
login-token`, then start the deployment:

```console
docker compose pull
docker compose up -d
curl --fail https://control.tnl.example.com/v1/ready
tnl login https://control.tnl.example.com --token
```

`tnld migrate` is the only schema migration path and reads only
`TNLD_DATABASE_DIRECT_URL`. Serving controls and standalone processes read only
the pooled `TNLD_DATABASE_URL` and require the exact supported schema version.

## Local Stack

The local stack builds this checkout and runs PostgreSQL, Pebble, and one
standalone `tnld` process. It uses `127.0.0.1.nip.io` as the managed deployment
domain and binds every published port to loopback.

```console
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
mise exec -- task local:tnl -- team current
```

`local:trust` modifies the macOS login keychain to trust the local certificate
root used for control, relay, and route TLS. Use `task local:down` to preserve
PostgreSQL state or `task local:reset` to remove trust, containers, volumes, and
`.local` state.

## Development

Tool versions are pinned in `mise.toml`:

```console
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
```

The full validation sequence is:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task generate-check
mise exec -- task format-check
mise exec -- task lint
mise exec -- task test
mise exec -- task go:test-race
mise exec -- task go:test-integration
mise exec -- task build
```

Integration tests require a disposable PostgreSQL server through
`TNL_TEST_POSTGRES_URL`. Fly benchmark execution requires explicit approval and
the repository's benchmark environment gates.

## License

tnl is available under the [MIT License](LICENSE). Dependency notices are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt).
