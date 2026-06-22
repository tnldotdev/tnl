# tnl

public urls for localhost.

tnl is a self-hosted tunnel service. A `tnld` process owns the control API,
hostnames, public TLS ingress, and durable SQLite state. The `tnl` client
publishes one loopback-only HTTP service at a public hostname.

Run a standalone deployment for the smallest setup, or a split deployment with
one stateful edge and a fixed pool of stateless workers.

## Route model

- A **local service** is the HTTP service that an application exposes on the
  publisher's loopback interface.
- A **target** is the loopback port or HTTP URL that tells `tnl` how to reach
  the local service.
- A **publisher** is the `tnl publish` or `tnl dev` process. It accepts tunneled
  connections, terminates route TLS, and sends HTTP to the target.
- A **worker backend** is the server-side forwarding object for one route
  version. It connects public ingress to that route's publisher. A standalone
  `tnld` hosts worker backends itself; a split deployment hosts them in worker
  processes.

A durable route is **enabled** until it is suspended or deleted. It is
**routable** only while its current route version has a ready publisher session
and worker backend. An enabled route can therefore be temporarily unroutable
during publisher startup, process restarts, or worker loss.

The **deployment hostname suffix** is the DNS suffix served by a deployment,
such as `example.com`. A **managed hostname** is claimed exactly one label
beneath that suffix, such as `demo.example.com`. A **custom domain** is a DNS
domain proved and claimed outside that suffix. A **child hostname** is below a
claimed managed hostname or custom domain. A **temporary hostname** is
generated for one publish invocation without `--host`. In all cases,
**hostname** means the complete DNS name used by a route.

## Install

Install a stable release with Homebrew:

```console
brew install tnldotdev/tap/tnl
```

The formula installs both `tnl` and `tnld` on macOS or Linux. Homebrew
packages are published only for stable releases.

For a project-local client during the prerelease series, install the npm
package with the `next` tag:

```console
pnpm add --save-dev @tnldotdev/tnl@next
```

The npm package makes `tnl` available to project scripts on macOS or Linux. It
does not include `tnld`; deploy the server with the release container or install
both commands through Homebrew or a release archive.

Release archives contain `tnl` and `tnld` for macOS and Linux on amd64 and
arm64. Each release also publishes checksums, SPDX SBOMs, a Sigstore bundle,
and a multi-platform daemon image at `ghcr.io/tnldotdev/tnl`.

See [release installation and verification](docs/RELEASES.md) before running a
downloaded artifact. macOS binaries are not Apple-signed or notarized.

## Standalone quick start

A deployment needs one static wildcard DNS record pointing to public ingress:

- `*.example.com` for the control API and public routes on TCP 443.

The reference deployment is under [`deploy`](deploy):

```console
cd deploy
install -m 0600 .env.example .env
```

Set `TNL_IMAGE`, `TNLD_DOMAIN`, and the ACME account values in `.env`, then
start the daemon:

```console
docker compose pull
docker compose up -d
curl --fail https://tnl.example.com/v1/ready
docker compose exec tnld tnl admin server login-token --state-dir /var/lib/tnl
```

The Compose deployment runs the container as a non-root user with a read-only
root filesystem and keeps `/var/lib/tnl` in a named volume. See the complete
[self-hosting guide](docs/SELF-HOSTING.md) for DNS, firewall,
metrics, and backup requirements.

## Publish

A server with browser login enabled can save a revocable control session in the
client's persistent state:

```console
tnl login https://tnl.example.com
tnl publish 3000
```

Add `--open` to launch the public URL in the default browser once it is ready.

The command prints the authorization URL and one-time code to approve. Use
`tnl logout` to revoke and remove the saved session.

For a server without browser login, `tnl login` securely prompts for the login
token printed by the daemon command above and stores a revocable control
session. The client fetches the deployment's stored relay region from the
server API:

```console
tnl login https://tnl.example.com
tnl host claim demo
tnl publish 3000 --host=demo
```

Control sessions have a fixed 30-day lifetime by default. Their one-hour access
tokens rotate automatically. Operators configure these lifetimes with
`TNLD_REFRESH_TOKEN_LIFETIME` and `TNLD_ACCESS_TOKEN_LIFETIME`.

The client keeps profiles, control sessions, route certificates, and local
tunnel lifecycle in one private SQLite database at `<state-dir>/client.db`. On
macOS, `tnl` keeps a profile encryption key in Keychain and encrypts saved access
and refresh tokens and route TLS private keys in the database. On Linux, the
database remains private and user-owned with mode `0600`.

The route becomes available at `https://demo.example.com`. Omitting `--host`
asks the server to generate a temporary hostname for that invocation. A
claimed managed hostname or custom domain authorizes its exact hostname and
child hostnames up to eight labels below it. `localhost:3000` is also accepted
and normalized to the loopback target `http://127.0.0.1:3000`.

Errors produced by the publisher's local proxy include a stable diagnostic code
and a short `tnl.dev/e/...` help URL. Browser requests receive a minimal HTML
wrapper around the plain-text ASCII diagnostic; other clients receive plain
text. HTTP errors returned by the local service pass through unchanged.

Restrict a route to specific visitor addresses or networks with repeatable
`--allow-ip` options. Individual addresses are accepted and converted to host
prefixes. `--allow-current-ip` adds the public address observed by the server
after authentication and prints that address before publishing:

```console
tnl publish 3000 --allow-current-ip
tnl publish 3000 --allow-ip=198.51.100.0/24 --allow-ip=2001:db8::/64
```

The effective list replaces the route's allowlist on every new route version.
Omit both options to allow visitors from any source. ACME certificate
validation remains reachable independently of the visitor allowlist.

Use `tnl host claim`, `tnl host list`, and `tnl host release HOSTNAME` to manage
managed hostnames and custom domains. Releasing a managed hostname stops its
routes and changes its status to inactive, but ownership remains with the same
server-local identity. That identity may claim it again, which restores active
status. Releasing a custom domain stops its routes and changes its status to
available; an identity may claim it only after completing new DNS proof.
Running `tnl host claim` without an argument generates a managed hostname that
remains claimed until released; it is not a temporary hostname.

Query every local tunnel without contacting a server:

```console
tnl status
tnl status --output=json
```

Each `publish` or `dev` invocation receives a randomly generated `tunnel_id`
that is distinct from its server-side `route_id`. The versioned JSON response
reports one observation time, lifecycle counts, and the exact tunnel rows used
for those counts. A tunnel whose local process lease expires is reported as
`stale`, rather than `ready`.

## Telemetry

The `tnl` CLI sends pseudonymous usage telemetry to
`https://tnl.dev/api/telemetry` to understand command adoption and how often
routes become ready on the hosted service versus self-hosted servers. Each
payload contains only `installation_id` (a stable random ID), `event`
(`command` or `route_started`), `command`, optional `server_kind` (`hosted` or
`self_hosted`, only for `route_started`), optional `framework` (`vite`, `next`,
or `other`, only for `tnl dev` routes), `version`, `os`, `arch`, and `ci`. It
does not include arguments, flags, route IDs, hostnames, URLs, targets, errors,
credentials, or timestamps.

Telemetry is retained by the server for 365 days. The source IP is visible in
transit to the endpoint but is not stored in the telemetry table. Disable
telemetry with `--no-telemetry` or `TNL_NO_TELEMETRY=true`; opting out prevents
creation of the installation ID as well as telemetry requests.

## Framework development

`tnl dev` starts a development server and publishes it after the framework has
reported its loopback port. The integration runs only beneath
`tnl dev`, so the project's usual development command remains local.

For Next.js 16.3.4 or newer, install the adapter and update `next.config.ts`:

```console
pnpm add --save-dev @tnldotdev/tnl@next @tnldotdev/next@next
```

```ts
import { withTnl } from "@tnldotdev/next";

export default withTnl({});
```

For Vite 6.0.9 or newer, install the plugin:

```console
pnpm add --save-dev @tnldotdev/tnl@next @tnldotdev/vite@next
```

Add it to `vite.config.ts`:

```ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/vite";

export default defineConfig({
  plugins: [tnl()],
});
```

Both integrations accept tunnel options in project configuration. To give each
Git worktree a predictable URL, first claim one managed hostname:

```console
tnl host claim myapp
```

Then derive a child hostname from the built-in worktree context. The factory is
evaluated only beneath `tnl dev`:

```ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/vite";

export default defineConfig({
  plugins: [
    tnl(({ worktree }) => ({
      host: `${worktree.label}.myapp`,
      allowCurrentIP: true,
    })),
  ],
});
```

`worktree.root` is the Git worktree root, `worktree.name` is its directory name,
and `worktree.label` is a readable DNS-safe identifier with a stable suffix that
prevents same-name worktrees from colliding. Outside Git, the current working
directory is used as a fallback. Vite and Next.js choose their normal listening
ports and report the final port to `tnl`; multiple worktrees therefore do not
need coordinated port assignments.

`allowIP` accepts IP addresses and prefixes; `allowCurrentIP` adds the public
address observed by the selected server. With no `allowIP` entries,
`allowCurrentIP: true` restricts the route to that address only. CLI
`--server`/`TNL_SERVER` and `--host`/`TNL_HOST` override project configuration.
The corresponding `TnlTunnelOptions` fields are `controlURL` and `host`.
Authentication credentials and client state remain controlled by the CLI and
are never sent to project code.

Add one shared project script:

```json
{
  "scripts": {
    "dev:public": "tnl dev -- pnpm dev"
  }
}
```

Ordinary `pnpm dev` remains local. Run the public server with:

```console
pnpm dev:public
```

Use `tnl dev --open -- pnpm dev` to open the public URL once it is ready.

Each developer can select a hostname in their local shell:

```console
export TNL_HOST=chase.example.com
pnpm dev:public
```

Another developer can use `TNL_HOST=john.example.com`. The flag form is:

```console
tnl dev --host chase.example.com -- pnpm dev
```

The selected server-local identity must own a managed hostname or custom domain
with active status. The requested hostname must match it exactly or add no more
than eight labels to its left. A temporary hostname authorizes only itself. An
identity cannot publish beneath a hostname owned by another identity.

For another framework, provide its fixed port:

```console
tnl dev --port=3000 -- pnpm dev
```

The publisher connects only to a loopback HTTP target. HTTP, streaming
responses, and WebSocket hot reload use the public HTTPS URL printed by `tnl`.

## Local development stack

The local development stack builds `tnld` from this checkout and runs it with
Pebble's test ACME service in Docker. It serves the control API at
`https://tnl.localhost` and routes at `https://<hostname>.localhost`. Tailcat
remains an external relay dependency.

Start the services, temporarily trust Pebble's generated issuance root, and
authenticate an isolated local client:

```console
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
```

Run the client from this checkout by passing its arguments after `--`:

```console
mise exec -- task local:tnl -- publish 3000 --host demo
```

Pebble creates a new issuance root when its container is recreated. Run
`task local:untrust` before recreating it, or use `task local:reset` to remove
the trust entry, containers, volumes, and isolated state together. All local
ports bind to `127.0.0.1`; never expose this development CA or ACME service to a
network.

Use `task local:down` to stop the existing containers without rotating Pebble's
root.

## Components

- `internal/api` serves the server HTTP API using the generated contract and
  explicit request and response size limits.
- `internal/auth`, `internal/credentials`, and `internal/state` own server-local
  identities and token storage.
- `internal/naming` validates and normalizes lowercase DNS hostnames.
- `internal/routes`, `internal/ingress`, and `internal/worker` coordinate route sessions and forward public streams.
- `internal/publisher` terminates route TLS and proxies only to a loopback HTTP target.
- `internal/clientstate` owns the shared client SQLite database and local tunnel
  status records.
- `internal/sqlite` owns SQLite connection and migration mechanics shared by client and server state.
- `internal/tailtransport` carries route-session traffic over Tailcat.
- `internal/observability` exports provider-neutral Prometheus metrics.
- `pkg/protocol/serverv1` contains generated Go types for the server API contract.
- `cmd/tnl` and `cmd/tnld` are the client and daemon entry points.

The hosted website and browser-authorization service are maintained separately.
Server contracts and conformance fixtures are under `api`.

## Repository checks

Install the tool versions configured by the repository and run its checks:

```console
brew install mise
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
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

The opt-in complete route-path Fly benchmark is documented in
[`docs/benchmarks`](docs/benchmarks/README.md).
