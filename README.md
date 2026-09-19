# tnl

`tnl` gives a local HTTP service a public HTTPS hostname. The publisher opens
outbound connections to two relay services. Route TLS reaches the publisher and
terminates there before traffic is sent to the local service.

The repository contains:

- `tnl`, the client CLI and publisher.
- `tnld`, the server process for standalone, control, ingress, and relay roles.
- `@tnldotdev/tnl`, the npm launcher, project configuration types, and framework
  integrations for the native client.

## Documentation

| Guide                                        | Owns                                                                  |
| -------------------------------------------- | --------------------------------------------------------------------- |
| [CLI reference](docs/CLI-REFERENCE.md)       | `tnl` and `tnld` commands, configuration, output, and side effects    |
| [JavaScript package](packages/tnl/README.md) | Next.js, Vite, multi-service configuration, and generated metadata    |
| [Self-hosting](docs/SELF-HOSTING.md)         | Deployment, configuration, current limitations, backups, and upgrades |
| [Observability](docs/OBSERVABILITY.md)       | Health probes, readiness guarantees, metrics, and alerts              |
| [Releases](docs/RELEASES.md)                 | Artifact installation, verification, and publishing                   |
| [Contributing](CONTRIBUTING.md)              | Toolchain, local stack, test tiers, and generated sources             |
| [Architecture](docs/ARCHITECTURE.md)         | Runtime invariants, package ownership, and API boundaries             |
| [Glossary](docs/GLOSSARY.md)                 | Canonical product, runtime, routing, and security terms               |

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

Authenticate once, then publish a local service port or URL:

```console
tnl login https://control.tnl.example.com
tnl publish 3000
```

By default, tnl builds the hostname from the local service and worktree label.
It places that name in the current member namespace on the team's default
domain. You can instead choose one child label or an authorized hostname:

```console
tnl publish 3000 --subdomain api
tnl publish 3000 --host api.dev.example.com
```

By default, only the IP address seen by the control API may use the route.
Repeat `--allow-ip` to allow more addresses or prefixes. Use
`--allow-all-ips` to allow all addresses. Add `--open` to open the public URL
when the route is ready. Use `--output=ndjson` for machine-readable status
events.

Each tunnel starts one route session. Control assigns its two connection slots
to different relay services. The route becomes routable after the publisher
installs its certificate and both connections are ready. After that, the route
can continue with one connection while the publisher replaces the other.

## Teams And Domains

Routes belong to teams. Each identity has a permanent personal team, and may
belong to organization teams:

```console
tnl team current
tnl team list
tnl team create resend --member-slug chase
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

Each project service uses a private Unix socket and lock to prevent duplicate
`tnl dev` processes. Framework integrations report the actual local service port.
They never receive server access tokens.

Run `tnl init` for project setup. Follow the
[package guide](packages/tnl/README.md) for framework integration, named services,
and browser-safe project metadata. Builds and previews remain inert.

## Project Configuration

`tnl publish` and `tnl dev` discover the nearest `tnl.yml`, `tnl.yaml`,
`tnl.json`, or `tnl.config.ts`, stopping at the Git worktree root. If more than one
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

TypeScript configuration is version 1 and uses camel-case names. It runs as
trusted local code. See the
[configuration API](packages/tnl/README.md#configuration) for object and factory
examples and project-service overrides.

Command-line values override supported `TNL_*` environment variables. Those
variables override project configuration. Run `tnl config path` to show the
selected file without evaluating it. Run `tnl config check` to load and validate
the file. `tnl config generate` uses the current team and domain to write project
metadata; see the package guide for setup and regeneration.

When you provide an access token, you must also select the control URL with
`--server` or `TNL_SERVER`. The client will not send an explicit token to a
control URL found only in project configuration.

## Machine Output

`tnl publish --output=ndjson` writes one status event per line on stdout. Events
use `schema_version: 1`. The `cursor` increases during one command invocation,
but it cannot be used to replay events. The `tunnel_id` identifies the local
tunnel. The [event type](cmd/tnl/output.go) lists all fields.

`tnl status --output=json` writes one
[local tunnel snapshot](internal/clientstate/tunnels.go), not a stream of events.
It shows the current project by default; add `--all` to include every local
project. Prompts and top-level diagnostics go to stderr. Human-readable diagrams
are not an automation interface. `tnl dev` passes child output through unchanged.

## Telemetry

By default, the CLI sends pseudonymous usage telemetry to
`https://tnl.dev/api/telemetry`, even when you use a self-hosted server. Delivery
is best effort. Disable it with `--no-telemetry` or `TNL_NO_TELEMETRY=true`.

The [payload](cmd/tnl/telemetry.go) includes an installation ID stored in client
state, event and command names, client version, OS, architecture, and whether
`CI` is set. Route-start events also identify the server as hosted or self-hosted
and the framework as Next.js, Vite, other, or unspecified. The payload does not
include command arguments, tokens, route hostnames, local paths, or visitor
traffic. As with any HTTP request, the receiver can see network information such
as the source IP. Its retention policy is managed outside this repository.

CLI telemetry is separate from the server's optional
[route-usage delivery](docs/SELF-HOSTING.md#route-usage). Disabling either does
not disable the other.

## License

tnl is available under the [MIT License](LICENSE). Dependency notices are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt).
