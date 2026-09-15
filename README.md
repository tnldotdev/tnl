# tnl

`tnl` publishes a local HTTP service at a public HTTPS hostname. The publisher
keeps two outbound publisher connections through distinct relay services, and
public route TLS terminates in the publisher before traffic reaches the local
service.

The repository contains:

- `tnl`, the client CLI and publisher.
- `tnld`, the server process for standalone, control, ingress, and relay roles.
- `@tnldotdev/tnl`, the npm launcher, project configuration types, and framework
  integrations for the native client.

## Documentation

| Guide                                        | Owns                                                                  |
| -------------------------------------------- | --------------------------------------------------------------------- |
| [JavaScript package](packages/tnl/README.md) | Next.js, Vite, multi-service configuration, and generated metadata    |
| [Self-hosting](docs/SELF-HOSTING.md)         | Deployment, configuration, current limitations, backups, and upgrades |
| [Observability](docs/OBSERVABILITY.md)       | Health probes, readiness guarantees, metrics, and alerts              |
| [Releases](docs/RELEASES.md)                 | Artifact installation, verification, and publishing                   |
| [Contributing](CONTRIBUTING.md)              | Toolchain, local stack, test tiers, and generated sources             |
| [Architecture](docs/ARCHITECTURE.md)         | Runtime invariants, package ownership, and API boundaries             |

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

The default hostname combines the local service and worktree beneath the current
membership's namespace on the selected team's default domain. Select one child
label or an exact authorized hostname:

```console
tnl publish 3000 --subdomain api
tnl publish 3000 --host api.dev.example.com
```

By default, tnl restricts the route to the visitor IP observed by the control
API. Repeat `--allow-ip` to add addresses or prefixes to that policy, or use
`--public` to allow every visitor address. Add `--open` to launch the public URL
after the route version becomes routable. Use `--output=ndjson` for
machine-readable lifecycle events.

One tunnel owns one current route session with two publisher connection slots
assigned to distinct relay services. A route version becomes routable after its
certificate is installed and both connections are ready. Existing routing may
continue with one ready connection while the publisher replenishes toward two.

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

Each project/service pair uses a deterministic private Unix socket and exclusive lock.
Framework integrations register the actual loopback port without receiving
server access tokens.

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

TypeScript configuration is implicitly version 1 and uses camel-case names.
See the [configuration API](packages/tnl/README.md#configuration) for object and
factory examples, service overrides, and trusted-code evaluation semantics.

Command-line values take precedence over supported `TNL_*` environment values,
which take precedence over project configuration. Run `tnl config path` to see
the selected file without evaluating it, and `tnl config check` to load and
validate it. `tnl config generate` resolves authenticated team/domain context
and writes project metadata; see the package guide for setup and regeneration.

An explicit access token cannot be sent to a server selected only by project
configuration: also supply `--server` or `TNL_SERVER`.

## Machine Output

`tnl publish --output=ndjson` emits one lifecycle event per line on stdout.
Events use `schema_version: 1`; `cursor` increases within that invocation, and
`tunnel_id` identifies the local tunnel. The cursor is not a replay token. The
[event type](cmd/tnl/output.go) is the field reference.

`tnl status --output=json` emits a single
[local tunnel snapshot](internal/clientstate/tunnels.go), not lifecycle events.
It defaults to the current project; add `--all` for every local project.
Prompts and top-level diagnostics go to stderr. Human diagrams are not an
automation interface, and `tnl dev` preserves child output unchanged.

## Telemetry

The CLI sends best-effort pseudonymous usage telemetry to
`https://tnl.dev/api/telemetry` by default, including when using a self-hosted
server. Disable it with `--no-telemetry` or `TNL_NO_TELEMETRY=true`.

The [payload](cmd/tnl/telemetry.go) contains a persistent installation ID stored
in client state, event and command names, client version, OS, architecture, and
whether `CI` is set. Route-start events also classify the server as hosted or
self-hosted and the framework as Next.js, Vite, other, or unspecified. It does
not include command arguments, tokens, route hostnames, local paths, or visitor
traffic. The receiver can observe ordinary network metadata such as the source
IP; receiver-side retention is managed outside this repository.

CLI telemetry is separate from the server's optional
[route-usage delivery](docs/SELF-HOSTING.md#route-usage). Disabling either does
not disable the other.

## License

tnl is available under the [MIT License](LICENSE). Dependency notices are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt).
