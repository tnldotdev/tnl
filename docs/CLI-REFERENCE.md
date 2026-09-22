# CLI Reference

This document is the practical command reference for the `tnl` client and the
`tnld` server process. It describes the implemented command trees,
configuration precedence, output contracts, local and remote side effects, and
long-running behavior.

All identifiers, domains, addresses, paths, tokens, and timestamps in examples
are illustrative. Domains use the reserved `.test` suffix, public IP addresses
use documentation ranges, local targets use addresses on this computer, private
listeners use private-use ranges, and credential-like values are not valid
secrets.

## tnl

`tnl` publishes local HTTP services at stable public URLs and manages the
teams, domains, and routes used by those tunnels.

### Placeholder Legend

| Placeholder              | Meaning                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------ |
| `<service>`              | A configured local service name such as `web`.                                             |
| `<service-or-target>`    | A configured service name, a port, `localhost:<port>`, or an HTTP origin on this computer. |
| `<server>`               | A control URL.                                                                             |
| `<team>`                 | A team ID or an unambiguous display name.                                                  |
| `<display-name>`         | A new organization team's display name.                                                    |
| `<member-slug>`          | An immutable lowercase member slug.                                                        |
| `<invitation-id>`        | A team invitation ID.                                                                      |
| `<secret>`               | A one-time invitation credential. Treat it as a secret.                                    |
| `<membership-id>`        | A membership ID returned by `tnl team members`.                                            |
| `<domain>`               | A domain name, or where documented, a domain ID.                                           |
| `<route-id>`             | A route ID returned by `tnl route list`.                                                   |
| `<relay-id>`             | A relay process identity returned by `tnl admin relays list`.                              |
| `<name>`                 | A maintenance control name.                                                                |
| `[flags]`                | Global flags plus flags shared by or specific to the command.                              |
| `-- <command> [args...]` | The `tnl dev` child command. Everything after `--` is passed to the child.                 |

Angle brackets indicate required arguments. Square brackets indicate optional
arguments. Literal fake IDs in examples use all-zero bodies so they cannot be
mistaken for live values.

### Output Conventions

Human-readable results use a shared ASCII diagram renderer:

```text
+--[ tnl command ]-- state ------------------------------------+
|                                                              |
|  fields, flows, trees, or sections                           |
|                                                              |
+-- optional action, hint, or diagnostic code -----------------+
```

Frames adjust to their command, state, and footer, but never exceed 72 columns.
They are normally 64 columns wide. Values wrap instead of being cut off. The
renderer escapes control bytes and non-ASCII input and never writes ANSI control
sequences. A healthy flow uses `v`; a diagnostic uses `x` where the failure
occurred.

Commands that finish write successful results to stdout. Prompts, tunnel status,
warnings, and errors go to stderr. Important exceptions are:

- Human `tnl publish` and `tnl dev` lifecycle frames go to stderr because both
  commands are long-running.
- `tnl dev` preserves its child process's stdin, stdout, and stderr. Child
  output can therefore be interleaved with tnl lifecycle output.
- `tnl publish --output=ndjson` writes NDJSON events to stdout.
- `tnl status --output=json` writes one JSON object to stdout.
- `tnl team invite create` writes one raw tab-separated credential line to
  stdout.
- `tnl version` writes one raw version line to stdout.
- Generated help is unframed.

Top-level errors are normally rendered once to stderr. If a `tnl dev` child
exits nonzero, `tnl` exits with the child's status without adding another error
frame. On SIGINT or SIGTERM, a long-running command begins graceful shutdown;
a second signal restores immediate termination. `tnl dev` sends SIGTERM to the
child process group and sends SIGKILL if it has not stopped after five seconds.

### Command Index

The `tnl` command tree has 33 leaf commands.

|   # | Syntax                                                                                          | Purpose                                                |
| --: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
|   1 | `tnl init [flags]`                                                                              | Set up tnl for the current project.                    |
|   2 | `tnl dev [<service>] [flags] [-- <command> [args...]]`                                          | Run and publish one development service.               |
|   3 | `tnl publish [<service-or-target>] [flags]`                                                     | Publish one existing local HTTP service.               |
|   4 | `tnl status [flags]`                                                                            | Show local tunnel processes.                           |
|   5 | `tnl login [<server>] [flags]`                                                                  | Authenticate to a tnl server.                          |
|   6 | `tnl config path [flags]`                                                                       | Show the selected project configuration path.          |
|   7 | `tnl config check [flags]`                                                                      | Validate the selected project configuration.           |
|   8 | `tnl config generate [flags]`                                                                   | Generate project metadata and TypeScript declarations. |
|   9 | `tnl team current [flags]`                                                                      | Show the effective team.                               |
|  10 | `tnl team list [flags]`                                                                         | List current memberships.                              |
|  11 | `tnl team use <team> [flags]`                                                                   | Save a team selection.                                 |
|  12 | `tnl team create --member-slug=STRING <display-name> [flags]`                                   | Create and select an organization team.                |
|  13 | `tnl team members [flags]`                                                                      | List memberships for a team.                           |
|  14 | `tnl team invite create --member-slug=STRING [flags]`                                           | Create a one-time invitation.                          |
|  15 | `tnl team invite list [flags]`                                                                  | List team invitations.                                 |
|  16 | `tnl team invite revoke <invitation-id> [flags]`                                                | Revoke an invitation.                                  |
|  17 | `tnl team join <secret> [flags]`                                                                | Accept an invitation.                                  |
|  18 | `tnl team member set-role --role=STRING <membership-id> [flags]`                                | Change a membership role.                              |
|  19 | `tnl team member remove <membership-id> [flags]`                                                | Remove a membership.                                   |
|  20 | `tnl domain claim <domain> [flags]`                                                             | Claim a domain.                                        |
|  21 | `tnl domain default <domain> [flags]`                                                           | Set the default domain.                                |
|  22 | `tnl domain list [flags]`                                                                       | List available team domains.                           |
|  23 | `tnl domain release <domain> [flags]`                                                           | Release a claimed domain.                              |
|  24 | `tnl route list [flags]`                                                                        | List routes.                                           |
|  25 | `tnl route delete <route-id> [flags]`                                                           | Delete a route.                                        |
|  26 | `tnl logout [flags]`                                                                            | Revoke and remove the saved control session.           |
|  27 | `tnl admin server status [flags]`                                                               | Show control, ingress, and relay status.               |
|  28 | `tnl admin relays list [flags]`                                                                 | List relay process leases.                             |
|  29 | `tnl admin relays drain --relay-run-id=STRING --relay-lease-revision=INT-64 <relay-id> [flags]` | Drain one matching relay lease.                        |
|  30 | `tnl admin maintenance list [flags]`                                                            | List maintenance controls.                             |
|  31 | `tnl admin maintenance allow <name> [flags]`                                                    | Allow the selected operation.                          |
|  32 | `tnl admin maintenance block <name> [flags]`                                                    | Block the selected operation.                          |
|  33 | `tnl version [flags]`                                                                           | Print release version information.                     |

### Global Flags

These flags are accepted by every leaf command. Some commands accept project
configuration flags through generated help but do not use project
configuration; those exceptions are called out under Configuration Selection.

| Flag              | Default | Environment                  | Behavior                                                                 |
| ----------------- | ------- | ---------------------------- | ------------------------------------------------------------------------ |
| `-h`, `--help`    | false   | None                         | Show context-sensitive, unframed help.                                   |
| `--config=STRING` | unset   | `TNL_CONFIG` is the fallback | Select an explicit project configuration file.                           |
| `--no-config`     | false   | None                         | Do not search for project configuration. Cannot be used with `--config`. |
| `--no-telemetry`  | false   | `TNL_NO_TELEMETRY`           | Disable pseudonymous usage telemetry.                                    |

Telemetry is enabled by default after the command is parsed. It reports a stable
pseudonymous installation ID, command name, release version, OS, architecture,
and whether `CI` is set. When a tunnel becomes ready, it also reports `publish`
or `dev`, whether the server is hosted or self-hosted, and `vite`, `next`,
`other`, or no framework. It never reports route hostnames, targets, team names,
or credentials. Telemetry can create the client-state database for a command
that otherwise only reads data. On exit, the process waits up to 500 milliseconds
for telemetry.

### Shared Remote Flags

These flags are used by `publish`, `dev`, every `team`, `domain`, `route`, and
`admin` leaf:

| Flag                    | Parser default | Effective fallback                                                                     |
| ----------------------- | -------------- | -------------------------------------------------------------------------------------- |
| `--server=STRING`       | empty          | `TNL_SERVER`, applicable project server, saved server, then `https://control.tnl.dev`. |
| `--access-token=STRING` | empty          | `TNL_ACCESS_TOKEN`, then a saved login or interactive authentication.                  |
| `--state-dir=STRING`    | empty          | `TNL_STATE_DIR`, then the platform user configuration directory plus `tnl`.            |

A control URL must use HTTPS and cannot contain credentials, a query, a fragment,
or a non-root path. Hostnames are lowercased, and an explicit port 443 is removed.

An explicit access token bypasses saved-session authentication. If project
configuration is the only source of the server, an explicit token is rejected;
provide `--server` or `TNL_SERVER` so the credential's destination is explicit.

`logout` has `--server` and `--state-dir`, but no access-token flag. `login` has
its own server and state flags. `status`, `config check`, and `config generate`
expose only `--state-dir`.

### Shared Tunnel Flags

These flags are used by `publish` and `dev`:

| Flag                  | Default and environment        | Behavior                                                                                                                              |
| --------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `--open`              | false; no environment variable | Open the first ready public URL in the default browser.                                                                               |
| `--team=STRING`       | empty; `TNL_TEAM`              | Team ID or unambiguous display name. Does not persist an invocation override.                                                         |
| `--host=STRING`       | empty; `TNL_HOST`              | Publish one complete, normalized hostname.                                                                                            |
| `--subdomain=STRING`  | empty; `TNL_SUBDOMAIN`         | Publish one label beneath the current member namespace.                                                                               |
| `--allow-ip=VALUE`    | empty; no environment variable | Add a visitor IP address or prefix. Repeat at most 63 times.                                                                          |
| `--allow-all-ips`     | false; `TNL_ALLOW_ALL_IPS`     | Allow visitors from every IP address.                                                                                                 |
| `--ephemeral`         | false; `TNL_EPHEMERAL`         | Request route cleanup when this tunnel stops.                                                                                         |
| `--request-limit=INT` | `500`; `TNL_REQUEST_LIMIT`     | Maximum concurrent requests forwarded by this publisher route. Must be positive; includes streaming responses and WebSocket upgrades. |

`--host` and `--subdomain` are mutually exclusive. `--allow-all-ips` and
`--allow-ip` are mutually exclusive. Without `--allow-all-ips`, the current
client IP is always added to the policy, including when explicit prefixes are
supplied. Boolean false forms such as `--allow-all-ips=false` and
`--ephemeral=false` are explicit overrides and prevent project configuration
from enabling the value.

### Runtime Environment

These ambient or child-process variables affect behavior but are not additional
CLI configuration flags:

| Variable               | Behavior                                                                                                          |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `CI`                   | Reported only as a boolean in telemetry.                                                                          |
| `XDG_RUNTIME_DIR`      | Preferred parent for the private `tnl dev` socket and lock directory; the OS temporary directory is the fallback. |
| `TNL_DEV_PROTOCOL=1`   | Injected into the `tnl dev` child for framework integration.                                                      |
| `TNL_DEV_SOCKET`       | Injected private framework-registration socket path.                                                              |
| `TNL_DEV_PORT`, `PORT` | Injected or replaced with the literal port when `--port` is supplied.                                             |
| `NO_COLOR=1`           | Added to a package-manager child started by `tnl init`.                                                           |

Before starting a `tnl dev` child, tnl removes inherited `TNL_DEV_*` values and
then adds its controlled values. It also removes `TNL_ACCESS_TOKEN`,
`TNL_LOGIN_TOKEN`, `TNL_PROJECT_RUNTIME`, `TNL_TUNNEL_ID`,
`TNL_PUBLIC_HOSTNAME`, and `TNL_PUBLIC_URL`. Credentials and stale tunnel
metadata are therefore not passed to the local service through these variables.

### Configuration Selection And Precedence

Project configuration selection is:

```text
--no-config
   x  disables all project configuration

--config
   v
TNL_CONFIG
   v
nearest recognized project configuration
```

Recognized discovered names are `tnl.yml`, `tnl.yaml`, `tnl.json`, and
`tnl.config.ts`. Discovery starts in the current directory and stops at the Git
worktree root. Outside a Git worktree it checks only the current directory. More
than one recognized file in the same directory is an error. An explicitly
selected TypeScript configuration must be named exactly `tnl.config.ts`.

Static YAML and JSON documents require `version: 1` and place client settings
under `tnl`. TypeScript configuration evaluates directly to the tnl project
settings. Root settings are inherited by named services; a service overrides
root settings field by field.

| Project setting  | Fields                                                                         |
| ---------------- | ------------------------------------------------------------------------------ |
| Root and service | `server`, `team`, `tunnel`, `publish`, `dev`                                   |
| Service only     | `directory`, relative to the project configuration                             |
| `tunnel`         | `host`, `subdomain`, `allow_ip`, `allow_all_ips`, `ephemeral`, `request_limit` |
| `publish`        | `target`                                                                       |
| `dev`            | `command`, `port`, `startup_timeout`                                           |

The effective runtime precedence is:

| Setting             | Highest to lowest precedence                                                                  |
| ------------------- | --------------------------------------------------------------------------------------------- |
| Server              | `--server`, `TNL_SERVER`, service/root project server, saved server, hosted default           |
| Access token        | `--access-token`, `TNL_ACCESS_TOKEN`, saved session, interactive login                        |
| Tunnel team         | `--team`, `TNL_TEAM`, service/root project team, saved team, personal team                    |
| Publish target      | Positional non-service target, service/root `publish.target`                                  |
| Dev command         | Tokens after `--`, service/root `dev.command`, no child command                               |
| Dev port            | Nonzero `--port`, service/root `dev.port`, framework registration                             |
| Dev startup timeout | Nonzero `--startup-timeout`, service/root value, `2m`                                         |
| Hostname unit       | CLI host/subdomain, environment host/subdomain, project host/subdomain, built-in selection    |
| IP policy unit      | CLI all-IP/allow list, `TNL_ALLOW_ALL_IPS`, project all-IP/allow list, current-IP-only policy |
| Ephemeral           | Explicit CLI value, presence of `TNL_EPHEMERAL`, project value, false                         |
| Request limit       | `--request-limit`, `TNL_REQUEST_LIMIT`, service/root `tunnel.request_limit`, `500`            |

TypeScript configuration uses `tunnel.requestLimit`. This publisher request
budget is shared across HTTP/1.1 connections and HTTP/2 streams for one route;
it is independent of the ingress visitor-connection limit. Excess requests
receive HTTP 503 with `Retry-After: 1` and `TNL_REQUEST_REJECTED` before reaching
the local service. See [publisher HTTP limits](SELF-HOSTING.md#publisher-http-limits)
for upload deadlines and streaming behavior.

Host and subdomain are chosen together: selecting one clears a lower-priority
value for the other. The same rule applies to all-IP and allow-list settings.
For example, CLI `--subdomain` clears a host from the environment, and CLI
`--allow-ip` clears the all-IP setting from the environment.

Without an explicit hostname, a non-ephemeral tunnel receives a stable
service/worktree-derived label in the current member namespace. The worktree
label is salted by client state, so changing `--state-dir` can change the
derived hostname. An ephemeral tunnel without another hostname selection uses
a generated hostname. A configured ephemeral `tnl dev` service can use its
generated project metadata hostname when no runtime server, team, hostname, or
ephemeral override changes that context.

Commands use project configuration as follows:

| Commands                                                                                      | Project behavior                                                                                                       |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `publish`, `dev`, `config check`, `config generate`, all `team`, `domain`, and `route` leaves | Load and evaluate the selected configuration.                                                                          |
| `config path`                                                                                 | Select but do not evaluate the configuration.                                                                          |
| `status` without `--all`                                                                      | Use the selected configuration's directory as the project root without evaluating it; otherwise use the worktree root. |
| `init`                                                                                        | Ignore global project selection and perform its own project/configuration scan.                                        |
| `login`, `logout`, all `admin` leaves, `version`                                              | Do not use project configuration.                                                                                      |

Project `server` applies to all project-sensitive remote commands. Project
`team` applies to `team current`, `team members`, every `team invite` and
`team member` leaf, and every `domain` and `route` leaf. It is intentionally not
a team selector for `team list`, `team use`, `team create`, or `team join`.
`team members --team` takes precedence over the project team.

### Start Commands

#### `tnl init`

```text
tnl init [flags]
```

| Flag           | Default | Behavior                                                          |
| -------------- | ------- | ----------------------------------------------------------------- |
| `--no-install` | false   | Report the dependency command as an action instead of running it. |

`init` finds the nearest package root within the Git worktree, detects npm,
pnpm, Yarn, or Bun from `packageManager` and lockfiles, and detects Next.js or
Vite from dependencies. It may:

- install `@tnldotdev/tnl` as a development dependency;
- create `tnl.config.ts` when no recognized project configuration exists;
- create a missing `next.config.ts` or `vite.config.ts` for a detected framework;
- add `.tnl/` to `.gitignore`;
- report manual framework or `tsconfig.json` actions without rewriting existing
  files.

Package-manager stdout and stderr are discarded. Existing project and framework
configuration is preserved. When lockfiles conflict, framework detection is
ambiguous, or framework configuration already exists, `tnl` reports an action
instead of guessing how to edit the project.

Representative first run with a deferred dependency install, stdout:

```console
$ tnl init --no-install
+--[ tnl init ]-- needs action --------------------------------+
|                                                              |
|  project  /Users/example/work/hello                          |
|  created  /Users/example/work/hello/tnl.config.ts            |
|  updated  /Users/example/work/hello/.gitignore               |
|                                                              |
|-- action ----------------------------------------------------|
|  Run: npm install --save-dev @tnldotdev/tnl                  |
|                                                              |
+-- complete the actions above, then run tnl dev --------------+
```

A first run that completes every automatic change uses `configured`:

```text
+--[ tnl init ]-- configured ----------------------------------+
|                                                              |
|  project  /Users/example/work/hello                          |
|  created  /Users/example/work/hello/tnl.config.ts            |
|  updated  /Users/example/work/hello/.gitignore               |
|                                                              |
+-- run tnl dev -----------------------------------------------+
```

A later run with nothing to change uses `already configured`:

```text
+--[ tnl init ]-- already configured --------------------------+
|                                                              |
|  project  /Users/example/work/hello                          |
|  config   /Users/example/work/hello/tnl.config.ts            |
|                                                              |
+-- run tnl dev -----------------------------------------------+
```

#### `tnl dev`

```text
tnl dev [<service>] [flags] [-- <command> [args...]]
```

| Flag                         | Default                  | Behavior                                                                                                                         |
| ---------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `--port=INT`                 | unspecified              | Require an exact local service port from 1 through 65535.                                                                        |
| `--startup-timeout=DURATION` | project value, then `2m` | Wait for the local service to start and report its target. `0` is unset; the effective value must be positive and at most `10m`. |

All shared remote, tunnel, and `--open` flags also apply. There is no
`--output` flag; `dev` always uses human lifecycle output.

An explicit `--startup-timeout=0` falls through to the service/root project
value, then `2m`. A negative CLI value or any effective nonpositive value fails
validation. Without `--port`, the initial wait for a framework integration to
connect is capped at the lesser of the effective startup timeout and 30 seconds.
After it connects, target reporting and target readiness each use the effective
startup timeout.

The optional service must be configured. If omitted, the only configured
service is selected; multiple configured services require an explicit name.
The child command after `--` wins over `dev.command`. The separator must be
followed by at least one token, and everything after it belongs to the child.
Project-local executables in the service's `node_modules/.bin` are preferred
before `PATH`.

`dev` authenticates and generates metadata for all configured services before
starting the child. With project configuration, it writes `.tnl/project.json`
and `.tnl/project.d.ts`. It creates a private local framework-registration
socket, starts the child in the configured service directory, waits for a
framework target or the forced port, and only then starts the publisher. Only
one `tnl dev` may run for the same project and service.

Representative command:

```console
$ tnl dev web --port 5173 -- npm run dev
```

Representative stderr after the child target is ready:

```text
+--[ tnl dev ]-- provisioning ---------------------------------+
|                                                              |
|  web-main-00000000.alice-fake.example.test                   |
|     |                                                        |
|     v  certificate and publisher connections                 |
|  http://127.0.0.1:5173                                       |
|                                                              |
|  route version  7                                            |
|                                                              |
+-- waiting for route readiness -------------------------------+
+--[ tnl dev ]-- ready ----------------------------------------+
|                                                              |
|  https://web-main-00000000.alice-fake.example.test           |
|     |                                                        |
|     v                                                        |
|  publisher                                                   |
|     |                                                        |
|     v                                                        |
|  http://127.0.0.1:5173                                       |
|                                                              |
|  route version  7                                            |
|  framework      vite                                         |
|  IP policy      192.0.2.10                                   |
|                                                              |
+-- ctrl+c to stop --------------------------------------------+
```

Child stdout and stderr are intentionally not included above because tnl does
not format or alter them.

#### `tnl publish`

```text
tnl publish [<service-or-target>] [flags]
```

| Flag              | Default | Enum              |
| ----------------- | ------- | ----------------- |
| `--output=STRING` | `human` | `human`, `ndjson` |

All shared remote, tunnel, and `--open` flags also apply.

The argument selects a project service when it matches a configured service
name. Otherwise it is a target. A target may be a bare port,
`localhost:<port>`, or an `http://` URL whose host is `localhost`, a
`127.x.x.x` address, or `::1`. Paths, queries, fragments, HTTPS, whitespace,
and all other hosts are not allowed. The normalized target is always an HTTP
origin on this computer.

If the argument is omitted, the only configured service is selected and its
`publish.target` is used. With multiple services, an explicit service is
required. `publish` requires the local service to be listening before it
authenticates or changes server state.

The command records the local tunnel, creates or updates the route's target and
IP policy, starts a route session, obtains the route certificate, terminates
route TLS, and maintains publisher connections until cancellation or failure.
If the route is ephemeral, it deletes the route during shutdown.

Representative command:

```console
$ tnl publish 3000 --subdomain api --allow-ip 198.51.100.0/24
```

Representative human stderr:

```text
+--[ tnl publish ]-- provisioning -----------------------------+
|                                                              |
|  api.alice-fake.example.test                                 |
|     |                                                        |
|     v  certificate and publisher connections                 |
|  http://127.0.0.1:3000                                       |
|                                                              |
|  route version  4                                            |
|                                                              |
+-- waiting for route readiness -------------------------------+
+--[ tnl publish ]-- ready ------------------------------------+
|                                                              |
|  https://api.alice-fake.example.test                         |
|     |                                                        |
|     v                                                        |
|  publisher                                                   |
|     |                                                        |
|     v                                                        |
|  http://127.0.0.1:3000                                       |
|                                                              |
|  route version  4                                            |
|  IP policy      192.0.2.10                                   |
|                                                              |
+-- ctrl+c to stop --------------------------------------------+
```

Human mode writes no normal output to stdout and has no `starting` or
`stopped` frame. The `IP policy` field shows the automatically included current
IP, not the entire allowlist.

The command can also write these status frames without stopping the tunnel:

```text
+--[ tnl publish ]-- transport fallback -----------------------+
|                                                              |
|  route version  4                                            |
|  transport      TLS/TCP                                      |
|                                                              |
+-- tunnel continues over TLS/TCP -----------------------------+
+--[ tnl publish ]-- visitors blocked -------------------------+
|                                                              |
|  newly blocked  2                                            |
|  total blocked  5                                            |
|                                                              |
+-- IP policy remains active ----------------------------------+
+--[ tnl publish ]-- publisher connection disrupted -----------+
|                                                              |
|  publisher connection closed                                 |
|                                                              |
+-- reconnecting ----------------------------------------------+
```

If provisioning remains incomplete, a classified
`TNL_PROVISIONING_STALLED` warning is emitted while retrying. If `--open`
succeeds, the ready footer is `opened in browser; ctrl+c to stop`. Browser
failure produces a separate `browser not opened` frame with `public` and
`reason` fields and footer `route remains ready`; it does not stop the tunnel.

The complete NDJSON contract is documented under Machine-Readable Output.

#### `tnl status`

```text
tnl status [flags]
```

| Flag                 | Default                         | Enum/behavior                             |
| -------------------- | ------------------------------- | ----------------------------------------- |
| `--output=STRING`    | `human`                         | `human`, `json`                           |
| `--state-dir=STRING` | platform client-state directory | `TNL_STATE_DIR`                           |
| `--all`              | false                           | Include tunnels from every local project. |

`status` reads the local client-state database. It does not call control or list
routes. Without `--all`, it filters by the selected configuration directory or
current worktree root. It returns only tunnels that have not stopped. An expired
local tunnel record is shown as `stale`.

Representative empty stdout:

```console
$ tnl status
+--[ tnl status ]-- no local tunnels --------------------------+
|                                                              |
|  start one with                                              |
|  |-- tnl publish 3000                                        |
|  `-- tnl dev -- pnpm dev                                     |
|                                                              |
+--------------------------------------------------------------+
```

Representative `--all` stdout with two tunnels:

```console
$ tnl status --all
+--[ tnl status ]-- 2 local tunnels ---------------------------+
|                                                              |
|-- ready -----------------------------------------------------|
|  public        https://api.alice-fake.example.test           |
|  target        http://127.0.0.1:3000                         |
|  command       publish                                       |
|  server        https://control.example.test                  |
|  service       api                                           |
|  project       /Users/example/work/hello                     |
|  route version  4                                            |
|  tunnel        tunnel_00000000000000000000000000000000       |
|                                                              |
|-- stale -----------------------------------------------------|
|  hostname      web.alice-fake.example.test                   |
|  command       dev                                           |
|  server        https://control.example.test                  |
|  service       web                                           |
|  project       /Users/example/work/hello                     |
|  framework     vite                                          |
|  tunnel        tunnel_00000000000000000000000000000001       |
|                                                              |
+-- 1 ready / 1 stale -----------------------------------------+
```

Each additional tunnel repeats one section. Section states are `starting`,
`provisioning`, `ready`, `draining`, or `stale`. Fields are included only when
known. The `project` field appears only with `--all`.

### Authentication And Configuration Commands

#### `tnl login`

```text
tnl login [<server>] [flags]
```

| Flag                   | Default                           | Behavior                                                      |
| ---------------------- | --------------------------------- | ------------------------------------------------------------- |
| `--server=STRING`      | saved server, then hosted default | `TNL_SERVER`; ignored when the positional server is nonempty. |
| `--state-dir=STRING`   | platform client-state directory   | `TNL_STATE_DIR`.                                              |
| `--token`              | false                             | Force login-token authentication even when OIDC is available. |
| `--login-token=STRING` | empty, hidden                     | `TNL_LOGIN_TOKEN`; sensitive noninteractive input.            |

`login` always performs a fresh login rather than silently reusing a valid
access token. It stores the resulting control session and selects the resolved
server for future commands. When replacing a saved session, it attempts to
revoke the previous session.

On an interactive terminal, OIDC can open the browser. Device or authorization
prompts are written to stderr:

```console
$ tnl login https://control.example.test
+--[ tnl login ]-- authentication required --------------------+
|                                                              |
|  open  https://identity.example.test/device                  |
|  code  FAKE-CODE                                             |
|                                                              |
+-- waiting for authentication --------------------------------+
```

After authentication, stdout is:

```text
+--[ tnl login ]-- authenticated ------------------------------+
|                                                              |
|  control  https://control.example.test                       |
|                                                              |
+-- saved for future commands ---------------------------------+
```

Login-token mode prompts without echo when no hidden token input was provided:

```text
Login token:
```

`--token` selects login-token authentication; it is not the token itself.
Login-token prompting requires an interactive terminal unless
`TNL_LOGIN_TOKEN` or the hidden flag supplies the value. Never place a real
credential in documentation or shell examples.

#### `tnl config path`

```text
tnl config path [flags]
```

This command selects but does not evaluate project configuration. It does not
normally create client state, though default telemetry can do so. Its output is
a human frame, not a raw pathname.

Representative stdout:

```console
$ tnl config path
+--[ tnl config path ]-- selected -----------------------------+
|                                                              |
|  /Users/example/work/hello/tnl.config.ts                     |
|                                                              |
+--------------------------------------------------------------+
```

With no selected configuration:

```text
+--[ tnl config path ]-- not found ----------------------------+
|                                                              |
|  No project configuration file is selected.                  |
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl config check`

```text
tnl config check [flags]
```

| Flag                 | Default                         | Environment     |
| -------------------- | ------------------------------- | --------------- |
| `--state-dir=STRING` | platform client-state directory | `TNL_STATE_DIR` |

`check` requires a selected configuration. It opens client state to obtain the
private worktree-label salt, evaluates TypeScript when selected, validates all
root and service settings, and resolves service directories. It does not
contact a tnl server.

Representative stdout:

```console
$ tnl config check
+--[ tnl config check ]-- valid -------------------------------+
|                                                              |
|  path  /Users/example/work/hello/tnl.config.ts               |
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl config generate`

```text
tnl config generate [flags]
```

| Flag                 | Default                         | Environment     |
| -------------------- | ------------------------------- | --------------- |
| `--state-dir=STRING` | platform client-state directory | `TNL_STATE_DIR` |

`generate` requires a selected configuration. It authenticates to each selected
control URL, finds each selected team and ready default domain, computes every
service hostname, and safely replaces:

- `.tnl/project.json`, including member namespace, service hostnames/URLs, and
  service directories;
- `.tnl/project.d.ts`, containing specific TypeScript service and hostname types
  when available.

The command never edits `tsconfig.json`. Missing declaration includes are
reported as action sections.

Representative stdout:

```console
$ tnl config generate
+--[ tnl config generate ]-- generated ------------------------+
|                                                              |
|  metadata      /Users/example/work/hello/.tnl/project.json   |
|  declarations  /Users/example/work/hello/.tnl/project.d.ts   |
|                                                              |
|-- action ----------------------------------------------------|
|  Add ".tnl/project.d.ts" to the include array in             |
|  /Users/example/work/hello/tsconfig.json.                    |
|                                                              |
+--------------------------------------------------------------+
```

Authentication prompts, if required, go to stderr under the
`tnl config generate` command title.

#### `tnl logout`

```text
tnl logout [flags]
```

| Flag                 | Default                           | Environment     |
| -------------------- | --------------------------------- | --------------- |
| `--server=STRING`    | saved server, then hosted default | `TNL_SERVER`    |
| `--state-dir=STRING` | platform client-state directory   | `TNL_STATE_DIR` |

`logout` discovers the authority, loads the saved control session, attempts to
revoke it, and removes it locally. An already-invalid remote access token does
not prevent local removal. No saved login is an error. The selected server and
selected team remain saved.

Representative stdout:

```console
$ tnl logout --server https://control.example.test
+--[ tnl logout ]-- logged out --------------------------------+
|                                                              |
|  control  https://control.example.test                       |
|                                                              |
+-- local session removed -------------------------------------+
```

### Team Commands

Each control URL has its own team selection. Without a project team override,
the saved selection is used. If no selection is saved, the personal team is
used. `<team>` and `--team` accept a team ID or an unambiguous display name.
Duplicate display names require an ID.

All team commands authenticate and may refresh or create a saved control
session. Authentication prompts go to stderr; results go to stdout.

#### `tnl team current`

```text
tnl team current [flags]
```

Shows the project team when configured, otherwise the saved/personal team. A
project override is not persisted. Without an override, falling back to the
personal team updates the saved selection.

Representative stdout:

```console
$ tnl team current
+--[ tnl team current ]-- selected ----------------------------+
|                                                              |
|  team         Example Team                                   |
|  kind         organization                                   |
|  role         admin                                          |
|  member slug  alice                                          |
|  id           team_00000000000000000000000000000000          |
|                                                              |
+--------------------------------------------------------------+
```

Team kinds are `personal` and `organization`; roles are `member`, `admin`, and
`owner`.

#### `tnl team list`

```text
tnl team list [flags]
```

Lists the authenticated identity's memberships. The project server applies, but
the project team does not choose the marked selection. When no team is saved,
the personal membership is marked.

Representative stdout:

```console
$ tnl team list
+--[ tnl team list ]-- 2 memberships --------------------------+
|                                                              |
|-- Personal --------------------------------------------------|
|  kind         personal                                       |
|  role         owner                                          |
|  member slug  alice                                          |
|  id           team_00000000000000000000000000000001          |
|                                                              |
|-- * Example Team --------------------------------------------|
|  kind         organization                                   |
|  role         admin                                          |
|  member slug  alice                                          |
|  id           team_00000000000000000000000000000000          |
|                                                              |
+-- * selected ------------------------------------------------+
```

Each additional membership repeats one titled section. An empty result retains
the count state and footer:

```text
+--[ tnl team list ]-- 0 memberships --------------------------+
|                                                              |
+-- * selected ------------------------------------------------+
```

#### `tnl team use`

```text
tnl team use <team> [flags]
```

Finds the argument in the current memberships and saves that team for the
selected control URL. The project team does not replace an explicit argument.

Representative stdout:

```console
$ tnl team use "Example Team"
+--[ tnl team use ]-- selected --------------------------------+
|                                                              |
|  team         Example Team                                   |
|  role         admin                                          |
|  member slug  alice                                          |
|  id           team_00000000000000000000000000000000          |
|                                                              |
+-- future commands use this team -----------------------------+
```

#### `tnl team create`

```text
tnl team create --member-slug=STRING <display-name> [flags]
```

`--member-slug` is required and becomes the creator's immutable member slug.
The command creates an organization team and saves it as the current selection.

Representative stdout:

```console
$ tnl team create --member-slug=alice "Example Team"
+--[ tnl team create ]-- created ------------------------------+
|                                                              |
|  team         Example Team                                   |
|  member slug  alice                                          |
|  id           team_00000000000000000000000000000000          |
|                                                              |
+-- selected for future commands ------------------------------+
```

#### `tnl team members`

```text
tnl team members [flags]
```

| Flag            | Default                                | Behavior                                                    |
| --------------- | -------------------------------------- | ----------------------------------------------------------- |
| `--team=STRING` | project team, then saved/personal team | Team ID or unambiguous display name. No `TNL_TEAM` binding. |

Representative stdout:

```console
$ tnl team members --team "Example Team"
+--[ tnl team members ]-- 2 members ---------------------------+
|                                                              |
|-- alice -----------------------------------------------------|
|  role           admin                                        |
|  identity       identity_00000000000000000000000000000000    |
|  managed label  alice-fake                                   |
|  id             membership_00000000000000000000000000000000  |
|                                                              |
|-- bob -------------------------------------------------------|
|  role           member                                       |
|  identity       identity_00000000000000000000000000000001    |
|  managed label  bob-fake                                     |
|  id             membership_00000000000000000000000000000001  |
|                                                              |
+--------------------------------------------------------------+
```

Each additional membership repeats one member-slug section. Zero members uses
state `0 members` with an otherwise empty frame.

#### `tnl team invite create`

```text
tnl team invite create --member-slug=STRING [flags]
```

| Flag                    | Default  | Enum/behavior                                      |
| ----------------------- | -------- | -------------------------------------------------- |
| `--member-slug=STRING`  | required | Reserve this immutable member slug.                |
| `--role=STRING`         | `member` | `member`, `admin`, `owner`                         |
| `--email=STRING`        | empty    | Restrict acceptance to an optional verified email. |
| `--expires-in=DURATION` | `168h`   | Positive invitation lifetime.                      |

This is a raw-output exception. It creates a one-time invitation and writes
exactly the invitation ID, a tab, the secret, and a newline to stdout. It does
not render a frame.

Representative raw stdout with an intentionally invalid fake secret:

```console
$ tnl team invite create --member-slug=bob --role=member
invitation_00000000000000000000000000000000	EXAMPLE_SECRET_NOT_VALID
```

Treat the second field as a credential. Do not log it or place a real value in
documentation.

#### `tnl team invite list`

```text
tnl team invite list [flags]
```

Representative stdout:

```console
$ tnl team invite list
+--[ tnl team invite list ]-- 1 invitation --------------------+
|                                                              |
|-- bob -------------------------------------------------------|
|  role     member                                             |
|  state    pending                                            |
|  expires  2030-01-08T12:00:00Z                               |
|  id       invitation_00000000000000000000000000000000        |
|                                                              |
+--------------------------------------------------------------+
```

Invitation states are `pending`, `accepted`, `revoked`, and `expired`. Each
additional invitation repeats one member-slug section. Zero invitations uses
state `0 invitations` with an otherwise empty frame.

#### `tnl team invite revoke`

```text
tnl team invite revoke <invitation-id> [flags]
```

Representative stdout:

```console
$ tnl team invite revoke invitation_00000000000000000000000000000000
+--[ tnl team invite revoke ]-- revoked -----------------------+
|                                                              |
|  invitation_00000000000000000000000000000000                 |
|     |                                                        |
|     v                                                        |
|  invitation revoked                                          |
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl team join`

```text
tnl team join <secret> [flags]
```

Accepts an invitation and saves the resulting team as the current selection.
The positional secret may remain in shell history; handle it as a credential.

Representative command uses an intentionally invalid fake secret. Successful
stdout has this shape:

```console
$ tnl team join EXAMPLE_SECRET_NOT_VALID
+--[ tnl team join ]-- joined ---------------------------------+
|                                                              |
|  team         Example Team                                   |
|  role         member                                         |
|  member slug  bob                                            |
|  id           team_00000000000000000000000000000000          |
|                                                              |
+-- selected for future commands ------------------------------+
```

#### `tnl team member set-role`

```text
tnl team member set-role --role=STRING <membership-id> [flags]
```

`--role` is required and must be `member`, `admin`, or `owner`.

Representative stdout:

```console
$ tnl team member set-role --role=admin membership_00000000000000000000000000000001
+--[ tnl team member set-role ]-- updated ---------------------+
|                                                              |
|  membership_00000000000000000000000000000001                 |
|     |                                                        |
|     v  role changed                                          |
|  admin                                                       |
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl team member remove`

```text
tnl team member remove <membership-id> [flags]
```

Representative stdout:

```console
$ tnl team member remove membership_00000000000000000000000000000001
+--[ tnl team member remove ]-- removed -----------------------+
|                                                              |
|  membership_00000000000000000000000000000001                 |
|     |                                                        |
|     v                                                        |
|  membership removed                                          |
|                                                              |
+--------------------------------------------------------------+
```

### Domain Commands

Domain commands operate on the project team when configured, otherwise the
saved/personal team. A managed deployment domain is server-controlled. A
claimed domain belongs exclusively to one team after DNS authority
verification.

#### `tnl domain claim`

```text
tnl domain claim <domain> [flags]
```

| Flag        | Default | Behavior                                                 |
| ----------- | ------- | -------------------------------------------------------- |
| `--default` | false   | Make the domain the team default after it becomes ready. |

The domain name must already be lowercase and normalized. The command creates
the claim and shows its state. A successful API request can return a domain in
the `failed` state without making the command itself fail.

Representative verification-required stdout:

```console
$ tnl domain claim routes.example.test --default
+--[ tnl domain claim ]-- verification required ---------------+
|                                                              |
|  domain  routes.example.test                                 |
|  state   pending                                             |
|  id      domain_00000000000000000000000000000000             |
|                                                              |
|-- DNS record ------------------------------------------------|
|  name   routes.example.test                                  |
|  type   NS                                                   |
|  value  ns1.example.test                                     |
|                                                              |
|-- DNS record ------------------------------------------------|
|  name   routes.example.test                                  |
|  type   NS                                                   |
|  value  ns2.example.test                                     |
|                                                              |
+-- add the DNS records; this domain will become the default --+
```

Each required DNS record repeats one `DNS record` section. Pending without
records is provisioning:

```text
+--[ tnl domain claim ]-- provisioning ------------------------+
|                                                              |
|  domain  routes.example.test                                 |
|  state   pending                                             |
|  id      domain_00000000000000000000000000000000             |
|                                                              |
+-- run tnl domain list to check DNS setup --------------------+
```

With `--default`, that footer becomes
`run tnl domain list; this domain will become the default`.

Ready with `--default` is:

```text
+--[ tnl domain claim ]-- ready -------------------------------+
|                                                              |
|  domain  routes.example.test                                 |
|  state   ready                                               |
|  id      domain_00000000000000000000000000000000             |
|                                                              |
+-- selected as the default domain ----------------------------+
```

Other non-pending states use the returned state directly, including `ready`,
`releasing`, and `failed`.

#### `tnl domain default`

```text
tnl domain default <domain> [flags]
```

The argument may be a domain ID or domain name already available to the selected
team.

Representative stdout:

```console
$ tnl domain default routes.example.test
+--[ tnl domain default ]-- updated ---------------------------+
|                                                              |
|  routes.example.test                                         |
|     |                                                        |
|     v                                                        |
|  default domain                                              |
|                                                              |
|  id  domain_00000000000000000000000000000000                 |
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl domain list`

```text
tnl domain list [flags]
```

Representative stdout:

```console
$ tnl domain list
+--[ tnl domain list ]-- 2 domains ----------------------------+
|                                                              |
|-- * example.test --------------------------------------------|
|  kind   managed                                              |
|  state  ready                                                |
|  id     domain_00000000000000000000000000000001              |
|                                                              |
|-- routes.example.test ---------------------------------------|
|  kind   claimed                                              |
|  state  pending                                              |
|  id     domain_00000000000000000000000000000000              |
|                                                              |
|-- DNS record ------------------------------------------------|
|  name   routes.example.test                                  |
|  type   NS                                                   |
|  value  ns1.example.test                                     |
|                                                              |
+-- * default -------------------------------------------------+
```

Each domain has its own section. Each required record has a nested `DNS record`
section. Domain kinds are `managed` and `claimed`; states are `pending`, `ready`,
`releasing`, and `failed`. Zero domains uses state `0 domains` and keeps the
footer `* default`.

#### `tnl domain release`

```text
tnl domain release <domain> [flags]
```

The argument may be a domain ID or domain name already available to the selected
team.

Representative stdout:

```console
$ tnl domain release routes.example.test
+--[ tnl domain release ]-- released --------------------------+
|                                                              |
|  routes.example.test                                         |
|     |                                                        |
|     v                                                        |
|  domain released                                             |
|                                                              |
|  id  domain_00000000000000000000000000000000                 |
|                                                              |
+--------------------------------------------------------------+
```

### Route Commands

A route maps a public hostname to a target, IP policy, scope, and state. The tnl
server stores that mapping. These commands use the project team when configured,
otherwise the saved or personal team.

#### `tnl route list`

```text
tnl route list [flags]
```

Representative stdout:

```console
$ tnl route list
+--[ tnl route list ]-- 1 route -------------------------------+
|                                                              |
|-- api.alice-fake.example.test -------------------------------|
|  scope          member                                       |
|  state          enabled                                      |
|  route version  5                                            |
|  id             route_00000000000000000000000000000000       |
|                                                              |
+--------------------------------------------------------------+
```

Each route repeats one hostname section. Scope is `member` or `shared`, and
lifecycle state is `enabled` or `suspended`. The displayed `route version` is
the API's `next_route_version`, not necessarily an open route session's current
version.

An empty list is still a successful frame:

```text
+--[ tnl route list ]-- 0 routes ------------------------------+
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl route delete`

```text
tnl route delete <route-id> [flags]
```

The command lists the effective team's routes, matches by route ID only, and
deletes the selected route.

Representative stdout:

```console
$ tnl route delete route_00000000000000000000000000000000
+--[ tnl route delete ]-- deleted -----------------------------+
|                                                              |
|  api.alice-fake.example.test                                 |
|     |                                                        |
|     v                                                        |
|  route deleted                                               |
|                                                              |
|  id  route_00000000000000000000000000000000                  |
|                                                              |
+--------------------------------------------------------------+
```

### Administrative Commands

Administrative commands target the server selected by `--server`,
`TNL_SERVER`, saved state, or the hosted default. They do not use project
configuration even though global configuration flags appear in generated help.
They require an identity authorized for the administrative operation.

#### `tnl admin server status`

```text
tnl admin server status [flags]
```

Representative stdout:

```console
$ tnl admin server status --server https://control.example.test
+--[ tnl admin server status ]-- serving ----------------------+
|                                                              |
|  control                                                     |
|  |-- ingress  2 leases                                       |
|  `-- relays  4 leases                                        |
|                                                              |
|  role            control                                     |
|  routes          12 enabled / 1 suspended                    |
|  route sessions  8 ready / 2 starting                        |
|  started         2030-01-01T10:00:00Z                        |
|  current         2030-01-01T12:00:00Z                        |
|                                                              |
+--------------------------------------------------------------+
```

Role is `standalone` or `control`. Times are UTC RFC3339. The top-level state is
`serving` whenever the status request succeeds; route or session counts do not
change that label.

#### `tnl admin relays list`

```text
tnl admin relays list [flags]
```

Representative stdout:

```console
$ tnl admin relays list --server https://control.example.test
+--[ tnl admin relays list ]-- 1 relay process ----------------+
|                                                              |
|-- relay_00000000000000000000000000000000 / draining ---------|
|  relay service          relay-service-example                |
|  process run            relay-run-example                    |
|  lease revision         9                                    |
|  relay address          relay.example.test:443               |
|  internal address       relay.internal.example.test:8443     |
|  publisher connections  12 / 1000                            |
|  visitor streams        48 / 4096                            |
|  lease expires          2030-01-01T12:00:30Z                 |
|  drain deadline         2030-01-01T12:01:00Z                 |
|                                                              |
+--------------------------------------------------------------+
```

Each relay process repeats one section. A nondraining section ends in
`/ active` and omits `drain deadline`. Zero relay processes uses state
`0 relay processes`.

#### `tnl admin relays drain`

```text
tnl admin relays drain --relay-run-id=STRING \
  --relay-lease-revision=INT-64 <relay-id> [flags]
```

| Flag                            | Default  | Behavior                                                         |
| ------------------------------- | -------- | ---------------------------------------------------------------- |
| `--relay-run-id=STRING`         | required | Exact relay process run ID.                                      |
| `--relay-lease-revision=INT-64` | required | Exact positive relay lease revision.                             |
| `--deadline=DURATION`           | `30s`    | Positive drain deadline measured from the client's current time. |

The relay ID, process run ID, and lease revision together identify the matching
lease. The relay rejects new work while existing connections finish, up to the
returned deadline.

Representative stdout:

```console
$ tnl admin relays drain relay_00000000000000000000000000000000 --relay-run-id=relay-run-example --relay-lease-revision=9 --deadline=1m
+--[ tnl admin relays drain ]-- draining ----------------------+
|                                                              |
|  relay_00000000000000000000000000000000                      |
|     |                                                        |
|     v                                                        |
|  rejecting new work                                          |
|                                                              |
|  process run     relay-run-example                           |
|  lease revision  9                                           |
|                                                              |
+-- deadline 2030-01-01T12:01:00Z -----------------------------+
```

If the response omits a drain deadline, the footer is `rejecting new work`.

#### `tnl admin maintenance list`

```text
tnl admin maintenance list [flags]
```

Representative stdout:

```console
$ tnl admin maintenance list --server https://control.example.test
+--[ tnl admin maintenance list ]-- 3 controls ----------------+
|                                                              |
|-- route_creation --------------------------------------------|
|  state             blocked                                   |
|  control revision  3                                         |
|  updated           2030-01-01T11:00:00Z                      |
|  updated by        identity_00000000000000000000000000000000 |
|                                                              |
|-- route_session_creation ------------------------------------|
|  state             allowed                                   |
|  control revision  8                                         |
|  updated           2030-01-01T11:30:00Z                      |
|  updated by        identity_00000000000000000000000000000000 |
|                                                              |
|-- certificate_issuance --------------------------------------|
|  state             blocked                                   |
|  control revision  5                                         |
|  updated           2030-01-01T11:45:00Z                      |
|  updated by        identity_00000000000000000000000000000000 |
|                                                              |
+--------------------------------------------------------------+
```

Each control repeats one section. Zero controls uses state `0 controls`. An
allowed operation may start new work; a blocked operation may not.

#### `tnl admin maintenance allow`

```text
tnl admin maintenance allow <name> [flags]
```

`<name>` must be `route_creation`, `route_session_creation`, or
`certificate_issuance`.

Representative stdout:

```console
$ tnl admin maintenance allow route_creation
+--[ tnl admin maintenance allow ]-- updated ------------------+
|                                                              |
|  route_creation                                              |
|     |                                                        |
|     v                                                        |
|  allowed                                                     |
|                                                              |
|  control revision  4                                         |
|                                                              |
+--------------------------------------------------------------+
```

#### `tnl admin maintenance block`

```text
tnl admin maintenance block <name> [flags]
```

`<name>` has the same enum as `allow`.

Representative stdout:

```console
$ tnl admin maintenance block route_creation
+--[ tnl admin maintenance block ]-- updated ------------------+
|                                                              |
|  route_creation                                              |
|     |                                                        |
|     v                                                        |
|  blocked                                                     |
|                                                              |
|  control revision  5                                         |
|                                                              |
+--------------------------------------------------------------+
```

### Version Command

#### `tnl version`

```text
tnl version [flags]
```

This is a raw-output exception. It writes one line to stdout and no success
frame. A build without commit metadata omits the parenthesized value.

Representative stdout with visibly fake build information:

```console
$ tnl version
tnl 1.2.3-example (0000000000000000000000000000000000000000)
```

The development build normally reports `tnl devel`.

### Machine-Readable Output

#### Publish NDJSON

`tnl publish --output=ndjson` writes one JSON object per line to stdout. Every
event contains these base fields:

| Field            | JSON type        | Meaning                                                                                |
| ---------------- | ---------------- | -------------------------------------------------------------------------------------- |
| `schema_version` | integer          | Always `1`.                                                                            |
| `type`           | string           | Event type described below.                                                            |
| `cursor`         | unsigned integer | Increases within this process, starting at 1.                                          |
| `tunnel_id`      | string           | Local tunnel ID; it can be empty when failure occurs before local tunnel registration. |

All possible event-specific fields are:

| Field           | JSON type         | Events and meaning                                                          |
| --------------- | ----------------- | --------------------------------------------------------------------------- |
| `target`        | string            | `starting`; normalized local HTTP target.                                   |
| `url`           | string            | `ready`; public HTTPS URL.                                                  |
| `route_version` | unsigned integer  | `ready` and warning events tied to one route version.                       |
| `ip`            | string            | `current_ip`; current client IP automatically included in nonpublic policy. |
| `message`       | string            | `warning` or `error`; error messages are capped at 1024 bytes.              |
| `code`          | string            | Classified warning/error diagnostic code.                                   |
| `help_url`      | string            | Help URL associated with `code`.                                            |
| `retryable`     | boolean           | Whether the warning/error is expected to be retryable.                      |
| `retry_at`      | RFC3339 timestamp | Rate-limited `error` when a positive retry delay is available.              |
| `reason`        | string            | `stopped`; currently `canceled`.                                            |
| `transport`     | string            | Transport warning; currently `tls-tcp` for fallback.                        |

The event variants are:

| `type`       | Fields beyond the base                                                    | Emission                                                                |
| ------------ | ------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `starting`   | `target`                                                                  | After local tunnel registration.                                        |
| `current_ip` | `ip`                                                                      | Nonpublic IP policy only.                                               |
| `warning`    | Stalled: `message`, `code`, `help_url`, `retryable=true`, `route_version` | Provisioning remains incomplete while the publisher continues retrying. |
| `warning`    | Fallback: `message`, `retryable=false`, `route_version`, `transport`      | TLS/TCP wins after QUIC does not establish first.                       |
| `ready`      | `url`, `route_version`                                                    | Every route version that becomes ready.                                 |
| `error`      | `message`, `retryable`; optional `code`, `help_url`, `retry_at`           | Terminal command failure.                                               |
| `stopped`    | `reason`                                                                  | Cancellation.                                                           |

NDJSON does not include events for ordinary provisioning, route assignment,
draining, or blocked-visitor totals. Publisher log messages and browser-open
failures remain one-line stderr diagnostics. After a terminal error event, the
process fails. A caller can therefore receive the NDJSON error on stdout and a
top-level human diagnostic on stderr.

Representative ready-then-canceled stream, with each object on one physical
line:

```json
{"schema_version":1,"type":"starting","cursor":1,"tunnel_id":"tunnel_00000000000000000000000000000000","target":"http://127.0.0.1:3000"}
{"schema_version":1,"type":"current_ip","cursor":2,"tunnel_id":"tunnel_00000000000000000000000000000000","ip":"192.0.2.10"}
{"schema_version":1,"type":"warning","cursor":3,"tunnel_id":"tunnel_00000000000000000000000000000000","route_version":4,"message":"route provisioning has not completed. tnl is still retrying certificate or publisher connection work.","code":"TNL_PROVISIONING_STALLED","help_url":"https://tnl.dev/e/provisioning-stalled","retryable":true}
{"schema_version":1,"type":"warning","cursor":4,"tunnel_id":"tunnel_00000000000000000000000000000000","route_version":4,"message":"QUIC did not establish before TLS/TCP; continuing over TLS/TCP.","retryable":false,"transport":"tls-tcp"}
{"schema_version":1,"type":"ready","cursor":5,"tunnel_id":"tunnel_00000000000000000000000000000000","url":"https://api.alice-fake.example.test","route_version":4}
{"schema_version":1,"type":"stopped","cursor":6,"tunnel_id":"tunnel_00000000000000000000000000000000","reason":"canceled"}
```

Representative classified terminal failure stream:

```json
{"schema_version":1,"type":"starting","cursor":1,"tunnel_id":"tunnel_00000000000000000000000000000000","target":"http://127.0.0.1:3000"}
{"schema_version":1,"type":"error","cursor":2,"tunnel_id":"tunnel_00000000000000000000000000000000","message":"connection refused","code":"TNL_TARGET_UNAVAILABLE","help_url":"https://tnl.dev/e/target","retryable":false}
```

Representative rate-limited terminal failure stream:

```json
{"schema_version":1,"type":"starting","cursor":1,"tunnel_id":"tunnel_00000000000000000000000000000000","target":"http://127.0.0.1:3000"}
{"schema_version":1,"type":"error","cursor":2,"tunnel_id":"tunnel_00000000000000000000000000000000","message":"rate limited","retryable":true,"retry_at":"2030-01-01T12:01:00Z"}
```

With `--open`, the first `ready` event triggers one browser-open attempt. A
failure writes exactly one stderr line shaped as:

```text
tnl: could not open https://api.alice-fake.example.test: browser unavailable
```

#### Status JSON

`tnl status --output=json` writes one JSON object followed by a newline. The
complete schema is:

| Path                         | JSON type         | Required | Meaning                                                      |
| ---------------------------- | ----------------- | -------- | ------------------------------------------------------------ |
| `schema_version`             | integer           | yes      | Always `1`.                                                  |
| `observed_at`                | RFC3339 timestamp | yes      | Local snapshot time.                                         |
| `summary`                    | object            | yes      | Counts of tunnels that have not stopped.                     |
| `summary.total`              | integer           | yes      | Number of returned tunnels.                                  |
| `summary.starting`           | integer           | yes      | Starting count.                                              |
| `summary.provisioning`       | integer           | yes      | Provisioning count.                                          |
| `summary.ready`              | integer           | yes      | Ready count.                                                 |
| `summary.draining`           | integer           | yes      | Draining count.                                              |
| `summary.stale`              | integer           | yes      | Expired local lease count.                                   |
| `tunnels`                    | array             | yes      | Tunnels ordered by start time, then tunnel ID.               |
| `tunnels[].tunnel_id`        | string            | yes      | Local tunnel ID.                                             |
| `tunnels[].command`          | string            | yes      | `publish` or `dev`.                                          |
| `tunnels[].state`            | string            | yes      | `starting`, `provisioning`, `ready`, `draining`, or `stale`. |
| `tunnels[].process_id`       | integer           | yes      | Local publisher process ID.                                  |
| `tunnels[].server`           | string            | yes      | Control URL.                                                 |
| `tunnels[].project`          | string            | yes      | Absolute local project root.                                 |
| `tunnels[].service`          | string            | no       | Configured service name.                                     |
| `tunnels[].route_id`         | string            | no       | Assigned route ID.                                           |
| `tunnels[].route_version`    | unsigned integer  | no       | Current recorded route version.                              |
| `tunnels[].hostname`         | string            | no       | Assigned public hostname.                                    |
| `tunnels[].public_url`       | string            | no       | `https://` plus the assigned hostname.                       |
| `tunnels[].target`           | string            | no       | Normalized local HTTP target.                                |
| `tunnels[].framework`        | string            | no       | Registered `tnl dev` framework.                              |
| `tunnels[].started_at`       | RFC3339 timestamp | yes      | Local start time.                                            |
| `tunnels[].updated_at`       | RFC3339 timestamp | yes      | Last local status update.                                    |
| `tunnels[].heartbeat_at`     | RFC3339 timestamp | yes      | Last local lease heartbeat.                                  |
| `tunnels[].lease_expires_at` | RFC3339 timestamp | yes      | Local lease expiration.                                      |

Optional string fields and a zero route version are omitted. A complete
representative object with every optional tunnel field populated is:

```json
{
  "schema_version": 1,
  "observed_at": "2030-01-01T12:00:00Z",
  "summary": {
    "total": 1,
    "starting": 0,
    "provisioning": 0,
    "ready": 1,
    "draining": 0,
    "stale": 0
  },
  "tunnels": [
    {
      "tunnel_id": "tunnel_00000000000000000000000000000000",
      "command": "dev",
      "state": "ready",
      "process_id": 12345,
      "server": "https://control.example.test",
      "project": "/Users/example/work/hello",
      "service": "web",
      "route_id": "route_00000000000000000000000000000000",
      "route_version": 7,
      "hostname": "web.alice-fake.example.test",
      "public_url": "https://web.alice-fake.example.test",
      "target": "http://127.0.0.1:5173",
      "framework": "vite",
      "started_at": "2030-01-01T11:59:00Z",
      "updated_at": "2030-01-01T11:59:10Z",
      "heartbeat_at": "2030-01-01T11:59:55Z",
      "lease_expires_at": "2030-01-01T12:00:15Z"
    }
  ]
}
```

### Diagnostics

Classified diagnostics have a stable code, title, summary text, failure flow,
`help` field, and code footer. The command title is the leaf that failed.

| Code                                 | Frame state                        | Typical boundary                                                                                              | Help URL                                           |
| ------------------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `TNL_TARGET_UNAVAILABLE`             | `local service unavailable`        | Publisher cannot connect to the target.                                                                       | `https://tnl.dev/e/target`                         |
| `TNL_TARGET_INVALID`                 | `invalid target`                   | Target is not a supported local HTTP origin or port.                                                          | `https://tnl.dev/e/config`                         |
| `TNL_ROUTE_INVALID`                  | `invalid route`                    | Publisher cannot use the assigned hostname.                                                                   | `https://tnl.dev/e/route`                          |
| `TNL_REQUEST_REJECTED`               | `request rejected`                 | Publisher rejects a visitor request before contacting the local service.                                      | `https://tnl.dev/e/request`                        |
| `TNL_FRAMEWORK_REGISTRATION_TIMEOUT` | `framework registration timed out` | `tnl dev` does not receive framework configuration or target registration before the applicable wait expires. | `https://tnl.dev/e/framework-registration-timeout` |
| `TNL_TARGET_MISMATCH`                | `target mismatch`                  | Framework reports a port different from `tnl dev --port`.                                                     | `https://tnl.dev/e/target-mismatch`                |
| `TNL_AUTHENTICATION_TIMEOUT`         | `authentication timed out`         | Interactive authentication expires.                                                                           | `https://tnl.dev/e/authentication-timeout`         |
| `TNL_SERVICE_AMBIGUOUS`              | `service selection ambiguous`      | Multiple configured services exist and none was selected.                                                     | `https://tnl.dev/e/ambiguous-service`              |
| `TNL_ROUTE_CONFLICT`                 | `route conflict`                   | An existing route conflicts with the requested route or state.                                                | `https://tnl.dev/e/route-conflict`                 |
| `TNL_PROVISIONING_STALLED`           | `provisioning stalled`             | Certificate or publisher connection work is still incomplete.                                                 | `https://tnl.dev/e/provisioning-stalled`           |

Representative classified stderr:

```text
+--[ tnl publish ]-- local service unavailable ----------------+
|                                                              |
|  the request reached the publisher, but the publisher could  |
|  not connect to the target. start the local service, then    |
|  try again.                                                  |
|                                                              |
|  localproxy: connect to target: dial tcp 127.0.0.1:3000:     |
|  connect: connection refused                                 |
|                                                              |
|  visitor                                                     |
|     |                                                        |
|     v                                                        |
|  tnl server                                                  |
|     |                                                        |
|     v                                                        |
|  publisher                                                   |
|     |                                                        |
|     x  target unavailable                                    |
|  local service                                               |
|                                                              |
|  help  https://tnl.dev/e/target                              |
|                                                              |
+-- TNL_TARGET_UNAVAILABLE ------------------------------------+
```

An unclassified error uses state `command failed`, includes the error text once,
and has no diagnostic code footer:

```text
+--[ tnl team use ]-- command failed --------------------------+
|                                                              |
|  team "Missing Team" is not in the current identity's        |
|  memberships                                                 |
|                                                              |
+--------------------------------------------------------------+
```

Errors go to stderr and exit with status 1, except cancellation and the
`tnl dev` child-exit behavior described under Output Conventions.

## tnld

`tnld` runs the tnl server as a standalone, control, ingress, or relay process.
Its output is simpler than `tnl` output. Generated help has no frame. Successful
administrative commands write raw output or remain silent. Serving processes
write short operational logs to stderr.

### Command Index

The `tnld` command tree has five leaf commands.

|   # | Syntax                            | Purpose                                                  |
| --: | --------------------------------- | -------------------------------------------------------- |
|   1 | `tnld serve [flags]`              | Run one configured `tnld` process.                       |
|   2 | `tnld migrate`                    | Apply embedded control-state PostgreSQL migrations.      |
|   3 | `tnld login-token`                | Generate a login token.                                  |
|   4 | `tnld config check --config=PATH` | Validate server configuration without starting services. |
|   5 | `tnld version`                    | Print release version information.                       |

`serve` is the default command. Bare `tnld` and a command line beginning with a
serve flag select `serve`:

```text
tnld
tnld --role=ingress --control-hostname=control.example.test ...
tnld serve --role=ingress --control-hostname=control.example.test ...
```

Bare `tnld` does not print help. With no applicable environment it selects the
default `standalone` role and fails because the required pooled PostgreSQL URL
is absent. Named leaf commands take precedence over the default command. There
are no other command aliases.

Every leaf accepts `-h` and `--help`. `migrate`, `login-token`, and `version`
have no other flags. `config check` accepts only `--config`. All remaining
server flags belong to `serve`, including when `serve` is implicit.

### Value Syntax

- Scalar flags accept either `--flag value` or `--flag=value`.
- Boolean flags use bare `--flag` for true or an attached value such as
  `--flag=false`. Accepted attached and environment values are, ignoring case,
  `true`, `1`, `yes`, `false`, `0`, and `no`. There are no `--no-*` aliases.
- A separated boolean value such as `--flag false` is not accepted.
- Repeatable flags accumulate and each occurrence may contain comma-separated
  values. Repeatable environment values are comma-separated. Static files use
  arrays.
- Durations use Go duration syntax, including `250ms`, `30s`, `5m`, and `720h`.
  There is no `d` unit.
- Path flags and path-valued environment variables are expanded to absolute
  paths relative to the current working directory; `~/` is also expanded.
- None of the five leaves accepts a positional argument.

### Output And Exit Conventions

Generated help and successful `login-token` and `version` results go to stdout.
Successful `migrate` and `config check` commands are silent. A serving process
normally writes nothing to stdout; startup and runtime logs go to stderr through
the standard Go logger. Every returned error is printed once to stderr as:

```text
tnld: <error>
```

Successful finite commands and help exit with status 0. Parser, validation,
I/O, migration, startup, runtime, and output-write errors exit with status 1;
there are no separate usage or configuration exit statuses.

`serve` is long-running. SIGINT or SIGTERM begins graceful drain and a clean
shutdown exits 0. Shutdown errors are joined into the returned error and exit

1. Draining uses `drain_timeout`, followed by a separate cleanup window of up
   to six seconds, so a process supervisor's stop grace period should exceed the
   configured drain timeout. Retryable ingress and relay control failures are
   logged and retried without making the process ready. A terminal component error
   stops the process.

### Leaf Commands

#### `tnld serve`

```text
tnld [serve] [--config=PATH] [serve flags]
```

`serve` loads and validates configuration before opening services. Control and
standalone connect to an already-migrated PostgreSQL database and require the
supported schema version. They do not migrate on startup. Ingress and relay do
not use PostgreSQL. They register through control's private API with cluster
authentication.

The standard logger is not reconfigured. Log lines therefore use a local-time
`YYYY/MM/DD HH:MM:SS` prefix. Bound addresses come from the operating system,
so a configured `:443` may be printed as `[::]:443`. Background messages may be
interleaved with the representative startup sequences below.

Representative standalone stderr, which is also the concrete output example
for the `serve` leaf:

```console
$ tnld serve --config /etc/tnl/standalone.yml
2030/01/02 03:04:05 relay internal forwarding listening on 127.0.0.1:49152
2030/01/02 03:04:05 relay internal forwarding listening on 127.0.0.1:49153
2030/01/02 03:04:05 public ingress listening on 192.0.2.10:8443
2030/01/02 03:04:05 control API listening on 192.0.2.10:8443 for control.example.test
2030/01/02 03:04:05 relay publisher TCP listening on 192.0.2.10:8443 for relay.example.test
2030/01/02 03:04:05 relay publisher UDP listening on 192.0.2.10:8443
```

Standalone composes one ingress and two logical relay services. Control HTTPS,
visitor ingress, and relay TLS/TCP share the TCP address configured by
`ingress_listen`; QUIC uses `relay_udp_listen`; internal forwarding uses two
temporary listeners on localhost.

Representative control stderr:

```text
2030/01/02 03:04:05 control API listening on 192.0.2.20:8443
2030/01/02 03:04:05 private control API listening on 10.0.0.20:9443
```

Representative ingress stderr:

```text
2030/01/02 03:04:05 public ingress listening on 192.0.2.30:8443
```

Representative relay stderr:

```text
2030/01/02 03:04:05 relay internal forwarding listening on 10.0.0.40:9445
2030/01/02 03:04:05 relay publisher TCP listening on 192.0.2.40:8443
2030/01/02 03:04:05 relay publisher UDP listening on 192.0.2.40:8443
```

There is no general started or ready message, role summary, or metrics-listener
log. A listener message proves only that the listener opened. Use the process's
private `/ready` endpoint to check readiness for its role.

#### `tnld migrate`

```text
tnld migrate
```

`migrate` reads only `TNLD_DATABASE_DIRECT_URL`. It does not accept a URL
argument, `--database-url`, `TNLD_DATABASE_URL`, `--config`, or `TNLD_CONFIG`.
It creates the control schema and persistent migration lock when needed. The lock
allows only one migration at a time. The command applies embedded forward
migrations and verifies the resulting schema version. It has no down,
target-version, status, or dry-run mode.

Successful migration is silent. This is a complete representative success
example; there is no output after the command:

```console
$ TNLD_DATABASE_DIRECT_URL='postgresql://tnl_migrate:EXAMPLE_NOT_VALID@db.example.test/tnl?sslmode=require' tnld migrate
```

Migration changes PostgreSQL and then exits. Running the same binary again with
an up-to-date schema makes no changes. A newer database schema is rejected.

#### `tnld login-token`

```text
tnld login-token
```

This command uses cryptographic randomness and writes exactly one new login
token followed by a newline to stdout. It does not
persist the token and does not generate a cluster secret or storage key. Treat
the raw output as a credential.

Representative raw stdout with an intentionally invalid fake token:

```console
$ tnld login-token
tnl_login_EXAMPLE_ID_NOT_VALID.EXAMPLE_SECRET_NOT_VALID
```

#### `tnld config check`

```text
tnld config check --config=/path/to/tnl.yml
```

`TNLD_CONFIG` is the environment fallback for `--config`. One of them is
required. `check` loads the complete static document, applies serve defaults and
all ambient `TNLD_*` serve variables, resolves role defaults, and runs server
configuration validation. It does not start services.

Successful validation is silent. This is a complete representative success
example:

```console
$ tnld config check --config /etc/tnl/relay.yml
```

The command is finite and does not open listeners, connect to PostgreSQL,
contact control, perform OIDC discovery, contact ACME or Route 53, or read the
configured certificate and key files. The limits of this check are detailed
under Config Check Limits.

#### `tnld version`

```text
tnld version
```

`version` writes exactly one raw line followed by a newline. A build without
commit metadata prints `tnld <version>`; a release build with commit metadata
prints `tnld <version> (<commit>)`. A source build defaults to `tnld devel`.

Representative raw stdout with fake build metadata:

```console
$ tnld version
tnld v0.0.0-example (0000000000000000000000000000000000000000)
```

### Complete Serve Configuration

The tables below list every `serve` setting. File keys use snake case under the
top-level `tnld` object. Role abbreviations are `S` for standalone, `C` for
control, `I` for ingress, and `R` for relay. Every role parses every listed flag.
The Applies column shows which roles use it. Validation rejects some values for
the wrong role, but not every ignored value.

An empty default means the empty string. `[]` means an empty repeatable value.
Role-derived defaults are applied after flags, environment, and file values are
merged.

#### Selection, Database, And Observability

| Flag / file key                       | Environment           | Parser or effective default | Applies | Behavior                                                                             |
| ------------------------------------- | --------------------- | --------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `--config` / not a file field         | `TNLD_CONFIG`         | empty                       | all     | Select one explicit static server document.                                          |
| `--role` / `role`                     | `TNLD_ROLE`           | `standalone`                | all     | Enum: `standalone`, `control`, `ingress`, `relay`.                                   |
| `--database-url` / `database_url`     | `TNLD_DATABASE_URL`   | empty                       | S/C     | Required pooled PostgreSQL URL; forbidden in I/R.                                    |
| `--metrics-listen` / `metrics_listen` | `TNLD_METRICS_LISTEN` | `127.0.0.1:9090`            | all     | Private HTTP health, readiness, and Prometheus address; empty disables the listener. |

#### Listeners And DNS Names

| Flag / file key                                             | Environment                      | Parser or effective default                              | Applies               | Behavior                                                                             |
| ----------------------------------------------------------- | -------------------------------- | -------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------ |
| `--control-listen` / `control_listen`                       | `TNLD_CONTROL_LISTEN`            | empty; `:443` in S/C                                     | C                     | Public control HTTPS listener. Resolved but not separately bound in S.               |
| `--private-control-listen` / `private_control_listen`       | `TNLD_PRIVATE_CONTROL_LISTEN`    | empty; `:9443` in S/C                                    | C                     | Private ingress and relay API listener. Standalone uses direct in-process clients.   |
| `--ingress-listen` / `ingress_listen`                       | `TNLD_INGRESS_LISTEN`            | empty; `:443` in S/I                                     | S/I                   | Public visitor listener and standalone's shared public TCP listener.                 |
| `--relay-tcp-listen` / `relay_tcp_listen`                   | `TNLD_RELAY_TCP_LISTEN`          | empty; `:443` in S/R                                     | R                     | Public TLS/TCP publisher-connection listener. Resolved but not used in S.            |
| `--relay-udp-listen` / `relay_udp_listen`                   | `TNLD_RELAY_UDP_LISTEN`          | empty; `:443` in S/R                                     | S/R                   | Public QUIC publisher-connection listener.                                           |
| `--internal-relay-listen` / `internal_relay_listen`         | `TNLD_INTERNAL_RELAY_LISTEN`     | empty; R derives `:<port>` from `internal_relay_address` | R                     | Internal forwarding listener. Standalone creates temporary localhost listeners.      |
| `--dns-server` / `dns_server`                               | `TNLD_DNS_SERVER`                | empty                                                    | S/C with DNS provider | Resolver used to verify claimed domains; empty uses the system resolver.             |
| `--server-domain` / `server_domain`                         | `TNLD_SERVER_DOMAIN`             | empty                                                    | S/C                   | Required infrastructure suffix used to derive control, ingress, and relay hostnames. |
| `--control-hostname` / `control_hostname`                   | `TNLD_CONTROL_HOSTNAME`          | empty                                                    | I/R                   | Required canonical control hostname without scheme, path, or port.                   |
| `--private-control-address` / `private_control_address`     | `TNLD_PRIVATE_CONTROL_ADDRESS`   | empty                                                    | I/R                   | Optional private `host:port` dial override; TLS still verifies `control_hostname`.   |
| `--managed-deployment-domain` / `managed_deployment_domain` | `TNLD_MANAGED_DEPLOYMENT_DOMAIN` | empty                                                    | S/C                   | Required server-controlled domain for member namespaces.                             |

Listen addresses are canonical `host:port` values with decimal ports from 1
through 65535. An empty host such as `:443` is valid for a listener. IPv6
host-and-port values require brackets.

#### Public TLS And ACME

| Flag / file key                                                   | Environment                         | Parser or effective default                      | Applies | Behavior                                                               |
| ----------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------ | ------- | ---------------------------------------------------------------------- |
| `--control-tls-certificate-file` / `control_tls_certificate_file` | `TNLD_CONTROL_TLS_CERTIFICATE_FILE` | empty                                            | S/C     | Optional static control certificate chain.                             |
| `--control-tls-private-key-file` / `control_tls_private_key_file` | `TNLD_CONTROL_TLS_PRIVATE_KEY_FILE` | empty                                            | S/C     | Paired static control private key.                                     |
| `--relay-tls-certificate-file` / `relay_tls_certificate_file`     | `TNLD_RELAY_TLS_CERTIFICATE_FILE`   | empty                                            | S/R     | Optional static relay transport certificate chain.                     |
| `--relay-tls-private-key-file` / `relay_tls_private_key_file`     | `TNLD_RELAY_TLS_PRIVATE_KEY_FILE`   | empty                                            | S/R     | Paired static relay transport private key.                             |
| `--acme-directory-url` / `acme_directory_url`                     | `TNLD_ACME_DIRECTORY_URL`           | empty; Let's Encrypt production directory in S/C | S/C     | HTTPS ACME directory for automatic public certificates.                |
| `--acme-email` / `acme_email`                                     | `TNLD_ACME_EMAIL`                   | empty                                            | S/C     | Required plain ACME account email.                                     |
| `--acme-accept-terms` / `acme_accept_terms`                       | `TNLD_ACME_ACCEPT_TERMS`            | false                                            | S/C     | Must be true to accept the ACME directory terms.                       |
| `--acme-profile` / `acme_profile`                                 | `TNLD_ACME_PROFILE`                 | `tlsserver`                                      | S/C     | Certificate profile containing lowercase letters, digits, and hyphens. |
| `--route-certificate-workers` / `route_certificate_workers`       | `TNLD_ROUTE_CERTIFICATE_WORKERS`    | `4`                                              | S/C     | Concurrent route certificate workers per control process, from 1–8.    |

Certificate and key overrides must be supplied as pairs. Control overrides are
forbidden in I/R. Relay overrides are valid only in S/R. A static control
certificate does not remove the S/C ACME directory, email, and accepted-terms
requirements because control still owns route-certificate issuance.

#### Authority, OIDC, And Sessions

| Flag / file key                                       | Environment                   | Parser or effective default  | Applies                | Behavior                                                                             |
| ----------------------------------------------------- | ----------------------------- | ---------------------------- | ---------------------- | ------------------------------------------------------------------------------------ |
| `--oidc-issuer` / `oidc_issuer`                       | `TNLD_OIDC_ISSUER`            | empty                        | S/C                    | OIDC HTTPS discovery issuer.                                                         |
| `--oidc-client-id` / `oidc_client_id`                 | `TNLD_OIDC_CLIENT_ID`         | empty                        | S/C                    | OIDC public client ID, trimmed and at most 128 bytes.                                |
| `--oidc-login-flow` / `oidc_login_flow`               | `TNLD_OIDC_LOGIN_FLOW`        | empty                        | S/C                    | Enum: `device_code`, `authorization_code_pkce`.                                      |
| `--oidc-scope` / `oidc_scope`                         | `TNLD_OIDC_SCOPES`            | `[]`; effective `openid`     | S/C                    | Repeatable requested scopes; explicit values must be unique and include `openid`.    |
| `--login-token` / `login_token`                       | `TNLD_LOGIN_TOKEN`            | empty                        | S/C built-in authority | Required login token; forbidden with an external authority and in I/R.               |
| `--authority-endpoint` / `authority_endpoint`         | `TNLD_AUTHORITY_ENDPOINT`     | empty; effective control URL | S/C                    | External authority URL; empty selects the built-in authority.                        |
| `--access-token-lifetime` / `access_token_lifetime`   | `TNLD_ACCESS_TOKEN_LIFETIME`  | `1h`                         | S/C                    | New access-token lifetime, from `5m` through `720h`.                                 |
| `--refresh-token-lifetime` / `refresh_token_lifetime` | `TNLD_REFRESH_TOKEN_LIFETIME` | `720h`                       | S/C                    | Absolute control-session lifetime, at least the access lifetime and at most `8760h`. |

OIDC is optional with the built-in authority. If any OIDC setting is present,
issuer, client ID, and login flow are all required. Scopes must be nonempty,
unique, whitespace-free strings no longer than 128 bytes.

An external authority requires `authority_endpoint`, complete OIDC settings,
and `hosted_secret`; it rejects `login_token`. The authority endpoint must be a
canonical HTTPS origin without credentials, path, query, fragment, or an
explicit default port 443.

#### Route Usage And Route 53

| Flag / file key                                         | Environment                    | Parser or effective default | Applies           | Behavior                                                             |
| ------------------------------------------------------- | ------------------------------ | --------------------------- | ----------------- | -------------------------------------------------------------------- |
| `--route-usage-url` / `route_usage_url`                 | `TNLD_ROUTE_USAGE_URL`         | empty                       | S/C               | External route usage receiver base URL.                              |
| `--route-usage-token` / `route_usage_token`             | `TNLD_ROUTE_USAGE_TOKEN`       | empty                       | S/C               | Service token paired with `route_usage_url`.                         |
| `--route53-region` / `route53_region`                   | `TNLD_ROUTE53_REGION`          | `us-east-1`                 | S/C with Route 53 | AWS region used to sign Route 53 requests.                           |
| `--route53-managed-zone-id` / `route53_managed_zone_id` | `TNLD_ROUTE53_MANAGED_ZONE_ID` | empty                       | S/C               | Hosted zone for public route DNS.                                    |
| `--route53-server-zone-id` / `route53_server_zone_id`   | `TNLD_ROUTE53_SERVER_ZONE_ID`  | empty                       | S/C               | Hosted zone enabling relay transport certificate DNS-01.             |
| `--ingress-ipv4-address` / `ingress_ipv4_address`       | `TNLD_INGRESS_IPV4_ADDRESSES`  | `[]`                        | S/C managed DNS   | Repeatable stable ingress IPv4 addresses published in route records. |
| `--ingress-ipv6-address` / `ingress_ipv6_address`       | `TNLD_INGRESS_IPV6_ADDRESSES`  | `[]`                        | S/C managed DNS   | Repeatable stable ingress IPv6 addresses published in route records. |

The route usage URL and token must be configured together. The URL must use
HTTPS, except that HTTP on `localhost`, `127.x.x.x`, or `::1` is accepted, and
cannot contain credentials, query, or fragment.

Route 53 zone IDs are bare values without surrounding whitespace, spaces, or
`/`. A managed-zone ID requires at least one canonical ingress IP. Ingress IPs
require a managed-zone ID and must be unique and in the correct address family.
A server-zone ID does not require ingress IPs. AWS credentials come from the
AWS SDK default configuration chain; `tnld` has no AWS credential flags.

#### Cluster, Authority, And Storage Secrets

| Flag / file key                                         | Environment                    | Parser default | Applies                         | Behavior                                                                                                                                   |
| ------------------------------------------------------- | ------------------------------ | -------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `--cluster-secret` / `cluster_secret`                   | `TNLD_CLUSTER_SECRET`          | empty          | C/I/R                           | Required current shared secret for split-process private communication. Standalone rejects a configured value and generates one in memory. |
| `--cluster-secret-previous` / `cluster_secret_previous` | `TNLD_CLUSTER_SECRET_PREVIOUS` | empty          | C/I/R rotation                  | Optional previous cluster secret accepted during rolling rotation.                                                                         |
| `--hosted-secret` / `hosted_secret`                     | `TNLD_HOSTED_SECRET`           | empty          | S/C external authority          | Required current secret shared by control and the external authority.                                                                      |
| `--hosted-secret-previous` / `hosted_secret_previous`   | `TNLD_HOSTED_SECRET_PREVIOUS`  | empty          | S/C external authority rotation | Optional previous hosted secret.                                                                                                           |
| `--storage-key` / `storage_key`                         | `TNLD_STORAGE_KEY`             | empty          | S/C                             | Required unpadded base64url AES-256 key for recoverable PostgreSQL secrets.                                                                |
| `--storage-key-previous` / `storage_key_previous`       | `TNLD_STORAGE_KEY_PREVIOUS`    | empty          | S/C rotation                    | Optional different previous storage key used only during re-encryption.                                                                    |

Cluster and hosted secrets must be from 32 through 4096 bytes, contain no
whitespace or comma, and differ from their previous value. A storage key must
be the canonical unpadded base64url encoding of exactly 32 bytes; the previous
key must differ from the current key.

#### Split Process Identity And Addresses

| Flag / file key                                       | Environment                   | Parser default | Applies | Behavior                                                              |
| ----------------------------------------------------- | ----------------------------- | -------------- | ------- | --------------------------------------------------------------------- |
| `--ingress-id` / `ingress_id`                         | `TNLD_INGRESS_ID`             | empty          | I       | Required stable ingress process identity.                             |
| `--relay-service-id` / `relay_service_id`             | `TNLD_RELAY_SERVICE_ID`       | empty          | R       | Required stable relay service identity.                               |
| `--relay-id` / `relay_id`                             | `TNLD_RELAY_ID`               | empty          | R       | Required stable relay process identity.                               |
| `--relay-address` / `relay_address`                   | `TNLD_RELAY_ADDRESS`          | empty          | R       | Required relay address.                                               |
| `--internal-relay-address` / `internal_relay_address` | `TNLD_INTERNAL_RELAY_ADDRESS` | empty          | R       | Advertised internal forwarding host and port; operationally required. |

Configured process identities must be nonempty, no longer than 256 bytes,
trimmed, and free of whitespace. Ingress and relay process run IDs are generated
at startup and are not configurable. `relay_address` requires a canonical
hostname and decimal port. `internal_relay_address` should be a reachable
internal hostname and port; Config Check Limits describes its validation gap.

#### Capacity, Policy, And Timing

| Flag / file key                                               | Environment                       | Default | Applies | Behavior                                                                      |
| ------------------------------------------------------------- | --------------------------------- | ------- | ------- | ----------------------------------------------------------------------------- |
| `--source-connection-rate` / `source_connection_rate`         | `TNLD_SOURCE_CONNECTION_RATE`     | `50`    | S/I     | New connections/sec per source IPv4 address or IPv6 /64, per ingress process. |
| `--source-connection-burst` / `source_connection_burst`       | `TNLD_SOURCE_CONNECTION_BURST`    | `200`   | S/I     | Token-bucket burst allowance for each source on each ingress process.         |
| `--visitor-connection-limit` / `visitor_connection_limit`     | `TNLD_VISITOR_CONNECTION_LIMIT`   | `20000` | S/I     | Maximum concurrent visitor connections.                                       |
| `--route-connection-limit` / `route_connection_limit`         | `TNLD_ROUTE_CONNECTION_LIMIT`     | `500`   | S/I     | Maximum concurrent visitor connections per route.                             |
| `--publisher-connection-limit` / `publisher_connection_limit` | `TNLD_PUBLISHER_CONNECTION_LIMIT` | `1000`  | S/R     | Maximum publisher connections held by one relay process.                      |
| `--relay-stream-capacity` / `relay_stream_capacity`           | `TNLD_RELAY_STREAM_CAPACITY`      | `4096`  | S/R     | Maximum concurrent visitor streams held by one relay process.                 |
| `--require-proxy-header` / `require_proxy_header`             | `TNLD_REQUIRE_PROXY_HEADER`       | false   | S/I     | Require one trusted outer PROXY v2 header on public ingress.                  |
| `--quic-max-incoming-streams` / `quic_max_incoming_streams`   | `TNLD_QUIC_MAX_INCOMING_STREAMS`  | `4096`  | S/R     | Maximum incoming QUIC streams per publisher connection.                       |
| `--quic-idle-timeout` / `quic_idle_timeout`                   | `TNLD_QUIC_IDLE_TIMEOUT`          | `45s`   | S/R     | Publisher connection QUIC idle timeout.                                       |
| `--ingress-lease-duration` / `ingress_lease_duration`         | `TNLD_INGRESS_LEASE_DURATION`     | `30s`   | S/C     | Ingress lease duration granted by control.                                    |
| `--relay-lease-duration` / `relay_lease_duration`             | `TNLD_RELAY_LEASE_DURATION`       | `30s`   | S/C     | Relay lease duration granted by control.                                      |
| `--lease-renewal-interval` / `lease_renewal_interval`         | `TNLD_LEASE_RENEWAL_INTERVAL`     | `10s`   | S/I/R   | Ingress and relay lease renewal frequency.                                    |
| `--control-retry-interval` / `control_retry_interval`         | `TNLD_CONTROL_RETRY_INTERVAL`     | `1s`    | S/I/R   | Delay before retrying a transient control failure.                            |
| `--routing-table-wait` / `routing_table_wait`                 | `TNLD_ROUTING_TABLE_WAIT`         | `25s`   | S/I     | Maximum wait for ingress routing-table updates.                               |
| `--drain-timeout` / `drain_timeout`                           | `TNLD_DRAIN_TIMEOUT`              | `30s`   | all     | Graceful connection drain deadline.                                           |

All connection and stream capacities must be positive, including fields not
used by the selected role. Source connection rate must be positive and finite;
fractional rates are supported. Source connection burst must be a positive integer.
All timing values must be positive.
`lease_renewal_interval` must be shorter than both lease durations.
`routing_table_wait` must be a whole-second duration no greater than 25 seconds.

### Role Requirements And Applicability

| Role         | Required operational settings                                                                                                                    | Listeners and responsibilities                                                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `standalone` | `database_url`, `server_domain`, `managed_deployment_domain`, `acme_email`, `acme_accept_terms=true`, one authority configuration, `storage_key` | Composes control, ingress, and two logical relay services. Shares `ingress_listen` for public TCP and uses `relay_udp_listen` for QUIC.                             |
| `control`    | Standalone's control-owned settings plus `cluster_secret`                                                                                        | Uses PostgreSQL; serves public control HTTPS and the private ingress/relay API; manages placement, certificates, DNS, administration, and persistent runtime state. |
| `ingress`    | `control_hostname`, `cluster_secret`, `ingress_id`                                                                                               | Stateless; accepts visitor TCP, registers with control, loads the ingress routing table, and forwards each visitor connection once.                                 |
| `relay`      | `control_hostname`, `cluster_secret`, `relay_service_id`, `relay_id`, `relay_address`, and operationally `internal_relay_address`                | Stateless; accepts publisher TCP/QUIC and internal forwarding, registers with control, and retrieves relay TLS when no static override is configured.               |

Control and standalone require exactly one authority configuration. The built-in
authority leaves `authority_endpoint` empty and requires `login_token`. An
external authority sets `authority_endpoint`, `hosted_secret`, and complete OIDC
settings, and rejects `login_token`. OIDC may also be added to the built-in
authority.

Ingress and relay reject a database URL, login token, control TLS overrides,
hosted secrets, storage keys, Route 53 zones, and ingress DNS addresses. Control
and standalone reject the split-process fields `control_hostname`,
`private_control_address`, `ingress_id`, `relay_service_id`, `relay_id`,
`relay_address`, and `internal_relay_address`. Standalone also rejects configured
cluster secrets. Control rejects relay TLS overrides; ingress rejects both
control and relay TLS overrides.

Validation does not reject every unused setting. A stateless role can accept and
then ignore some namespace, ACME, OIDC, authority, or route-usage values. Supply
only the settings used by the selected role.

### Static Configuration Files

`tnld serve --config` and `tnld config check --config` accept static, versioned
YAML or JSON only:

```yaml
$schema: https://tnl.dev/schema/v1.json
version: 1
tnld:
  role: ingress
  metrics_listen: ""
```

The rules are:

- Supported filename extensions are `.yml`, `.yaml`, and `.json`, ignoring
  extension case.
- TypeScript configuration is rejected. There is no configuration discovery,
  evaluation, import, include, or interpolation.
- `version: 1` and an object-valued `tnld` section are required.
- `$schema` and a `tnl` client section may coexist with `tnld`.
- If `tnl` is present, it is also validated; an invalid client section makes a
  server configuration check fail.
- Unknown root, `tnl`, and `tnld` fields are rejected.
- YAML duplicate fields, custom tags, and multiple documents are rejected.
- JSON trailing content is rejected.
- The document must be valid UTF-8 and no larger than 1 MiB.
- `tnld` duration values are strings. Booleans and integers use their native
  YAML or JSON types. Repeatable values use arrays.
- Repeatable file keys remain singular: `oidc_scope`, `ingress_ipv4_address`,
  and `ingress_ipv6_address`. Their environment names are plural.

### Configuration Precedence

For each `serve` field, highest precedence wins:

```text
explicit command-line flag
  v
matching TNLD_* environment variable is present
  v
explicitly present tnld file field
  v
parser default
  v
role-derived default
```

An explicitly empty environment variable still overrides a file value. It may
disable the setting or fail validation. `--config` overrides `TNLD_CONFIG`.

`config check` accepts no serve-value flags, but it reparses every serve default
and `TNLD_*` environment value before applying the file. Ambient deployment
environment can therefore change or break a check. For an environment-neutral
file check, clear unrelated `TNLD_*` values.

Only control certificate and key paths that actually came from the static file
are resolved relative to the file's directory. Relay certificate and key paths
from a file remain relative to the process working directory. Paths from flags
or environment are expanded relative to the process working directory.

`TNLD_DATABASE_DIRECT_URL` is outside this precedence system. It belongs only
to `migrate` and is not a `serve` or file field.

### Serving Side Effects

Control and standalone perform or start the following work after validation:

- Open the pooled database and reject any schema version other than the exact
  supported version.
- Complete recoverable-secret re-encryption when a previous storage key is
  configured.
- Start expired ephemeral-route cleanup immediately and then at 30-second
  intervals.
- Load or create the ACME account and start route-certificate work.
- Optionally start DNS-01 for relay transport certificates, public route DNS,
  and external route-usage delivery.
- Load the AWS SDK default configuration when either Route 53 zone is
  configured.
- Open the role's public, private, and metrics listeners.

Ingress and relay generate a fresh process run ID, open their listeners, and
register and renew leases through control. A relay without a static TLS override
retrieves its relay transport certificate from control. Standalone generates an
in-memory cluster secret and never prints it.

Serving logs may include messages such as:

```text
2030/01/02 03:04:05 stored secrets re-encrypted with the current storage key
2030/01/02 03:04:05 public control certificate: <error>
2030/01/02 03:04:05 ingress control: <error>
2030/01/02 03:04:05 relay control: <error>
2030/01/02 03:04:05 ingress connection: <error>
2030/01/02 03:04:05 relay publisher: <error>
2030/01/02 03:04:05 relay forwarding: <error>
2030/01/02 03:04:05 ephemeral route cleanup: <error>
```

### Representative Errors

Parser and configuration errors occur before serving:

```text
tnld: pooled PostgreSQL database URL is required
tnld: TNLD_DATABASE_DIRECT_URL is required
tnld: --config or TNLD_CONFIG is required
tnld: unknown flag --state-dir
tnld: tnld configuration must use .yml, .yaml, or .json
tnld: tnld configuration section is required
tnld: load config /etc/tnl/server.yml: unsupported configuration version 2
```

Migration and serving failures preserve their component context:

```text
tnld: controlstate: migrate: connect database: <database error>
tnld: controlstate: incompatible database schema version <database-version>; supported version is <supported-version>
tnld: listen for public ingress: <network error>
tnld: listen for observability: <network error>
tnld: run relay control: <terminal control error>
```

Errors can contain platform- or dependency-specific text after the stable
context. Multiple shutdown failures may be joined onto separate lines beneath
the single `tnld:` prefix.

### Config Check Limits And Traps

`tnld config check` verifies the document structure, value types, precedence,
defaults, role rules, and other configuration rules. It does not:

- connect to PostgreSQL or verify the database or schema;
- open listeners or detect address conflicts;
- read or parse certificate and private-key files;
- perform OIDC discovery;
- contact ACME, Route 53, control, or a route usage receiver;
- verify that advertised addresses are reachable.

Known practical boundaries and documentation traps are:

- A relay can pass configuration checks with an empty
  `internal_relay_address`, then fail runtime construction with
  `relay: registration identifiers are required`. Treat that field as required.
- A pooled database URL can pass the first configuration validator without a
  database path, then fail the stricter control-state URL validation at serve
  time. Always name the database.
- Standalone does not separately bind `control_listen`,
  `private_control_listen`, `relay_tcp_listen`, or `internal_relay_listen`.
  Its actual listener topology is described under `tnld serve`.
- Listener logs are not readiness guarantees. A later metrics bind failure or
  an unready certificate or lease can follow earlier listener messages.
- `serve` never migrates the database. Run the matching binary's `migrate`
  command as an explicit deployment step.
- `login-token` creates only a login token for the built-in authority. It does
  not generate a cluster secret or storage key.
- Secrets are accepted as flags, but flags can be exposed through shell history
  and process inspection. Prefer deployment secret injection and never include
  real values in logs or documentation.

### Implementation Sources

The command tree and stream routing are in
[`cmd/tnld/main.go`](../cmd/tnld/main.go). The complete flag metadata, defaults,
role selection, and validation are in
[`internal/tnldconfig/config.go`](../internal/tnldconfig/config.go). Static file
loading and precedence are in [`internal/config`](../internal/config). Runtime
listeners, logs, side effects, and shutdown are in
[`internal/tnldruntime`](../internal/tnldruntime). Migration behavior is in
[`internal/controlstate/controlstate.go`](../internal/controlstate/controlstate.go).
