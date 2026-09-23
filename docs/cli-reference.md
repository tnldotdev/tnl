# `tnl` cli reference

`tnl` publishes local HTTP services and manages the teams, domains, and routes
used by those tunnels. This page is a concise command reference. Run
`tnl <command> --help` for generated help at the terminal.

See [project configuration](project-configuration.md) for config files and
precedence. See [automation](automation.md) before consuming command output from
another program.

## command index

### start and inspect tunnels

| Command       | Purpose                                  |
| ------------- | ---------------------------------------- |
| `tnl init`    | Set up tnl for the current project.      |
| `tnl dev`     | Run and publish one development service. |
| `tnl publish` | Publish an existing local HTTP service.  |
| `tnl status`  | Show local tunnel processes.             |

### authenticate and configure

| Command               | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `tnl login`           | Authenticate to a tnl server.                          |
| `tnl logout`          | Revoke and remove a saved control session.             |
| `tnl config path`     | Show the selected project configuration.               |
| `tnl config check`    | Validate project configuration.                        |
| `tnl config generate` | Generate project metadata and TypeScript declarations. |

### manage teams

| Command                    | Purpose                                 |
| -------------------------- | --------------------------------------- |
| `tnl team current`         | Show the effective team.                |
| `tnl team list`            | List current memberships.               |
| `tnl team use`             | Save a team selection.                  |
| `tnl team create`          | Create and select an organization team. |
| `tnl team members`         | List team memberships.                  |
| `tnl team invite create`   | Create a one-time invitation.           |
| `tnl team invite list`     | List invitations.                       |
| `tnl team invite revoke`   | Revoke an invitation.                   |
| `tnl team join`            | Accept an invitation.                   |
| `tnl team member set-role` | Change a membership role.               |
| `tnl team member remove`   | Remove a membership.                    |

### manage domains and routes

| Command              | Purpose                   |
| -------------------- | ------------------------- |
| `tnl domain claim`   | Claim a domain.           |
| `tnl domain default` | Set the default domain.   |
| `tnl domain list`    | List team domains.        |
| `tnl domain release` | Release a claimed domain. |
| `tnl route list`     | List routes.              |
| `tnl route delete`   | Delete a route.           |

### administer a tnl server

| Command                       | Purpose                                  |
| ----------------------------- | ---------------------------------------- |
| `tnl admin server status`     | Show control, ingress, and relay status. |
| `tnl admin relays list`       | List relay process leases.               |
| `tnl admin relays drain`      | Drain one exact relay process lease.     |
| `tnl admin maintenance list`  | List maintenance controls.               |
| `tnl admin maintenance allow` | Allow one gated operation.               |
| `tnl admin maintenance block` | Block one gated operation.               |

`tnl version` prints the release version and optional commit.

## global flags

Every command accepts:

| Flag             | Environment        | Meaning                                  |
| ---------------- | ------------------ | ---------------------------------------- |
| `-h`, `--help`   | none               | Show context-sensitive help.             |
| `--config=PATH`  | `TNL_CONFIG`       | Select project configuration.            |
| `--no-config`    | none               | Disable project configuration discovery. |
| `--no-telemetry` | `TNL_NO_TELEMETRY` | Disable pseudonymous usage telemetry.    |

`--config` and `--no-config` cannot be used together. Commands that do not use
project configuration still expose these global parser flags.

## telemetry

The client sends pseudonymous usage telemetry to
`https://tnl.dev/api/telemetry` by default, including when it connects to a
self-hosted tnl server. Disable it with `--no-telemetry` or
`TNL_NO_TELEMETRY=true`.

Telemetry includes an installation ID, command and event names, client version,
OS, architecture, CI presence, framework category, and whether the selected
server is hosted or self-hosted. It does not include command arguments, tokens,
hostnames, local paths, or visitor traffic. The receiver can see ordinary
network information such as the source IP.

## remote flags

Commands that call a tnl server generally accept:

| Flag                   | Fallbacks, from highest to lowest                          |
| ---------------------- | ---------------------------------------------------------- |
| `--server=URL`         | `TNL_SERVER`, project server, saved server, hosted default |
| `--access-token=TOKEN` | `TNL_ACCESS_TOKEN`, saved session, interactive login       |
| `--state-dir=PATH`     | `TNL_STATE_DIR`, platform client-state directory           |

The control URL must use HTTPS and must not contain credentials, a query,
fragment, or non-root path.

An explicit access token requires an explicit server from `--server` or
`TNL_SERVER`. This prevents a token from being sent to a destination selected
only by project configuration.

## tunnel flags

`tnl dev` and `tnl publish` accept:

| Flag                    | Environment         | Meaning                                                  |
| ----------------------- | ------------------- | -------------------------------------------------------- |
| `--open`                | none                | Open the first ready URL in the default browser.         |
| `--team=TEAM`           | `TNL_TEAM`          | Select a team for this command.                          |
| `--host=HOSTNAME`       | `TNL_HOST`          | Use one complete authorized hostname.                    |
| `--subdomain=LABEL`     | `TNL_SUBDOMAIN`     | Use one label in the member namespace.                   |
| `--allow-ip=PREFIX`     | none                | Add an allowed visitor address or prefix; repeatable.    |
| `--allow-all-ips`       | `TNL_ALLOW_ALL_IPS` | Accept visitors from every address.                      |
| `--ephemeral`           | `TNL_EPHEMERAL`     | Delete the route when the tunnel stops.                  |
| `--request-limit=COUNT` | `TNL_REQUEST_LIMIT` | Set the concurrent publisher request limit; default 500. |

`--host` and `--subdomain` are mutually exclusive. `--allow-all-ips` and
`--allow-ip` are also mutually exclusive.

Without `--allow-all-ips`, tnl always includes the current client IP in the
route policy. Excess publisher requests receive HTTP 503 with `Retry-After: 1`
before reaching the local service.

## initialize a project

```text
tnl init [--no-install]
```

`tnl init` finds the nearest package root, detects npm, pnpm, Yarn, or Bun, and
detects supported Next.js or Vite dependencies. It can:

- install `@tnldotdev/tnl` as a development dependency;
- create `tnl.config.ts` when no project configuration exists;
- create a missing framework configuration;
- add `.tnl/` to `.gitignore`;
- report manual actions without rewriting existing configuration.

Use `--no-install` to report the dependency command instead of running it. The
initializer reports ambiguity rather than guessing which package manager,
framework, or existing configuration to modify.

## run development

```text
tnl dev [<service>] [flags] [-- <command> [args...]]
```

Unique flags are:

| Flag                         | Meaning                                                  |
| ---------------------------- | -------------------------------------------------------- |
| `--port=PORT`                | Require one exact local service port.                    |
| `--startup-timeout=DURATION` | Set the local startup wait; default `2m`, maximum `10m`. |

The optional service must exist in project configuration. A project with one
service selects it automatically. A project with several services requires a
name.

The command after `--` overrides `dev.command`. Project-local executables in the
service's `node_modules/.bin` take precedence over `PATH`.

`tnl dev` generates project metadata, creates a private framework-registration
socket, starts the child when configured, waits for the local target, and then
starts publishing. Only one `tnl dev` process can own the same project service.

The command preserves child stdin, stdout, and stderr. It sends SIGTERM to the
child process group during shutdown, then SIGKILL after five seconds if needed.

## publish an existing service

```text
tnl publish [<service-or-target>] [--output=human|ndjson] [flags]
```

The argument can be a configured service, a port, `localhost:<port>`, or a
loopback `http://` origin. Paths, queries, fragments, HTTPS targets, whitespace,
and non-loopback hosts are rejected.

The target must be listening before tnl authenticates or changes server state.
The command keeps publishing until cancellation or failure. An ephemeral route
is deleted during clean shutdown.

Use `--output=ndjson` for a machine-readable event stream. The complete contract
is in [automation](automation.md#follow-publish-events).

## inspect local tunnels

```text
tnl status [--all] [--output=human|json] [--state-dir=PATH]
```

Status reads local client state. It does not call control or list every stored
route.

Without `--all`, it selects the current project from configuration or the Git
worktree. With `--all`, it includes every known local project. Records whose
local lease expired appear as `stale`.

The JSON contract is in [automation](automation.md#read-a-status-snapshot).

## log in

```text
tnl login [<server>] [--token] [--server=URL] [--state-dir=PATH]
```

Login always performs a fresh authentication and saves the resulting control
session. It may open an interactive OIDC flow when the selected server supports
one.

Use `--token` to force login-token authentication. The flag selects the method;
it is not the token itself. Without `TNL_LOGIN_TOKEN`, tnl prompts without echo
on an interactive terminal.

When replacing a saved session, tnl attempts to revoke the previous session.

## log out

```text
tnl logout [--server=URL] [--state-dir=PATH]
```

Logout attempts to revoke the saved session and removes it locally. An already
invalid access token does not prevent local removal. The saved server and team
selection remain.

## inspect project configuration

```text
tnl config path
tnl config check [--state-dir=PATH]
tnl config generate [--state-dir=PATH]
```

`config path` selects but does not evaluate configuration. `config check` loads
and validates the file without contacting a tnl server.

`config generate` authenticates, resolves each service's team and domain, and
writes `.tnl/project.json` and `.tnl/project.d.ts`. It does not edit
`tsconfig.json`; it reports a required include as an action.

## select and create teams

```text
tnl team current
tnl team list
tnl team use <team>
tnl team create --member-slug=SLUG <display-name>
```

Each control URL has its own saved team selection. A project team override takes
precedence without changing that saved selection. Without either selection, tnl
uses the personal team.

Team arguments accept an ID or unambiguous display name. Duplicate display names
require an ID. Creating an organization team also selects it.

Roles are `member`, `admin`, and `owner`.

## manage team membership

```text
tnl team members [--team=TEAM]
tnl team invite create --member-slug=SLUG [flags]
tnl team invite list
tnl team invite revoke <invitation-id>
tnl team join <secret>
tnl team member set-role --role=ROLE <membership-id>
tnl team member remove <membership-id>
```

Invitation creation accepts:

| Flag                    | Default  | Meaning                                     |
| ----------------------- | -------- | ------------------------------------------- |
| `--member-slug=SLUG`    | required | Reserve an immutable member slug.           |
| `--role=ROLE`           | `member` | Initial `member`, `admin`, or `owner` role. |
| `--email=EMAIL`         | unset    | Restrict acceptance to a verified email.    |
| `--expires-in=DURATION` | `168h`   | Set a positive invitation lifetime.         |

`tnl team invite create` writes the invitation ID, a tab, and the one-time secret
to stdout. Treat the second field as a credential. The join secret can also
remain in shell history.

## manage domains

```text
tnl domain claim <domain> [--default]
tnl domain default <domain>
tnl domain list
tnl domain release <domain>
```

Domain commands use the project team when configured, then the saved or personal
team.

`domain claim` prints the DNS records needed to prove authority. With
`--default`, the domain becomes the default after it is ready. `domain default`
and `domain release` accept a domain ID or name already available to the team.

Managed deployment domains are controlled by the server. Claimed domains belong
to one team after DNS verification.

## manage routes

```text
tnl route list
tnl route delete <route-id>
```

A route maps a public hostname to a target, policy, scope, and state. These
commands use the project team when configured, then the saved or personal team.

`route delete` matches by route ID. Deleting a route releases its stored mapping;
do not delete a route whose hostname should remain reserved for another
publishing run.

## inspect a server

```text
tnl admin server status
tnl admin relays list
tnl admin maintenance list
```

Administrative commands ignore project configuration. They use `--server`,
`TNL_SERVER`, saved state, or the hosted default, and require an administrator
identity.

Server status summarizes the control role, ingress and relay leases, routes, and
route sessions. Relay listing reads every cursor page and includes the exact
process run ID and lease revision needed to drain a process.

## drain a relay process

```text
tnl admin relays drain <relay-id> \
  --relay-run-id=ID \
  --relay-lease-revision=REVISION \
  [--deadline=30s]
```

The relay ID, process run ID, and positive lease revision identify one exact
lease. Draining rejects new work while existing visitor streams finish until the
deadline.

## control maintenance gates

```text
tnl admin maintenance allow <name>
tnl admin maintenance block <name>
```

Supported names are:

```text
route_creation
route_session_creation
certificate_issuance
```

Maintenance gates affect new work. They do not stop existing routes or route
sessions.

## print the version

```text
tnl version
```

The command writes one raw line to stdout. A release build includes the version
and, when available, its commit. A source build normally reports `tnl devel`.

## output and errors

Human results use plain ASCII diagrams no wider than 72 columns. Finite results
go to stdout. Prompts, lifecycle output, warnings, and errors go to stderr.

Known failures include a stable diagnostic code and help URL. Unclassified
errors contain human text only. See [automation](automation.md) for exact stream
and machine-output behavior.
