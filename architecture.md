# architecture

tnl connects visitors to apps and services running elsewhere. Control decides
who may publish and connect. Ingress, relays, and direct UDP paths carry traffic.
The publisher connects it to the target.

This is the repository map. See [contributing](contributing.md) for commands,
[AGENTS.md](AGENTS.md) for rules, and [tnl.dev/docs](https://tnl.dev/docs) for
product and operator guides.

## how an app publishes a service

The SDK reports the listener its app opened. The local `tnl` process registers
it and starts publishing:

```text
app + SDK              local tnl                control
    |-- bound listener -->|                        |
    |<-- registered ------|                        |
    |                     |-- create service run ->|
    |                     |<-- run + assignments --|
    |-- renew ownership ->|                        |
```

Registration is not readiness. The publisher still needs permission, a
certificate, and ready publisher connections. A public endpoint also needs
ingress and DNS; connector access can be ready first.

The SDK renews ownership while the app runs. `publisher/app` stops an old
publication before replacing it. `publisher/local` runs that manager and the
local API. All protocols use the same service-run code.

## how visitors reach the app

Here is the relay path for a public endpoint:

```text
visitor        ingress         relay           tnl          target
   |-- TLS ------>|              |              |             |
   |              |-- TLS ------>|              |             |
   |              |              |-- TLS ------>|             |
   |              |              |              |-- request ->|
   |              |              |              |<- response -|
   |              |              |<-- TLS ------|             |
   |              |<-- TLS ------|              |             |
   |<-- TLS ------|              |              |             |
```

Each TLS arrow carries bytes from the same visitor connection. Visitor TLS ends
at the publisher. A TLS target gets a separate connection with its own trust
settings.

Ingress may try another eligible relay before sending the first visitor byte.
After that byte, it never retries the connection against another relay.

### services through a connector

A local `tnl` connector reaches a service without ingress:

```text
client       tnl connector      relay        publisher       target
   |-- TCP ------>|              |              |              |
   |              |-- encrypted->|-- encrypted->|              |
   |              |-- direct UDP (optional) --->|              |
   |              |              |              |-- request -->|
   |              |              |              |<-- response -|
```

Control authorizes the connection before traffic flows. Relay and direct UDP
carry the same encrypted peer session; changing paths does not replay requests.
Public endpoint access starts at ingress and can also use a direct publisher
path. Making an endpoint public does not remove its access rules.

## who decides what

| Component | Owns                                                                                    |
| --------- | --------------------------------------------------------------------------------------- |
| Control   | Permissions, saved records, runs, relay assignments, leases, and certificate approvals. |
| Ingress   | Public visitor connections and forwarding under control's current routing policy.       |
| Relay     | Publisher connections and visitor streams.                                              |
| Publisher | Publications, visitor TLS, and target connections.                                      |
| Connector | Service selection, local listeners, and encrypted connections to publishers.            |

Only control opens the server's PostgreSQL database. It checks permission in the
transaction that changes state. Ingress and relays use control-issued permissions
and leases. `standalone` runs control, ingress, and two logical relay services in
one `tnld` process, still backed by PostgreSQL.

Control stores each ingress pool's allocation inventory. Split ingress reads it
before binding listeners, then reports its live HTTPS and port capabilities.
Startup verifies saved pool policy; explicit pool operations change it. Per-run
traffic policy belongs to control, while ingress and relays own process budgets.

Client state uses SQLite and private files for sessions, keys, certificates,
project records, feedback, and locks. Feedback content stays with the local
publisher; control checks access and authorship. A cached credential is not
proof of current permission.

## native and portable sdks

Node, Bun, and Python use native `tnl` processes. Browser and Cloudflare SDKs run
the same Go connector and service-run code through Go/WASM, without a local
listener. TypeScript supplies Fetch, WebSockets, streams, and storage.

Native relay connections use QUIC or WSS with yamux. Portable SDKs use WSS only
and have no direct UDP path. Browsers and Durable Objects can own publishers;
ordinary Workers own request-scoped connectors. `packages/ts/wasm` composes these
owners rather than implementing another tunnel engine.

## find the code

```text
cmd/tnl, cmd/tnld       flags, process composition, output
internal/
  control/             server APIs and durable state
  ingress/             public visitor acceptance and forwarding
  relay/               publisher connections and visitor streams
  daemon/              server startup and shutdown
  publisher/           service publication and app registrations
    service/           service runs and target streams
    deployment/        publication of deployment assignments
    local/             project-scoped local tnl process
  connector/           visitor-side service connections
  installed/           installed jobs and OS supervision
  client/              shared auth, API clients, state, and projects
  config/              project configuration types and validation
  transport/           connection and multiplexing mechanics
  policy/, security/   shared policy and security code
  clioutput/           client ASCII output renderer
contracts/             OpenAPI sources
pkg/api/               generated HTTP APIs
pkg/protocol/tunnelv1/  handwritten tunnel protocol
pkg/tnl/               public Go SDK
packages/{ts,py}/       TypeScript and Python SDKs
packages/ts/wasm/       Go/WASM SDK composition and host bindings
connect/               GitHub Action
tests/integration/     built-CLI tests and shared fixtures
tasks/, scripts/       checks, generation, and packaging
development/, deploy/  local stack and deployment templates
```

## how packages fit together

```text
commands and SDK adapters
           |
           v
       operations
           |
           v
processes, runs, and streams
           |
           v
shared clients, values, transport, and contracts
```

Commands handle arguments and presentation. Operations do reusable work. The
owner of a process, run, or stream starts its workers and waits for them to stop.
Cancellation requests cleanup; it does not prove cleanup finished.

Start with the package that already owns the work. Add a package for a separate
responsibility with a real caller, not because a file grew large. A child package
must not import its parent just to reach a helper.

Some boundaries worth knowing:

- `control/state` owns transactional permission checks and updates; it never
  imports HTTP handlers. Ingress and relay use control API clients, not state.
- `publisher/local` composes `app`, `localapi`, and `invocation`; the API does
  not call back into the process owner.
- `publisher/service` composes `httpaccess`, `requestlimit`, and `service/stream`
  for public and connector traffic. Those packages never import publisher root.
- `installed` uses publisher and connector operations. Shared client packages
  never import installed-process code.
- Project configuration types belong to `config`; evaluation and resolution
  belong to `client/project`. CLI commands supply arguments and prompts.

The dependency tests in `internal/daemon/package_dependencies_test.go` enforce
these directions. Keep detailed behavior, package comments, and tests with their
implementation. Use [generation commands](contributing.md#edit-generated-sources)
when changing a contract or schema.
