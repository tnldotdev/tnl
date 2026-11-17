# architecture

tnl connects visitors to apps and services on another machine.

Use this guide to follow a connection or find the code to change.
See [contributing](contributing.md) for setup and checks,
[AGENTS.md](AGENTS.md) for project rules, and `../tnl.dev` for product docs.

| Component | What it does                                                     |
| --------- | ---------------------------------------------------------------- |
| Control   | Checks permissions and stores server state in PostgreSQL.        |
| Ingress   | Accepts public connections and picks a connected relay.          |
| Relay     | Carries traffic between ingress or connectors and publishers.    |
| Publisher | Runs as `tnl`, accepts visitor traffic, and connects to the app. |
| Connector | Runs as `tnl`, opens a local port, and connects to a publisher.  |

`tnld` runs the server roles. Its `standalone` mode runs control, ingress,
and two logical relay services in one process. It still needs PostgreSQL.
Ingress and relay never open the database themselves.

## how an app publishes a service

The SDK tells the local `tnl` process where the app is listening.
`tnl` then asks control to start a service run:

```text
app + SDK             local tnl                 control
    |-- app address ----->|                        |
    |<-- registered ------|                        |
    |                     |-- create service run ->|
    |                     |<-- run + assignments --|
    |-- still running --->|                        |
```

Registration only means `tnl` accepted the app. Before visitors can connect,
the publisher needs permission, a certificate, and ready relay connections.
A public endpoint also needs ready ingress and DNS. Connector access can be
ready first; waiting for DNS does not stop the run.

The SDK keeps the registration alive while the app runs. `publisher/app`
stops and waits for the old publication before replacing it.
`publisher/local` runs this manager and the local API. All protocols use the
same service-run code.

## how visitors reach the app

A public visitor connects through ingress and a relay. Neither can read the
visitor's TLS traffic. That TLS connection ends at the publisher:

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

Each `TLS` arrow carries the same visitor connection. If the app needs TLS,
the publisher opens a separate TLS connection to it.

For HTTP, control sends routing and visitor policy ahead of requests. The
publisher checks access locally, then reserves ingress capacity before
forwarding. Ingress signs the visitor's socket addresses; the publisher checks
that signature. A capacity reservation is not permission to visit.

Prepared HTTP traffic can continue during a control outage until its last
confirmed deadline: five minutes by default, or sooner if a credential,
certificate, service, or parent session expires. A failed refresh adds no time.
Native client certificates still need a current control check.

Ingress can try another relay only before sending the first visitor byte.
Requests never trigger a control refresh or replay against another target.
See `internal/ingress` for cache-miss and relay-replacement rules.

PostgreSQL, MySQL, and TCP do not call control for each query or message.
Public Kubernetes checks control for each API request; connector Kubernetes
checks its admitted permission locally. Long-running requests still expire.

Public HTTP requests share a target connection pool for their service run.
Connector sockets stay tied to the visitor that opened them. Both use the
same target proxy. Recovery reports measure when traffic resumes; they do
not grant or renew access.

### service access through a connector

A connector reaches the publisher without ingress. It uses a relay, or direct
UDP when available:

```text
client       tnl connector      relay        publisher       target
   |-- TCP ------>|              |              |              |
   |              |-- encrypted->|-- encrypted->|              |
   |              |              |              |              |
   |              |-- direct UDP (optional) --->|              |
   |              |              |              |-- request -->|
   |              |              |              |<-- response -|
```

Both paths carry the same encrypted session. Changing paths does not duplicate
requests or retry a failed stream against another target.

During shutdown, the connector and publisher wait for stream cleanup and
acknowledge the result. Missing acknowledgments never extend the deadline.
See `connector/stream` and `publisher/service/stream` for that exchange.

A service may also have a public endpoint. HTTP services share ingress port 443
by TLS hostname; other protocols get an allocated port. Connector ports are
separate, local assignments. Changing a public endpoint does not stop authorized
connector sessions or change target trust. Public access still requires the
service's visitor permission.

## where state lives

`control/state` stores server state in PostgreSQL. It checks permissions in the
same transaction that changes state. Certificate and DNS workers carry out
work approved there.

`client/state` stores local sessions, keys, certificates, project records, and
locks in SQLite and private files. A saved credential is not proof of current
permission.

Project configuration names services in `services` and supplies targets in
`deployments.NAME.targets`. `tnl apply` updates the selected deployment without
removing sibling deployments. Selecting `local` does not create a saved server
deployment.

Apps, foreground commands, and installed jobs all use the same service-run code.
Management, publication, and connection permissions stay separate, even when
one process uses all three.

Feedback reports, evidence, source snapshots, and conversation history also live
in `client/state`, scoped to a local project/worktree, server, and preview.
Control checks current visitor or management access and verified authorship
without receiving that content. The publisher HTTP frontend and CLI compose
those decisions with the same SQLite owner; a decision never outlives its original
deadline while waiting for local state. There is no cross-machine feedback store.


## find the code

```text
cmd/
  tnl/                 client flags, prompts, and output
  tnld/                server flags and role selection
internal/
  publisher/           starts and manages publications
    app/               app registrations and replacement
    local/             local tnl process for a project
    localapi/          native app and CLI registration API
    invocation/        operations for publishing a service
    httpaccess/        shared HTTP policy and browser access
    requestlimit/      shared per-run HTTP request budgets
    service/           saved service runs and certificates
      stream/          visitor TLS, protocol, expiry, and target connection
    processidentity/   signed process identity and control lease
    identity/          publisher identities and grants
    deployment/        deployment assignments and publication
    target/            target selection and preparation
    browserapi/        generated browser API validators
    toolbar/           development-only browser assets
  connector/           selects and connects to a service
    runtime/           listeners, renewal, and expiry
    stream/            encrypted connections to a publisher
    workload/          workload authentication
    kubeconfig/        Kubernetes client configuration
  installed/           installed jobs, OS setup, and supervision
  daemon/              server startup and shutdown
  control/
    api/               public, authority, and private HTTP handlers
    state/             permission checks and updates in PostgreSQL
  ingress/             public visitor acceptance and forwarding
  relay/               publisher connections and visitor streams
  client/              shared auth, API clients, local state, and projects
    telemetry/         bounded collection and delivery of client telemetry
  config/              project configuration types and validation
  serverhttp/          shared HTTP decoding, errors, cookies, and auth
  naming/              checks shared names and IDs
  transport/           carries connections and streams
  policy/ security/    shared policy and security code
  failure/             diagnostics and error contracts
  observability/       measurements and event vocabulary
  clioutput/           ASCII output renderer
  browserpage/         standalone browser shell, styles, and bundled Fira Code
  testutil/            shared test-only fixtures
contracts/             HTTP OpenAPI sources and other shared inputs
pkg/
  api/                 generated HTTP API contracts
  protocol/tunnelv1/   handwritten tunnel protocol
  tnl/                 public Go SDK
packages/ts/           TypeScript SDK and framework integrations
packages/py/           Python ASGI binding and packaging
connect/               independently built GitHub Action
schema/                generated project configuration schema
tests/integration/     built-CLI tests and shared fixtures
tasks/ scripts/        checks, generation, and build tools
development/           contributor stack
deploy/                deployment templates
.github/workflows/     CI and releases
```

## how packages fit together

Commands handle flags, prompts, and output. They call reusable operations.
The code that starts a process, run, or stream also stops and waits for it:

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

Skip layers you do not need. Do not add wrappers just to follow this diagram.
A child package must not import its parent to reach a helper.

`browserpage` shares the layout and styles for device verification, sign-in,
handoff, and error pages. It uses only bundled fonts and the standard library. The font is
inside the CSS, so pages work without the app or a font endpoint. Each caller
still handles permissions, redirects, status codes, and security headers.

### shared HTTP code

Public and connector HTTP requests use the same service code:

```text
invocation + deployment --> publisher/service
                                    |
                                    +--> httpaccess + requestlimit
                                    |
                                    +--> service/stream
```

- `httpaccess` checks visitor access and handles policy refresh, browser
  handoffs, cookies, and token renewal.
- `requestlimit` shares one request budget across a run's connections.
- `service/http.go` puts these pieces together.
- `service/stream` handles visitor TLS, protocols, target connections, and cleanup.
- `observability/inspection` records request summaries without bodies.

Readiness probes have a separate budget and secret. A successful visitor request
is not a readiness proof.

These packages must not import publisher root.

### installed jobs

Installed jobs use publisher operations, not the other way around:

```text
installed --> publisher/deployment --> publisher/service
    |
    +-------> shared client packages
```

`installed` manages saved jobs, OS service setup, restarts, and shutdown.
It calls publisher and connector operations. Shared clients must not import it.
A saved job does not grant permission to publish.

`publisher/deployment` publishes assignments for foreground commands too.
It does not need the installed-job registry.

### other important dependencies

- `publisher/local` combines `app`, `localapi`, and `invocation`. It supplies
  operations to the API; the API does not call back into the process owner.
- Connector operations use `connector/runtime` and `connector/stream`. Neither
  child imports connector root.
- `control/state` never imports HTTP handlers. Ingress and relay use control API
  clients, not control state.
- `transport` handles connections, not process startup, relay assignment, or
  visitor policy.

Use shared values directly. For example, use `policy/applicationlimits.Limits`,
not a publisher alias. Shared names belong under `naming`; shared Amazon RDS
certificates belong in `security/rdsroots`.

For shared behavior, put a small interface where it is used. Supply the
implementation from the caller. Do not copy permission checks or service-run
code to avoid an import.

## where to put a change

Start where the work already happens. Add a package only for a separate job
with a real caller, not because a file is large.

| Change                          | Start here                                                                 |
| ------------------------------- | -------------------------------------------------------------------------- |
| Replace an app registration     | `publisher/app`; stop and wait for the old publication first.              |
| Renew a connector               | `connector/runtime`; keep renewal and fixed expiry together.               |
| Approve certificate issuance    | `control/state`; check the current run, grant, and certificate plan.       |
| Claim a publisher connection    | `relay` for the local session; `control/state` for the durable claim.      |
| Change HTTP visitor access      | `publisher/httpaccess`.                                                    |
| Change per-run HTTP limits      | `publisher/requestlimit`.                                                  |
| Change QUIC or yamux mechanics  | `transport/muxsession`.                                                    |
| Change configuration syntax     | `config` for types and validation; `client/project` for evaluation.        |
| Resolve project metadata        | `client/project/resolve`; `client/project/meta` writes portable artifacts. |
| Change project initialization   | `client/project/init`; commands supply prompts and output.                 |
| Change CLI frames               | `clioutput`; commands supply facts, not borders or padding.                |
| Change standalone browser pages | `browserpage` for layout and styles; the handler for behavior.             |

Choose by the work, not the executable. `tnl publish` is publisher work,
`tnl connect` is connector work, `tnl apply` sends a control change, and `tnld`
starts server roles. One process can run publisher and connector operations
without combining their permissions.

## starting work means owning cleanup

The code that starts work must stop it and wait for cleanup before returning.
This includes workers, renewal loops, locks, sockets, and temporary files.
Reporting progress to a command does not make the command responsible for cleanup.

Cancellation is only a stop request. Keep real operation and cleanup errors even
if cancellation happens at the same time. In particular,
`errors.Is(err, context.Canceled)` can match a joined error that contains another
failure too.

Pass deadlines, endpoint details, identities, and permissions explicitly.
HTTP access checks use the visitor address from the accepted stream, not
forwarding headers.

Keep visitor TLS separate from target TLS. A public endpoint does not grant
visitor access or change which target certificates the publisher trusts.

Protect reads from background updates. Keep secrets out of JSON, logs, diagrams,
metadata, and snapshots. The public Go SDK exposes a prepared publisher identity,
not its key or control client.

## generated code

Edit the source, then regenerate:

| Source                                                  | Generated output                                                       |
| ------------------------------------------------------- | ---------------------------------------------------------------------- |
| `contracts/control/**/v1`                               | Four matching Go packages under `pkg/api/control`.                     |
| `contracts/control/public/v1` management operations     | Fetch-only TypeScript SDK under `packages/ts/src/internal/management`. |
| `contracts/publisher/{local,browser}/v1`                | Two Go packages and browser API validators.                            |
| `contracts/integrations/telemetry/v1`                   | Go telemetry models and TypeScript validators.                         |
| `internal/control/state/{migrations,queries,sqlc.yaml}` | PostgreSQL access in `controlstatedb`.                                 |
| `internal/client/state/{migrations,queries,sqlc.yaml}`  | SQLite access in `clientstatedb`.                                      |
| `internal/config` and its generators                    | JSON Schema, SDK configuration types, and keys.                        |
| `internal/client/project/loader.ts`                     | Embedded JavaScript loader.                                            |

Each HTTP contract belongs to the component serving it. Edit its OpenAPI
`paths/`, `schemas/`, and generator settings, not generated code.
Reuse the same schema for identical fields on the wire.

`pkg/protocol/tunnelv1` is handwritten. Test its wire format directly;
do not add a second definition in JSON Schema. See the
[contracts guide](contracts/readme.md) for other shared inputs.

From the repository root:

```sh
mise exec -- task generate
mise exec -- task format
```

`generate-check` rewrites files before comparing them with `HEAD`.
Commit intended generated changes first. See
[edit generated sources](contributing.md#edit-generated-sources) for details.

## tests and dependency checks

Keep Go tests and `testdata` beside their implementation. Shared test fixtures
go under `internal/testutil`.

Built-CLI tests live in `tests/integration/<boundary>`, with shared subprocess and
Compose fixtures in `tests/integration/fixtures`. TypeScript tests and fixtures
live in `packages/ts/test`; Python tests stay in `packages/py`.

Move tests with the code. Keep each unique assertion and its Task selector.

Use Task targets; CI uses the same targets. Routine tests need no external
infrastructure. Integration tests use the smallest real setup needed.
PostgreSQL-backed targets create and remove their own digest-pinned disposable
database. Large load and fault sweeps require explicit opt-in. Put check results
in the PR, not this guide.

`internal/daemon/package_dependencies_test.go` checks the import rules above.
Keep detailed implementation rules and their tests with the code, not in this
guide.
