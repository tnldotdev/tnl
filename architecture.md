# architecture

tnl connects visitors to apps and services running elsewhere. Control decides
who may publish and connect. Ingress and relays carry connections. The publisher
connects them to the app.

This guide explains those paths and where their code lives. For setup and check
commands, see [contributing](contributing.md). For terms and repository rules,
see [AGENTS.md](AGENTS.md). Product and operator docs live in `../tnl.dev`.

## how an app gets a public url

An SDK tells the local `tnl` process which listener the app opened. `tnl` accepts
the registration, then starts publishing in the background:

```text
app + SDK             local tnl                 control
    |-- bound listener -->|                        |
    |<-- registered ------|                        |
    |                     |-- create publish run ->|
    |                     |<-- run + assignments --|
    |-- renew ownership ->|                        |
```

Registration does not mean the public URL is ready. The publisher still needs
permission, a certificate, and connections to its assigned relays. Certificate
and relay setup are omitted from this diagram.

The SDK renews the registration while the app is running. `publisher/app` manages
registrations and stops the old publication before replacing it.
`publisher/local` runs that manager and the local API.

## how visitors reach the app

A public visitor connects through ingress and a relay. Visitor TLS passes
through both and ends at the local `tnl` publisher:

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

Each `TLS` arrow carries bytes from the same visitor connection. If the target
needs TLS, the publisher opens a separate TLS connection using the target's
trust settings. Authentication between server roles does not replace visitor TLS.

Ingress may try another eligible relay before sending the first visitor byte.
After that byte, it never retries the connection against another relay.

### service access through a connector

A local `tnl` connector reaches a service without ingress. It opens an encrypted
peer session to the publisher, through a relay or over direct UDP when available:

```text
client       tnl connector      relay        publisher       target
   |-- TCP ------>|              |              |              |
   |              |-- encrypted->|-- encrypted->|              |
   |              |              |              |              |
   |              |-- direct UDP (optional) --->|              |
   |              |              |              |-- request -->|
   |              |              |              |<-- response -|
```

Control setup is omitted. The two delivery paths carry the same session; they
do not send duplicate application requests. Relay delivery remains available
when direct UDP is not. Changing paths does not replay a failed stream against
another target.

A service can also have a public hostname and port, reached through ingress.
That is **public endpoint access**, rather than **connector access**. Making an
endpoint public does not remove its visitor access rules.

HTTP services share ingress 443 by exact TLS hostname. Other protocols use
allocated ingress ports. Neither selects the connector's machine-local listener.
Endpoint allocation and release advance `endpoint_revision`, not target trust;
authorized runs and connector sessions survive those changes. Public admission
still checks the current endpoint, and a retired port cannot select that service.
Port quarantine captures outstanding certificate issuance by revision, so a late
certificate can delay reuse without later connector renewals pinning capacity.

## who decides what

| Role      | Job                                                                                         |
| --------- | ------------------------------------------------------------------------------------------- |
| Control   | Stores identities, permissions, runs, relay assignments, leases, and certificate approvals. |
| Ingress   | Accepts public connections and picks a connected relay from control's routing table.        |
| Relay     | Holds publisher connections and carries visitor streams.                                    |
| Publisher | Publishes apps and services, ends visitor TLS, and connects to targets.                     |
| Connector | Selects a service, opens local listeners, and connects to its publisher.                    |

Control stores shared server state in PostgreSQL. Ingress and relay do not open
that database. They enforce control-issued permissions and leases, along with
their own capacity limits.

The `standalone` role runs control, ingress, and two logical relay services in
one `tnld` process. It still needs PostgreSQL.

### server state and local state are different

`control/state` checks permission in the transaction that changes state. Creating
a run, for example, checks the current grant and locks the rows used to assign
relays. Certificate and DNS workers carry out work approved there. Keep related
checks, updates, and lock ordering together, not in separate HTTP handlers.

`client/state` stores local sessions, publisher keys, pending certificate requests,
certificate caches, project records, and locks. It uses SQLite and private files.
A cached credential or certificate does not prove current permission to serve.

### project declarations and deployment bindings

Project configuration declares service names and protocols in `services`.
`deployments.NAME.targets` supplies targets and publication settings for one
selection. Selecting `local` resolves client-side targets; it does not create a
saved server deployment.

Apply reconciles the selected deployment and the project's logical declarations.
It preserves sibling deployments, including those created through the management
API. A declaration cannot remove or change the protocol of a retained binding.
Control keeps each deployment's encrypted serving configuration and revision
separate from the project's desired configuration and apply revision.

An HTTP binding can reference an existing public URL record instead of a private
service. Apply saves its deployment ownership and visitor policy. An app-owned
binding defers its listener to the application; installed workers receive only
explicit targets. They compose `publisher.Run`, not another publication engine.

Deployment credentials independently approve management, connections, named HTTP
publication, and temporary allocation. Control stores temporary provenance in the
existing namespace allocation table and reuses URL expiration and deletion.
Native preparation narrows that credential to one URL without issuing another
grant. Retiring a namespace waits for public URL and service authority alike.

SDK deployment handles compose connections and publications without sharing their
credentials. Remote publication passes its captured registered credential through
private invocation IPC and starts a configuration-free local publisher journal.
Named local publication uses configured app preparation. Both use the existing
registration manager and workers; registration and routability remain distinct.
The SDK owns Fetch/ASGI adapter listeners, not supplied Node or Bun servers.

Project status includes deployment identity so two bindings called `db` remain
distinct. Project retirement removes all deployment bindings and local worktree
realizations in the same transaction, while retaining the project's source
identity and revision.

## find the code

```text
cmd/
  tnl/                 client flags, prompts, and output
  tnld/                server flags and role selection
internal/
  publisher/           public URL publish runs
    app/               app registrations and replacement
    local/             project-scoped local tnl process
    localapi/          native app and CLI registration API
    invocation/        publication operations used by callers
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
  connector/           visitor-side service selection and connection
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
  naming/              shared names and validated identifiers
  transport/           connection and multiplexing mechanics
  policy/ security/    shared policy and security code
  failure/             diagnostics and error contracts
  observability/       measurements and event vocabulary
  clioutput/           ASCII output renderer
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

`scripts/generate` has its own private tooling workspace so Hey API resolves the
TypeScript 6 compiler API it executes. Application and SDK checks stay on
TypeScript 7. Generated source still belongs to its serving/runtime owner; the
tooling workspace owns no product runtime or alternate schema authority.

Commands handle arguments, prompts, and output. Reusable operations live below
them. The packages running processes, runs, or streams start and stop their own
work:

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

This is not a required chain of wrappers. Use a shared value or contract directly
when that is all you need. A package in a child directory should not import its
parent to reach a helper.

### shared HTTP code

Public URL and service runs share HTTP authorization and request limits, but
manage their runs separately:

```text
publisher (public URLs) --+
                         +--> httpaccess + requestlimit
publisher/service -------+
        |
        +--> service/stream
```

- `httpaccess` refreshes visitor policy and handles browser handoffs, token
  renewal, cookies, and HTTP authorization. Run owners stop and wait for its
  workers. It does not own accepted visitor connections.
- `requestlimit` keeps one HTTP request budget per run, shared across that run's
  visitor connections.
- `service/http.go` builds the service HTTP frontend. `service/stream` handles
  visitor TLS, protocol negotiation, expiry, target connections, and cleanup.
  The run supplies current admission and a shared request budget.
- `observability/inspection` records body-free HTTP summaries for public and
  connector requests. The target transport marks accepted application responses;
  a denied request or failed target dial remains a tnl response. Inspection
  observes completion without owning the handler or changing its cancellation.

Neither shared package nor the service tree imports publisher root.

### installed jobs

Installed jobs use publisher operations, not the other way around:

```text
installed --> publisher/deployment --> publisher/service
    |
    +-------> shared client packages
```

`installed` owns the registry, OS service setup, job reconciliation, supervision,
and shutdown. It uses publisher operations and caller-supplied connector
operations. Shared clients must not import it. A registry entry records a job;
it does not grant permission to publish.

`publisher/deployment` publishes assignments for both foreground commands and
installed jobs. Publishing an assignment does not need an installed-job registry.

### other important dependencies

- `publisher/local` combines `app`, `localapi`, and `invocation`. It supplies
  operations to the API; the API does not call back into the process owner.
- Connector operations use `connector/runtime` and `connector/stream`. Neither
  child imports connector root.
- `control/state` never imports HTTP handlers. Ingress and relay use control API
  clients, not control state.
- `transport` handles connections, not process startup, relay assignment, or
  visitor policy.

Use the package that defines a shared value. HTTP limits, for example, use
`policy/applicationlimits.Limits` directly, not a publisher alias.
`naming/ingresspool` defines an address pool ID shared by control and ingress;
control state need not import ingress just to name that pool.

`security/rdsroots` owns the pinned offline Amazon RDS regional CA catalog used
by publisher discovery and control target approval. It depends on neither owner;
control must not import publisher discovery to approve a supplied endpoint.

`client/auth` packages deployment signing credentials and acquires their short-lived
tokens through the existing publisher proof exchange. `connector` composes that
registered-key source into its existing owner and stream engine; neither a human
device nor a provider workload is substituted for the registered key. Language
bindings give each explicit deployment handle an independent native registry and
join its driver factories and native cleanup without stopping sibling handles.

For shared behavior, define a small interface where it is used and have the
caller supply the implementation. Do not copy permission checks or run-management
code to avoid an import, or leave forwarding wrappers after moving code.

## where to put a change

Start in the package that already does the job. Add a package when it has a
separate responsibility and a caller that needs it, not just because a file is
large. For example, keep `control/state` together where its operations share
transactional checks and lock ordering.

| Change                         | Start here                                                                 |
| ------------------------------ | -------------------------------------------------------------------------- |
| Replace an app registration    | `publisher/app`; stop and wait for the old publication first.              |
| Renew a connector              | `connector/runtime`; keep renewal and fixed expiry together.               |
| Approve certificate issuance   | `control/state`; check the current run, grant, and certificate plan.       |
| Claim a publisher connection   | `relay` for the local session; `control/state` for the durable claim.      |
| Change HTTP visitor access     | `publisher/httpaccess`.                                                    |
| Change per-run HTTP limits     | `publisher/requestlimit`.                                                  |
| Change QUIC or yamux mechanics | `transport/muxsession`.                                                    |
| Change configuration syntax    | `config` for types and validation; `client/project` for evaluation.        |
| Resolve project metadata       | `client/project/resolve`; `client/project/meta` writes portable artifacts. |
| Change project initialization  | `client/project/init`; commands supply prompts and output.                 |
| Change CLI frames              | `clioutput`; commands supply facts, not borders or padding.                |

Choose by the work, not the executable. `tnl publish` is publisher work,
`tnl connect` is connector work, `tnl apply` sends a control change, and `tnld`
starts server roles. One process can run publisher and connector operations
without combining their permissions.

Two names worth distinguishing:

- `publisher/processidentity` manages a signed process identity and control
  lease. Callers own renewal and stop loops; the package starts no worker and
  owns no app publication or socket.
- `serverhttp` provides bounded JSON decoding, problem responses, control cookies
  (including the authority API), and private cluster authentication. It does not
  manage saved services or decide durable permission.

Shared client operations belong under `client`, not in command-private helpers.
`client/team` handles session, team, and domain selection.
`client/project/resolve` combines project declarations with server, team, and
local state.

## starting work means owning cleanup

Every worker, renewal loop, lock, socket, and temporary file needs one owner.
That owner starts the work, requests stop, and waits for cleanup before returning.
Process owners also supervise workers and allow a bounded drain. A progress
callback does not make a command responsible for cleanup.

Cancellation is only a stop request. Keep real operation and cleanup errors even
if cancellation happens at the same time. In particular,
`errors.Is(err, context.Canceled)` can match a joined error that contains another
failure too.

Pass deadlines, endpoint details, transport identities, and requested capabilities
explicitly. Do not guess from defaults or optional runtime interface assertions.
HTTP authorization must receive the trusted visitor source from the accepted
stream, not reconstruct it from forwarding headers or socket defaults.

Keep visitor TLS separate from target TLS. Keep public URL and service records,
credentials, and lifecycles separate even where they share HTTP or transport code.

Shared APIs must be safe during refresh and cleanup: reads must not race with
background updates, and exported fields must not leak credentials through JSON.
Keep secrets out of logs, diagrams, browser-safe metadata, and snapshots. The
public Go SDK exposes a prepared publisher identity, not its key or control client.

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

The six HTTP serving contracts follow the component serving them. Local publisher
registration and the browser API are separate contracts. Edit their OpenAPI
`paths/` and `schemas/` fragments and generator configuration. Reuse control
schemas for identical wire shapes; shared components contain only byte-identical
referenced schemas and generate no Go package.

The telemetry contract describes batches sent by native clients. Its generated
models and validators do not add a native HTTP server. `client/telemetry` collects
and delivers bounded events; process and publication owners close their scopes
after their workers stop.

`pkg/protocol/tunnelv1` is handwritten and is the only tunnel protocol definition.
Use golden JSON, framed-wire fixtures, invalid inputs, bounds tests, fuzzing, and
shared transport tests, not a second definition in JSON Schema. See the
[contracts guide](contracts/readme.md) for other shared inputs.

From the repository root:

```sh
mise exec -- task generate
mise exec -- task format
```

`generate` runs the generators in order. `generate-check` also rewrites generated
files, then compares them with `HEAD`; commit intended generated changes first.
See [edit generated sources](contributing.md#edit-generated-sources).

## tests and dependency checks

Keep Go unit tests and tests using package internals beside the implementation,
including daemon startup and shutdown tests. Keep local `testdata` there too;
shared test-only fixtures go under `internal/testutil`.

Built-CLI tests live in `tests/integration/<boundary>`, with shared subprocess and
Compose fixtures in `tests/integration/fixtures`. TypeScript tests and fixtures
live in `packages/ts/test`; Python tests stay in `packages/py`.

Move tests with the code. Update fixture paths, `-tnl-*` flags, test tiers, and
Task selectors. Before combining or removing suites, preserve every unique
assertion at the smallest package that can prove it.

Use Task targets; CI uses the same targets. Routine tests need no external
infrastructure. Integration tests use the smallest real setup needed.
PostgreSQL-backed targets create and remove their own digest-pinned disposable
database. Large load and fault sweeps require explicit opt-in. Put check results
in the PR, not this guide.

`internal/daemon/package_dependencies_test.go` checks production imports,
including generated and platform-specific files. It keeps the service tree and
shared HTTP packages from importing publisher root, and shared clients from
importing installed-process code.

Package comments explain what the package does, who calls it, and what it starts
and stops. Keep detailed rules and their tests with the code; this guide connects
the parts.
