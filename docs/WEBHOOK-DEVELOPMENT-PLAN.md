# Webhook Development Plan

Status: planned; implementation has not started.

Build a local webhook workflow around `tnl dev`: automatic endpoint setup,
durable delivery history, inspection, and replay across restarts. Start with
Stripe, GitHub, and Resend, with a small provider-neutral base that accommodates
CLI, HTTP API, or SDK integrations.

## 1. Implementation Scope

All webhook orchestration, capture, storage, and replay belongs in the local
client. Provider credentials remain managed by their existing CLIs. Provider
calls and captured payloads stay on the developer's computer.

Keep the implementation consistent with the existing project configuration,
client-state database, publisher lifecycle, private development socket, and
shared CLI renderer. Use the repository's pinned mise toolchain and normal
generation and validation workflow.

## 2. Developer Experience

### Configuration

Add a named webhook map under `tnl.dev.webhooks`:

```yaml
version: 1

tnl:
  dev:
    command: [pnpm, dev]

    webhooks:
      billing:
        provider: stripe
        path: /api/webhooks/stripe
        events:
          - checkout.session.completed
        secret_env: STRIPE_WEBHOOK_SECRET

      repository:
        provider: github
        repository: acme/my-app
        path: /api/webhooks/github
        events:
          - push
          - pull_request
        secret_env: GITHUB_WEBHOOK_SECRET

      email:
        provider: resend
        path: /api/webhooks/resend
        events:
          - email.delivered
          - email.bounced
        secret_env: RESEND_WEBHOOK_SECRET
```

`tnl dev` will provision endpoints, inject signing secrets into the application
process, and activate delivery once the application and public route are ready.

Configuration rules:

- Webhook names identify integrations within a project service.
- `path` is an absolute application path without a query string or fragment.
- Paths and secret environment names must be unique within the effective
  service.
- `events` is required, nonempty, and contains unique values.
- `["*"]` explicitly selects all supported events; adapters translate
  provider-specific conventions.
- `secret_env` defaults to the provider's conventional variable.
- Environment names must be valid and avoid reserved runtime variables and
  framework-public prefixes.
- GitHub's `repository` accepts `owner/repo`; when omitted, resolve it once
  through `gh` and record the resolved repository.
- Stripe initially manages test-mode endpoints.
- A service inherits the root webhook map when omitted. A supplied service map
  replaces it; `{}` disables inherited webhooks.
- Configuration is resolved once per `tnl dev` invocation.

Generate JSON Schema and TypeScript configuration declarations through the
existing pipeline.

### Project And Worktree Scope

Use the existing project resolution:

- The directory containing the selected project configuration.
- Otherwise, the existing worktree/current-directory fallback.
- Named services belong to that project.

Delivery history spans development sessions. By default, commands select the
current project/worktree and all its services.

For `--all-worktrees`, associate related checkouts using the Git common directory
and the project's relative location inside the worktree. This keeps separate
projects inside a monorepo distinct.

### Commands

| Command                                     | Behavior                                              |
| ------------------------------------------- | ----------------------------------------------------- |
| `tnl webhook`                               | Alias for `list`                                      |
| `tnl webhook list [name]`                   | Browse and search stored deliveries                   |
| `tnl webhook inspect <delivery>`            | Inspect a delivery and its result                     |
| `tnl webhook replay <delivery>`             | Replay against an active development session          |
| `tnl webhook status [name]`                 | Show configuration, endpoint state, and history usage |
| `tnl webhook cleanup [name]`                | Clean up leftover remote endpoints                    |
| `tnl webhook prune --older-than <duration>` | Remove old local delivery history                     |

Provider tools remain the way to generate new provider events:

```sh
stripe trigger checkout.session.completed
```

Those requests appear in ordinary delivery history. A generic `tnl webhook test`
wrapper is outside the initial command surface because provider event-generation
capabilities differ substantially.

### Finding An Old Request

```sh
tnl webhook list

tnl webhook list billing \
  --event checkout.session.completed \
  --since 7d

tnl webhook list billing --failed --since 7d

tnl webhook list billing \
  --since 7d \
  --search "order_4821"

tnl webhook inspect dlv_abc123 --body

tnl webhook replay dlv_abc123
```

List options:

| Option                            | Meaning                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `[name]`                          | Configured webhook name                                         |
| `--service <name>`                | Project service                                                 |
| `--provider <provider>`           | Provider                                                        |
| `--event <type>`                  | Exact event type; repeatable                                    |
| `--failed`                        | Non-2xx responses or forwarding failures                        |
| `--status <code>`                 | Exact HTTP status                                               |
| `--since <duration-or-timestamp>` | Lower time boundary                                             |
| `--until <timestamp>`             | Upper time boundary                                             |
| `--search <text>`                 | Literal search in event identifiers and captured request bodies |
| `--limit <n>`                     | Result count; default 20                                        |
| `--before <delivery>`             | Page through older results                                      |
| `--all-worktrees`                 | Include related project worktrees                               |
| `--follow`                        | Display recent results and follow new matching deliveries       |
| `--json`                          | JSON, or NDJSON with `--follow`                                 |

Results show delivery ID, timestamp, service, webhook name, event type, status,
duration, and whether the request was an original delivery or local replay.

IDs remain copyable; commands accept unique prefixes and reject ambiguous
matches.

### Inspection

```sh
tnl webhook inspect dlv_abc123
tnl webhook inspect dlv_abc123 --body
tnl webhook inspect dlv_abc123 --headers
tnl webhook inspect dlv_abc123 --response
tnl webhook inspect dlv_abc123 --body --response --json
```

The default view includes:

- Original project, service, webhook, and development session.
- Provider event and delivery identifiers.
- Request method and path.
- Timing, status, and forwarding errors.
- Capture completeness and replay availability.
- Related replay attempts.

Body and header content is explicitly requested. Human and JSON output share
redaction rules.

## 3. Package Design And Extensibility

Use a small application package with independent provider adapters:

```text
internal/webhookdev/
  types.go
  manager.go
  history.go
  capture.go
  replay.go

  stripe/
    driver.go

  github/
    driver.go

  resend/
    driver.go
```

Introduce shared CLI execution and signing helpers where actual reuse exists.

### Ownership

| Component         | Owns                                                                      |
| ----------------- | ------------------------------------------------------------------------- |
| `webhookdev`      | Endpoint lifecycle, capture policy, history queries, replay orchestration |
| Provider adapters | Remote API translation, event identification, signing behavior            |
| `clientstate`     | SQLite queries, transactions, protected payload storage, retention        |
| `localproxy`      | Generic HTTP observation and local forwarding                             |
| `cmd/tnl`         | Configuration mapping, dependency wiring, command dispatch, presentation  |

The application package depends on narrow interfaces for storage, endpoint
operations, and delivery signing. It does not import provider implementations,
CLI presentation, or concrete SQLite code.

Provider adapters register at the CLI composition root.

### Provider Capabilities

Separate capabilities instead of one large interface:

- **Endpoint management:** create, retrieve/reconcile, update,
  activate/deactivate, delete.
- **Delivery interpretation:** extract event type and provider identifiers.
- **Replay signing:** prepare fresh authentication headers for an exact payload.
- **Source ranges:** resolve provider webhook source networks.

Represent provider differences explicitly, including whether creation can start
inactive and whether a signing secret is recoverable.

The lifecycle manager owns shared ordering, journaling, rollback, and cleanup.
Adapters own provider-specific requests and response decoding.

A future provider can use HTTP or an SDK without changing the history store or
replay engine. Providers unable to support a capability report that explicitly.

## 4. Initial Provider Adapters

| Provider | Endpoint management                   | Secret behavior               | Local replay                  |
| -------- | ------------------------------------- | ----------------------------- | ----------------------------- |
| Stripe   | Authenticated Stripe CLI API commands | Secret returned at creation   | Fresh `Stripe-Signature`      |
| GitHub   | `gh api` repository hooks             | Generate and supply a secret  | Fresh `X-Hub-Signature-256`   |
| Resend   | `resend --json webhooks ...`          | Secret returned by create/get | Fresh Svix-compatible headers |

Shared subprocess execution will provide:

- Direct executable invocation without a shell.
- Operation deadlines and cancellation.
- Bounded stdout/stderr.
- Typed decoding of machine-readable responses.
- Sanitized errors.
- Secret-bearing input through stdin where required, such as GitHub hook
  configuration.

Resolve provider context during setup and retain its non-secret identity where
available. Cleanup must verify recorded ownership and scope before modifying a
remote endpoint.

Native provider replay can be added later as a separate capability. The initial
replay command uses captured requests consistently across all three providers.

## 5. Development Lifecycle

### Startup

1. Resolve and validate effective configuration.
2. Acquire the existing project/service development lock.
3. Preflight provider tools and authentication.
4. Resolve the route hostname and provider source ranges.
5. Reconcile unfinished endpoint operations from previous sessions.
6. Record endpoint creation intent in SQLite.
7. Create inactive endpoints, or create and immediately disable them.
8. Obtain signing secrets and retain them in memory.
9. Start the child with those secrets added to its environment.
10. Wait for the local target.
11. Start publishing with the delivery observer installed.
12. After `publisher.EventReady`, activate endpoints.
13. Present webhook readiness alongside tunnel readiness.

Provider operations run outside publisher event callbacks. Readiness
notifications drive the manager without blocking publisher coordination.

If activation partially fails, roll back activated endpoints and report the
failure.

### Initially Active Endpoints

GitHub supports creation with `active: false`.

Stripe and the inspected Resend CLI require a create-then-disable sequence. Use
a uniquely owned staging URL on the selected hostname, then switch to the
configured callback once disabled. This prevents early delivery from reaching
the intended handler, although a provider can still attempt delivery during
that short interval.

Creation intents and ownership markers allow recovery when a process dies after
remote creation but before recording the returned endpoint ID.

### Shutdown And Recovery

For normal shutdown:

1. Stop accepting new replay work.
2. Disable remote endpoints.
3. Delete remote endpoints.
4. Drain and stop publishing.
5. Stop the application child.
6. Flush pending capture writes and close session resources.

Use a bounded cleanup context independent of the canceled command context.
Signal handling must preserve this ordering while retaining immediate publisher
shutdown for authorization or lease failures.

Failed cleanup retains the ownership record. `cleanup` and the next development
session can retry it.

Use one initial recovery policy across providers: clean up stale owned
endpoints and create fresh ones. Captured history remains useful independently
of those endpoints.

### Route IP Policy

When the route is restricted, combine existing allowed addresses with:

- Stripe's published webhook ranges.
- GitHub's `hooks` ranges.
- Resend's documented webhook ranges.

Canonicalize, deduplicate, and enforce the existing prefix limit. Resolve these
before creating remote resources; a lookup failure must not silently make the
route public.

This remains a hostname-wide IP policy, which the documentation and status
output will explain.

## 6. SQLite History And Protection

Add a client-state migration with two main tables.

### Endpoint Ownership

Store:

- Local ownership ID.
- Project/worktree/service identity.
- Webhook name and provider.
- Provider scope and remote endpoint ID.
- Callback URL and ownership marker.
- Creation intent and lifecycle state.
- Tunnel ID, timestamps, and cleanup status.

### Deliveries

Store queryable metadata:

- Local delivery ID and stable ordering sequence.
- Project/worktree/service identity.
- Original control URL, tunnel ID, webhook name, and provider.
- Provider event and delivery IDs.
- Event type, timestamps, HTTP status, duration, and byte counts.
- Capture completeness.
- Replay-parent ID and source classification.

Store protected payload data:

- Exact request-body bytes.
- Method, path, query, and relevant headers.
- Captured response headers and body.

Delivery rows contain enough historical identity to survive remote endpoint
cleanup. Their lifetime must not depend on the endpoint ownership row remaining
present.

### Protection

Reuse the existing `clientstate` `Seal`/`Open` abstraction, with protection
contexts bound to the delivery ID and payload field.

- Protect payloads before inserting them into SQLite.
- Keep signing secrets in the active development process.
- Exclude unnecessary authorization, cookie, and original signature headers
  from persisted request data.
- Apply bounded redaction to displayed content without altering stored body
  bytes needed for replay.
- Keep payload search local: filter metadata first, then decrypt candidate
  bodies in batches.

### Retention

Initial limits:

- **30 days of history.**
- **100 MiB per project/worktree**, including services.
- Evict oldest deliveries when either limit is exceeded.

Prune incrementally during writes/startup and through the explicit `prune`
command. `status` reports retained count, bytes, and oldest delivery.

## 7. Capture And Replay

### Capture

Propagate a generic observer through:

```text
publisher.Config
  -> RouteServerConfig
  -> localproxy
```

Capture only configured webhook paths after route TLS terminates locally.

Initial capture limits:

- Request body: 1 MiB.
- Response body: 64 KiB.
- Captured headers: 16 KiB per direction.
- Bounded aggregate in-memory capture and persistence queue.

Forward original bytes unchanged. Large requests continue normally while
history records truncation.

Use bounded streaming capture rather than reading entire requests before
forwarding. Preserve HTTP streaming, cancellation, upgrades, and existing
request validation.

Persistence runs through a bounded writer. Recording failures are visible in
session status; completed records appear in history after commit. Graceful
shutdown flushes the writer. An abrupt process kill can lose in-flight or queued
captures.

### Replay

```sh
tnl webhook replay dlv_abc123

tnl webhook replay dlv_abc123 \
  --webhook billing \
  --service api
```

The replay engine:

1. Loads a complete saved request.
2. Resolves the active destination development session.
3. Validates provider compatibility.
4. Uses the destination's current configured path and signing secret.
5. Preserves exact payload bytes and provider event identity.
6. Generates fresh signature headers.
7. Sends the request to the active local target.
8. Stores the result as a new delivery linked to the original.

Share the existing local-target restrictions and forwarding mechanics. Strip
historical transport/forwarding headers, recompute body length, and avoid
following redirects.

The default destination is the original service/webhook in the current project.
Replaying into another worktree requires explicit destination selection.

Replay works after endpoint deletion and secret rotation because the
destination session supplies the current secret. Application deduplication
still applies because event identity is preserved.

Truncated or incomplete requests remain inspectable and receive a clear
non-replayable reason.

## 8. Local IPC And Output

Reuse the existing private development Unix socket for:

- Active webhook status.
- Replay execution requests.

History listing, inspection, search, and follow mode read SQLite directly and
work without a running application.

Replay IPC carries delivery IDs and destination selection; the active process
loads the payload and uses its in-memory secret. Secrets never enter socket
responses or browser-safe project metadata.

Follow mode uses a committed sequence cursor with bounded polling and
deduplication.

Output rules:

- Shared ASCII renderer for human output.
- Existing `tnl dev` child output remains untouched.
- Finite results on stdout; lifecycle output and errors on stderr.
- JSON for finite results and NDJSON for follow mode.
- Handler failures are recorded and reported, with a nonzero replay exit
  status.
- Stable diagnostics for missing sessions, incomplete captures, provider
  errors, ambiguous IDs, and pending cleanup.

## 9. Implementation Phases

### Phase 1: Configuration And Contracts

Update:

- `internal/config/document.go` and validation.
- `internal/projectconfig/project.go` inheritance/cloning.
- `cmd/tnl/config.go`.
- Schema/type generation and related tests.

Define normalized webhook specifications and narrow application interfaces.

### Phase 2: Durable History

Add:

- Next client-state migration.
- Source SQL queries.
- Handwritten storage/protection methods.
- Retention and scoped history queries.

Regenerate `clientstatedb`; keep generated files generator-owned.

### Phase 3: Provider-Neutral Lifecycle And Adapters

Implement the manager and subprocess helper, then Stripe as the first
end-to-end integration.

Add GitHub and Resend using the same contracts. Verify shared lifecycle
behavior through an adapter conformance suite.

### Phase 4: Development Integration And Capture

Update:

- `cmd/tnl/dev.go`.
- Publisher configuration and route-server construction.
- `internal/localproxy`.
- Private development socket dispatch.

Keep lifecycle helpers separate from the main command loop.

### Phase 5: Replay And CLI

Add focused command/output files for:

- List and search.
- Inspect.
- Replay.
- Status.
- Cleanup.
- Prune.

Implement provider signing and the shared replay executor.

### Phase 6: Documentation And Verification

Document configuration, provider authentication, history scope, retention,
cleanup, replay semantics, and worktree behavior in:

- [CLI reference](https://md.cormo-turtle.ts.net/git/tnldotdev/tnl/docs/CLI-REFERENCE.md).
- [Architecture](https://md.cormo-turtle.ts.net/git/tnldotdev/tnl/docs/ARCHITECTURE.md).
- [Package guide](https://md.cormo-turtle.ts.net/git/tnldotdev/tnl/packages/tnl/README.md).

## 10. Tests And Completion Criteria

Meaningful coverage includes:

- Strict configuration validation and empty-map inheritance.
- Project, service, and related-worktree history isolation.
- Endpoint journaling, interrupted creation, activation rollback, and cleanup.
- Child-only secret injection and output redaction.
- Provider command contracts using fake executables.
- Byte-preserving capture, truncation, queue bounds, and persistence failures.
- Protected payload round trips and context-mismatch rejection on encrypted
  backends, with the existing plaintext backend's behavior covered separately.
- Stable pagination, filtering, search, and follow cursors.
- Published signing fixtures and verification of replay signatures.
- Replay after process restart with a different endpoint ID and signing secret.
- Explicit cross-worktree replay.
- Retention under concurrent capture and inspection.
- Socket permissions and shutdown ordering.
- Human renderer and JSON/NDJSON contracts.

Run the repository validation sequence through mise:

```sh
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

Prepare the documented integration prerequisites first. Account for
`generate-check` comparing generated output against `HEAD`, including
intentional uncommitted generated changes.

The key acceptance scenario: receive a webhook, stop `tnl dev`, restart it with
fresh endpoints and secrets, locate the old delivery, replay it successfully,
and inspect both the original and replay results.

## Encryption Follow-Up

Keep protection simple for this implementation: reuse the existing backend.
**macOS provides Keychain-backed AES-GCM protection; the current non-macOS
backend stores plaintext.** Document that accurately and flag portable
encrypted storage as a follow-up in the completion summary.
