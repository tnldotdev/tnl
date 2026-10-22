# client tracing

native commands, SDK calls, and development framework integrations carry one
canonical W3C `traceparent` through native launch and private IPC. a preparation
does not become a permanent trace parent for its handle's later operations.

## process and operation ownership

`cmd/tnl` creates one `internal/observability` owner after parsing and before
dispatching native connection commands. finite commands record their result;
publishers, connectors, app owners, and watch loops record startup and finite
attempts. startup ends at the owned readiness boundary, not process exit.
shutdown joins native work before stopping exporters.

finite CLI invocations give exporter shutdown **250 milliseconds total**, with a
fresh context. persistent native owners retain the existing five-second budget
and batch processors. neither an unavailable receiver nor a failed flush changes
a successful command, readiness, registration, or publication result. invalid
export configuration still returns the authored configuration error.

the connection backend keeps the process metrics context when creating its
independently canceled lifetime. group runners replace identity for each enrolled
group before setup; assignment workers narrow that scope to one managed service.
group setup, lease renewal, assignment polling, acknowledgement, and shutdown
remain separate finite observations. no tenant becomes a process resource.

the Node SDK uses `@opentelemetry/api` and the host application's tracer provider.
it installs no global provider, context manager, exporter, or error handler.
SDK-local async context carries finite `prepare`, `connect`, `open`, registration,
renewal, recovery, and cleanup operations even when the host has no context manager.
Vite traces preparation and listener registration/restart; Next traces development
registration and target replacement. their shared app lifecycle owns renewal,
recovery, and cleanup, with framework-specific cleanup observations.
browser imports remain independent of the Node tracing implementation.

scheduled renewals, connection paths, app publications, and recovery attempts are
new roots with a scheduling **link**. links contain only trace/span IDs and flags.
per-operation IPC instead uses the current caller as its parent. a canceled
registration request cannot cancel the publication it scheduled.

## lifecycle meaning

- **bound**: the SDK has an actual local listener address. this is a span event;
  it does not claim native registration or public readiness.
- **registered**: the native manager accepted the registration transition. a
  duplicate registration or renewal does not emit it again.
- **publication_ready**: the exact current publish run became routable. repeated
  readiness observations, status reads, and watch readers do not emit it again.
- **app operation**: the application owns its request, SQL, and payload spans.
  SDK connection preparation can be a child of that operation, but tnl does not
  inject its trace into application requests, SQL, database bytes, or metadata.

`tnl_client_operation_duration_seconds` measures finite native CLI and private IPC
operations with `tnl.operation` and `tnl.outcome`. it has no tenant or service-name
dimensions. `tnl_client_lifecycle_events_total{tnl.event}` counts native
`registered` and `publication_ready` transitions. publisher group phases reuse
`tnl_publisher_operation_duration_seconds` with authenticated scoped identity.
the generated observability vocabulary owns the instruments and keys.

## website bootstrap handoff

the website's bootstrap producer needs this exact native input contract:

| input                                   | meaning                                                                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`    | explicit HTTPS OTLP/HTTP-protobuf trace endpoint, including its path                                                             |
| `OTEL_EXPORTER_OTLP_TRACES_HEADERS`     | standard comma-separated, percent-encoded `name=value` receiver authorization; for example `Authorization=Bearer%20<credential>` |
| `OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE` | optional private receiver CA PEM file; ordinary WebPKI needs no setting                                                          |
| `OTEL_RESOURCE_ATTRIBUTES`              | optional approved deployment/cloud resource facts, with no tenant, path, credential, or durable publisher identity               |
| `TNL_TRACEPARENT`                       | optional **one-launch** parent, exactly `00-<32 lowercase hex trace ID>-<16 lowercase hex span ID>-00\|01`; IDs must be nonzero  |

metrics and logs need their own explicitly enabled endpoints (or the existing
standard base `OTEL_EXPORTER_OTLP_ENDPOINT`). there is no default receiver or
tnl-specific telemetry authentication exchange. the bootstrap producer supplies
receiver authorization using the existing standard header settings. exporting
requires no additional control API rights, and trace identity is not authorization.
all existing timeout, queue, TLS, sampling, and disable settings in
[the observability contract](metrics.md#optional-https-export) still apply.

set exporter environment **before the first native command**. native resources
are `service.namespace=tnl`, `service.name=tnl`, the binary version, a fresh
`service.instance.id`, and the command-selected `tnl.role=client|publisher`.
the native process chooses role and instance; the bootstrap does not supply
tenant dimensions. a website-owned provider exporting SDK spans uses the
website's own approved resource (`service.name=tnl-accounts`, `tnl.role=accounts`).

the SDK reads the host's current OTel span, starts its finite operation, and
passes only the resulting canonical parent to native launches and private HTTP
requests. a native launcher replaces any stale `TNL_TRACEPARENT` in the child
environment. native `main` consumes and unsets it before dispatch. do not put it
in a project payload, handle, endpoint descriptor, installed job, persistent
environment file, or browser metadata. private IPC carries the parent in an HTTP
header, not an OpenAPI JSON field. missing, duplicate, malformed, noncanonical,
or zero-ID parents start independent work. tracestate and baggage are neither
extracted nor forwarded.

## check the boundary

from the repository root:

```console
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task go:test:client-tracing
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task js:test:client-tracing
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task go:test:connections
```

the native connection tier exercises the real CLI launcher, detached owner,
backend workers, and per-read IPC against a local HTTPS OTLP receiver. it checks
the exact parent/span chain, a different trace for a later caller, absence of
parents in the handle, and unchanged application requests. routine tracing tests
cover canonical rejection, independent links, lifecycle deduplication, safe errors,
and a stalled exporter within the short CLI flush budget.
