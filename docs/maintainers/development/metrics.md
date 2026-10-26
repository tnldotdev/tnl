# observability contract

`internal/observability` owns each native process's metrics, finite-operation
spans, optional operational logs, export queues, and shutdown. applications record
each boundary once. the attribute handles in `attributes.go`, catalog in
`attribute_catalog.go`, semantic result mappings in `contract.go`, and actual
instrument declarations generate the shared contract at
`api/observability/v1/vocabulary.json`. sync that file to tnl.dev; it is neither an
HTTP API nor a tunnel schema. regenerate with `mise exec -- task generate`.

the JSON lists keys, allowed fixed values, meanings, dimension policies, each
instrument's dimension allowlist, and explicit histogram boundaries. native OTel
attributes use dots; Prometheus escapes them to underscores. for example,
`tnl.service_kind` becomes `tnl_service_kind`. application instrument names use
the same meaningful `tnl_*` families in both exports. there are no old-label or
old-family aliases. the shared API families are `tnl_api_request_duration_seconds`
and `tnl_api_requests_in_flight`, including ingress and relay APIs.

## process ownership

`StartProcess(ctx, role)` reads standard exporter configuration once and returns
the owner context and `*Metrics`. `WithMetrics` and `FromContext` carry the owner
through workers. retain that context when starting background work; use
`context.WithoutCancel` when the worker has a separate cancellation lifetime.
join workers before `Shutdown` with a fresh context. flush and shutdown have a
shared five-second bound across signals and respect shorter caller deadlines.
each provider starts its flush or shutdown independently within that bound. the
owner stops its processors even when shutdown starts with a canceled context;
one slow signal cannot strand another signal's queue. export failures preserve
their causes for callers while displaying only authored text.

`New(role)` is isolated and local-only. embedding never reads exporter environment
variables or installs global providers implicitly. neither native entry point
installs global meter/tracer/error handlers. owner-local export queues avoid
global SDK feature flags. missing owners make scoped helpers no-ops.

`tnld` serves `/metrics` on its private listener (`127.0.0.1:9090` by default).
standalone includes its control, ingress, and relay observations once. native
`tnl` has no metrics listener. ordinary CLI commands have role `client`; foreground
publishing, group publishers, app-led owners, and installed supervisors have role
`publisher`. detached launchers have role `client`; their child owns publishing.
parsing help, version, project configuration commands, and offline infrastructure
generation do not initialize exporters.

finite `tnl` invocations use a shorter 250-millisecond shutdown budget. persistent
owners retain the five-second budget. see [client tracing](client-tracing.md) for
native launch and private IPC carriers, SDK/framework ownership, lifecycle
meaning, and the website bootstrap input contract.

process resource facts are:

- `service.namespace=tnl`;
- `service.name=tnld|tnl|tnl-accounts|otel-collector`, according to the process;
- `service.version` and `tnl.role`;
- `service.instance.id`, generated randomly for each owner when unset; a durable
  publisher identity or replica key is not a runtime instance;
- operator-declared `deployment.environment.name`, `cloud.provider`,
  `cloud.region`, and `cloud.availability_zone`, only when known.

there is no cloud metadata discovery. scoped tenant or publisher identity never
becomes a process resource.

## authenticated scope and caller helpers

`ReplaceIdentity(ctx, Identity)` replaces every field, including empty fields.
use it after authentication or when clearing scope. `NarrowIdentity` keeps parent
team/group/publisher/deployment scope within the same authenticated boundary but
always replaces or clears service scope. changing a team, publisher, group, or
deployment starts a replacement scope. conflicting service IDs or invalid fields
clear the identity instead of inheriting the previous tenant.

```go
ctx = observability.ReplaceIdentity(ctx, observability.Identity{
    TeamID: member.TeamId,
    PublisherGroupID: member.GroupId,
    PublisherIdentityID: member.PublisherIdentityId,
})
worker := observability.NarrowIdentity(ctx, observability.Identity{
    ServiceID: service.ServiceId,
})
worker, finish := observability.PublisherOperation(worker, "target_preflight")
defer func() { finish(err) }()
```

`ServiceID` is only a service. `PublicURLID` is only a public URL; they
are mutually exclusive. the scope derives `ServiceKind=service|public_url`.
`NormalizeServiceKind` translates the `service` wire value.
`PublisherGroupID` maps the authenticated `group_id`; `PublisherIdentityID`,
`DeploymentID`, and `ReplicaKey` retain their distinct meanings. only the publisher
instruments and the signed control runtime lifecycle instrument allow scoped identity
dimensions. runtime scope attaches only after control verifies the signing proof.

`WithFields(ctx, Fields)` replaces the protocol/component field set. protocol and
transport fields use `Protocol` and `TransportValue`; parse wire strings with
`ParseProtocol` and `ParseTransport` before setting them. unknown values are omitted.
`Attributes(ctx, allowed ...MetricKey)` selects identity/protocol
fields for a caller's explicit instrument allowlist. `TLSAttributes` returns only
negotiated TLS version and session resumption. `Start(ctx, name, options...)`
accepts standard span options, including trace links, for authored finite work.
its error finish function is idempotent. `PublisherOperation` also records its
duration exactly once. `ObserveOperationContext` attaches an already measured
operation interval to its caller context; do not wrap the same boundary in an
additional span. control state starts `ControlOperation` before transaction work;
driver query and acquisition spans use that context. DNS and certificate workers
start finite `WorkerAttempt` spans; an available scheduling span is a link, never
an invented asynchronous request parent. links retain trace/span IDs and flags,
with at most eight links per span and no link attributes. `Start` also removes
link tracestate. no scheduling payload is copied into link events or attributes,
and no request context is stored in worker records or database activity snapshots.

publisher byte directions are `visitor_to_target|target_to_visitor`. relay wire
directions are `visitor_to_publisher|publisher_to_visitor`; ingress keeps its
explicit forwarding direction. wire bytes include protocol metadata and are not
application payload bytes. `tnl.transport` is absent until a transport is selected;
`tnl.transport_preference` describes the initial preference independently.

## typed authoring boundaries

`Key` is a catalog name with no value constructors. declared handles expose only
the right constructor: `HTTPStatus.Int(200)`, `TLSResumed.Bool(true)`, and
`RequestID.String(id)`. closed values use `Value`, such as
`ServiceProtocol.Value(ProtocolHTTP)` and `OutcomeKey.Value(Success)`. protocol,
transport, role, outcome, service kind, state, and event are distinct ordinal
types; a string cast cannot turn supplied input into one. `New` and `StartProcess`
validate dynamic role strings before the owner uses a typed `Role`.

```go
protocol, _ := observability.ParseProtocol(string(service.Protocol))
ctx = observability.WithFields(ctx, observability.Fields{
    Component: "publisher",
    ServiceProtocol: protocol, // unknown wire values stay unspecified
})
ctx, finish := observability.Start(ctx, "publisher.target_preflight")
defer func() { finish(err) }()
```

`Start`, `WorkerAttempt`, `PublisherOperation`, and authorization helpers accept
authored string literals through an unexported operation type. dynamic strings
cannot be passed or cast to that type by callers. `ControlOperation` validates
wrapper arguments against its compiled operation list. the database adapter
builds a `DatabaseOperationCatalog` from `embed.FS` SQL sources; `Lookup` returns
an opaque `DatabaseOperationName`, normalizing unknown driver names to `unknown`.
query, guard, and passive snapshot observations all require that token.

instrument declarations take sealed `MetricKey` handles and an `InstrumentKind`.
resource and trace/log-only keys cannot be declared as metric dimensions, except
the explicitly metric-eligible process role used by `tnl_process_info`.
`DimensionPolicy` describes catalog policy with a separate type. recording uses
named `Dimension` values, independent of argument order:

```go
attempts := newCounter(meter, "tnl_example_attempts_total", "Completed attempts.",
    ConnectionSlot, OutcomeKey)
attempts.With(ConnectionSlot.Dimension(0), OutcomeKey.Dimension(Success)).Inc()
```

there is no positional string-label binding or arbitrary key-to-dimension adapter.
trace/log-only handles have no `Dimension` method. bindings reject duplicate or
undeclared keys; invalid external values are omitted. semantic result adapters
classify domain strings into typed outcomes and bounded reasons before binding.
scoped identity strings remain dynamic and retain their authentication and length
checks. the SDK filter also checks value types, enums, and instrument allowlists
for observations made directly through OTel. `.Key()` returns a handle's catalog
name for metadata comparisons; it does not recover a value constructor.

## results and cardinality

`tnl.outcome` is `success|denied|rejected|timeout|canceled|error`. bounded domain
detail goes in `tnl.reason`; readiness belongs in `tnl.state`, and queue/ingestion
lifecycle belongs in `tnl.event`. certificate, DNS, cleanup, and admission domains
use `tnl.certificate_kind`, `tnl.dns_kind`, `tnl.cleanup_kind`, and
`tnl.capacity_resource`. there is no generic `kind` label.

worker phases, stages, and actions use `tnl.operation`; certificate milestones use
`tnl.event`. a successful HTTP 200 authorization response can have outcome `denied`
or `rejected` with reason `not_admitted`. the latter means the credential was
allowed but the visitor was not admitted. infrastructure failures remain `error`.

`ErrorOutcome` classifies context cancellation/deadlines, network timeouts, and
owned failure classes without formatting an error. `FailureCode` exports only an
owned failure reason or diagnostic code as `error.type`, using `internal.unexpected` for
unclassified errors. original errors and causes remain available to callers.
span status and logs never contain raw error strings or exception messages.
the generated `error.type` values include exact catalog codes, including `TNL_*`
client codes. native providers disable the SDK's automatic panic exception
recording. interrupted API handlers finish with an error and continue unwinding
the original panic; an unsent response does not acquire a synthetic HTTP 200.

HTTP instrumentation uses standard method/status/route attributes; the route is
a compiled matched pattern, never a raw path or URL. a semantic HTTP 200 denial
remains `denied`. `APIRequests` accepts only one canonical, 55-byte version-00
`traceparent`, preserving its parent IDs while the process chooses sampling.
absent, duplicate, or malformed parents clear previous parentage. tracestate and
baggage headers are never extracted. `OwnedHTTPClient` sends only the current
canonical `traceparent` to dedicated tnl-owned API clients and removes any existing
tracestate or baggage headers. customer target, DNS, CA, and identity-provider
traffic does not receive tnl trace propagation. no baggage, headers, bodies, peer
addresses, hostnames, credentials, project paths, or SQL text are recorded.

visitor, request, publish-run, connection, grant, actor, revision, and image-hash
correlation is trace/log-only. `Visitor` and `WithVisitor` correlate existing
visitor connection IDs without inventing tunnel parentage or changing headers.
SDK views enforce per-instrument attribute allowlists and fixed enum values. each
instrument is capped at 2000 series per collection. overflow points carry only
`otel.metric.overflow=true` as a boolean, replacing application dimensions.
collectors must preserve that validated marker. instrument callers cannot supply
it themselves. exemplar reservoirs discard all view-rejected attributes before
storing a sample, including trace/log-only keys and wrong value types. exemplars
retain their timestamp, value, and trace/span IDs under both trace-based and
always-on sampling; changing the SDK exemplar filter cannot bypass the allowlist.
absolute gauge state is reserved for bounded process-wide enums.
spans are limited to 32 attributes, 256 characters per value, eight events with
eight attributes each, and eight attribute-free links. the native SDK's raw
per-link attribute limit is zero, including links added after span creation.
link IDs and flags are trace-only correlation, never metric dimensions or tenant
authorization evidence. authenticated telemetry receivers trust hosted producers
to derive tenant scope from authenticated state and enforce this producer policy;
retaining asynchronous links does not verify a tenant claim on the wire.

## optional https export

there is no default destination, including localhost. no signal leaves the process
without an explicit endpoint for that signal. operational observability is
independent of pseudonymous CLI usage telemetry.

| setting                                                                             | contract                                                                                                                                            |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                                                       | HTTPS base URL; append `/v1/metrics`, `/v1/traces`, or `/v1/logs`                                                                                   |
| `OTEL_EXPORTER_OTLP_{METRICS,TRACES,LOGS}_ENDPOINT`                                 | exact signal URL, overriding the base                                                                                                               |
| `OTEL_{METRICS,TRACES,LOGS}_EXPORTER`                                               | `otlp` or `none`; `otlp` still needs an explicit endpoint                                                                                           |
| `OTEL_SDK_DISABLED=true`                                                            | case-insensitive; disables application metrics, sampled spans, logs, and export; ignores exporter settings; passive local Go/process scrape remains |
| `OTEL_EXPORTER_OTLP_PROTOCOL`                                                       | `http/protobuf` only                                                                                                                                |
| `OTEL_EXPORTER_OTLP_HEADERS`                                                        | comma-separated `name=value`, percent-decoded values, at most 8 KiB; signal-specific headers replace the general list                               |
| `OTEL_EXPORTER_OTLP_TIMEOUT`                                                        | milliseconds, default 5000, maximum 10000                                                                                                           |
| `OTEL_METRIC_EXPORT_TIMEOUT`, `OTEL_BSP_EXPORT_TIMEOUT`, `OTEL_BLRP_EXPORT_TIMEOUT` | may shorten the corresponding timeout; maximum 10000 ms                                                                                             |
| `OTEL_METRIC_EXPORT_INTERVAL`                                                       | milliseconds, default 60000, maximum 600000                                                                                                         |
| `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE`                                 | unset or `cumulative`; `delta` and `lowmemory` are rejected                                                                                         |
| `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION`                          | unset or `explicit_bucket_histogram`; other aggregations are rejected                                                                               |
| `OTEL_EXPORTER_OTLP_COMPRESSION`                                                    | `none` or `gzip`                                                                                                                                    |
| `OTEL_EXPORTER_OTLP_CERTIFICATE`                                                    | PEM receiver CA file                                                                                                                                |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY`            | paired PEM client certificate/key                                                                                                                   |
| `OTEL_BSP_MAX_QUEUE_SIZE`                                                           | default 2048, maximum 8192 spans                                                                                                                    |
| `OTEL_BSP_MAX_EXPORT_BATCH_SIZE`                                                    | default 512, maximum 1024, capped at queue size                                                                                                     |
| `OTEL_BSP_SCHEDULE_DELAY`                                                           | milliseconds, default 5000, maximum 60000                                                                                                           |
| `OTEL_BLRP_MAX_QUEUE_SIZE`, `OTEL_BLRP_MAX_EXPORT_BATCH_SIZE`                       | log queue default 2048/max 8192; batch default 512/max 1024, capped at queue size                                                                   |
| `OTEL_BLRP_SCHEDULE_DELAY`                                                          | log batch delay in milliseconds, default 1000, maximum 60000                                                                                        |
| `OTEL_TRACES_SAMPLER`                                                               | `always_on`, `always_off`, `traceidratio`, or their `parentbased_` forms; default `parentbased_always_on`                                           |
| `OTEL_TRACES_SAMPLER_ARG`                                                           | ratio in `[0,1]` for ratio samplers                                                                                                                 |
| `OTEL_SERVICE_NAME`                                                                 | one approved service name, overriding resource `service.name`                                                                                       |
| `OTEL_RESOURCE_ATTRIBUTES`                                                          | approved resource keys above; values at most 128 characters; namespace must remain `tnl`                                                            |

disabled owners use the no-op meter and tracer APIs without constructing SDK
providers or their default resources. malformed ambient provider, resource, and
exporter settings therefore do not block disabled startup or enter constructor
diagnostics. the owner does not mutate the process environment.

exporter TLS/header/compression/timeout/protocol settings accept signal-specific
`OTEL_EXPORTER_OTLP_{METRICS,TRACES,LOGS}_*` overrides. HTTPS verification is required;
userinfo, query strings, fragments, insecure transport, and redirects are rejected.
invalid settings report only the setting name. standard headers support a receiver's
authorization scheme, including website-issued collector authorization, without
adding a tnl-specific auth protocol.
the pinned Go metric exporter supports delta and low-memory selectors, but the
hosted contract accepts cumulative sums and explicit-bucket histograms. native
construction pins those selectors and validates their environment settings.
all generic and signal-specific exporter settings are validated even when an
override wins: SDK constructors parse some ambient values before applying explicit
options. invalid overridden URLs, headers, durations, or certificate files must
fail through the owned setting error before that SDK diagnostic path runs.

the indirect Go auto-instrumentation SDK also reads span-limit variables during
package initialization. malformed values such as `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT`
or `OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT` can produce upstream stderr warnings before
`StartProcess` runs. constructor validation cannot intercept that import-time
output; those variables do not change tnl's fixed span limits.

export runs outside traffic with bounded queues and retry deadlines. retries start
at 100 ms, back off to at most one second, and share the signal timeout. sampled
spans drop on overflow without blocking recording. log export uses the bounded
SDK batch processor with the standard `OTEL_BLRP_*` settings above.
failed batches are lost; metrics are recollected at the next interval. there is no
persistent queue. exporter errors, readiness decisions, and traffic are independent.

`operatorlog.ReportContext` preserves compact authored one-line `tnld` output,
adds `trace_id`/`span_id` when present, and optionally calls `OperationalFailure`
to export safe failure copy with authenticated scope. `Correlation` is available
for other existing operational logs. these helpers never export arbitrary log
bodies or secrets. existing context-free `Report` still writes its one-line log.
exported operational failures use `tnl.event=operational_failure` and look up
the caller's operation in the compiled log vocabulary. approved operation words
become lowercase underscore-separated `tnl.operation` values; unknown operations
use `operational_failure`. the operation never comes from cause text. already measured
operation spans retain their own machine operation attribute too.

export health is local and best-effort:

- `tnl_observability_export_failures_total{tnl_signal}`: failed batches after retry;
- `tnl_observability_export_lost_spans_total`: spans in failed batches;
- `tnl_observability_queue_dropped_spans_total`: sampled spans lost to queue overflow.

## interpreting existing families

the generated JSON is the complete instrument/dimension inventory. these boundaries
matter when reading it:

- `RuntimeInstrumentDefinitions` declares an exact-name subset of the pinned
  Prometheus Go/process bridge for hosted collection. its gauges, cumulative
  counters, and `go_gc_duration_seconds` OTLP summary keep their actual types;
  a summary is not an explicit-bucket histogram. platform-specific process metrics
  may be absent. other local runtime scrape families are outside that hosted
  allowlist; collectors must not admit arbitrary `go_*` or `process_*` names.

- ingress visitor outcomes describe forwarding, not visitor TLS or application
  success. `success` with reason `forwarded` means forwarding was established.
  relay attempts can exceed visitor counts because ingress can retry before sending
  the first visitor byte. registered connections are not database claims.
- publisher readiness and lease timestamps require freshness checks. failed refresh
  does not extend confirmed expiry. control remains the authority for authorization,
  grants, lease state, and durable audit.
- certificate `progress` and DNS `pending` are successful observations with domain
  reasons. certificate availability does not imply publisher installation. order
  counters count committed new orders, excluding cached reuse/idempotent retries;
  they do not measure a CA quota or orders outside this deployment.
- service audit events are `queued|delivered|retry|dropped|accepted|duplicate`.
  they describe separate queue/ingestion stages, not distinct visitors or durable
  audit totals.
- service audit cleanup is measured by the runtime worker once per database call,
  including its committed row count. the instrumented database does not record
  that same cleanup again.
- website company reconciliation events use `busy|completed|partial_failed`.
  `busy` means another reconciliation owns the lease; `partial_failed` retains
  that some reconciliation work committed before a later step failed. sync the
  generated vocabulary to the website before qualifying its receiver.
- `KindGauge` describes current state. native Set/Add bindings and scoped
  publisher active HTTP requests, visitor streams, and connections use SDK
  up/down counters: their OTLP type is a cumulative, non-monotonic sum. SDK
  synchronous and observable gauges export actual OTLP gauges. the hosted receiver
  accepts both shapes for semantic gauges; neither shape is a monotonic activity
  total. the local HTTPS export regression decodes both wire shapes and verifies
  their current values.
- pool/active SQL snapshots are passive. scraping never acquires a database
  connection or queries a remote service. SQL operation names come from the compiled
  query sanitizer, never SQL text or parameters.
- database-wide port-pool and guest-trial snapshots repeat across control replicas;
  use their maximum rather than their sum. process-local counters reset at restart.
  guest trial events count trials, not publish runs or pings. public URL purpose
  counters measure activity by saved purpose, not distinct identities.
- port inventory refresh runs every 30 seconds with a five-second deadline.
  `tnl_control_tcp_port_pool_last_success_timestamp_seconds` records only complete
  successful refreshes. disappeared pools vanish on the next successful refresh;
  all capacity series disappear after 90 seconds without success. the timestamp
  remains available to explain stale data. neither scrape nor collection queries
  PostgreSQL. use `max`, not `sum`, across replicas for both inventory and timestamp.
- `tnl_control_certificate_orders_total` and
  `tnl_control_certificate_milestone_age_seconds` cover public URLs and managed
  services using `tnl.certificate_kind`; there are no public-URL-only aliases.
  certificate work, claims, transitions, and installation use the same kinds.
  the shared service certificate queue reports failed claims and empty polls as
  `service_queue`; only a successfully claimed row identifies `public_url` or
  `service`. relay claims retain `relay`.
- certificate and DNS worker attempt deadlines are operational timeouts while the
  process lifetime remains live. their owner attempt and one authored diagnostic
  retain the timeout and trace correlation even if saving retry state succeeds.
  process-lifetime cancellation or deadline ends work without an operational
  failure diagnostic. expired work leases remain recoverable by later claims.
- `tnl_control_publisher_runtime_duration_seconds` measures signed `inspect`,
  `start`, `renew`, and `stop` with selected authenticated team/group/publisher
  and reported deployment/replica dimensions. replaced/stopped runtime rejection
  uses outcome `rejected` and the existing reason `stale`. run IDs, epochs, and
  signing assertions never become metric labels.
- operation histograms preserve explicit classic second buckets. benchmark
  `DurationSummaries` selects only histograms ending in `_seconds`, excluding
  non-duration SDK distributions. runtime/process collectors use the supported
  Prometheus bridge for OTLP; application metrics never pass through that bridge.

publisher live payload-byte instruments and complete HTTP streaming instrumentation
belong to their data-path owners. this backend does not add tunnel headers or
service/database desired-version state. see [server readiness](server-readiness.md)
for the private diagnostic surfaces and lease-loss boundary.
