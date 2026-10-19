# metrics

each `tnld` process serves `/metrics` on its private observability listener
(`127.0.0.1:9090` by default). split roles expose their own metrics; standalone
exposes control, ingress, and both logical relays together. application metrics
start with `tnl_` and are recorded once through OpenTelemetry (OTel).

`internal/observability` owns the instruments, meter provider, tracer provider,
exporters, and shutdown. the Prometheus exporter retains the existing application
names, labels, counter semantics, and explicit classic duration buckets. native
OTel names also retain those names. SDK names use underscore escaping without
added unit or counter suffixes in Prometheus. Go/process metrics retain their
existing scrape families; the supported OTel Prometheus bridge translates those
runtime collectors for OTLP. application metrics never use that bridge.

## process ownership and optional export

`StartProcess(ctx, role)` reads configuration once, creates one owner, and returns
its context. `tnldruntime.Serve` shares that owner across control, ingress and
relay components. native `tnl` creates its owner in `main`, so foreground,
app-led owner, installed service supervisor, and group workers in that process
share it. child native processes create their own owner. installed services read
the environment of the service process, not the environment of a later CLI
invocation. the Go embedding API does not implicitly install a process provider.

workers inherit `WithMetrics` context or receive the semantic observer. call
`Shutdown` after joining workers, with a fresh context independent of canceled
traffic. the owner shares a five-second shutdown/flush deadline across tracing
and metrics. `New(role)` is a local-only owner for fixtures and embedding;
it never reads export environment variables or installs global providers.

there is no default OTLP destination, including localhost. neither metrics nor
traces leave the process until that signal has an explicit endpoint. native
`tnl` opens no metrics listener. optional publisher export uses the same standard
OTLP configuration as `tnld`, independently of pseudonymous CLI usage telemetry.

the supported configuration is:

| setting                                                                     | contract                                                                                                                                                                                                       |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                                               | HTTPS base URL; append `/v1/metrics` or `/v1/traces`                                                                                                                                                           |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | exact HTTPS URL for that signal; overrides the base URL                                                                                                                                                        |
| `OTEL_METRICS_EXPORTER`, `OTEL_TRACES_EXPORTER`                             | `otlp` or `none`; `otlp` still requires an explicit endpoint                                                                                                                                                   |
| `OTEL_SDK_DISABLED=true`                                                    | disables network export and sampled traces; existing local `/metrics` remains available                                                                                                                        |
| `OTEL_EXPORTER_OTLP_PROTOCOL`                                               | `http/protobuf` only; also accepts signal-specific overrides                                                                                                                                                   |
| `OTEL_EXPORTER_OTLP_HEADERS`                                                | comma-separated `name=value` headers with percent-decoded values; signal-specific headers replace the general list; at most 8 KiB                                                                              |
| `OTEL_EXPORTER_OTLP_TIMEOUT`                                                | positive milliseconds, default 5000, maximum 10000; signal-specific override                                                                                                                                   |
| `OTEL_METRIC_EXPORT_TIMEOUT`, `OTEL_BSP_EXPORT_TIMEOUT`                     | may shorten the corresponding export timeout; maximum 10000 ms                                                                                                                                                 |
| `OTEL_METRIC_EXPORT_INTERVAL`                                               | positive milliseconds, default 60000, maximum 600000                                                                                                                                                           |
| `OTEL_EXPORTER_OTLP_COMPRESSION`                                            | `none` or `gzip`; signal-specific override                                                                                                                                                                     |
| `OTEL_EXPORTER_OTLP_CERTIFICATE`                                            | PEM CA file for receiver verification; signal-specific override                                                                                                                                                |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY`    | paired PEM client certificate and key; signal-specific overrides                                                                                                                                               |
| `OTEL_BSP_MAX_QUEUE_SIZE`                                                   | default 2048 spans, maximum 8192; overflow drops spans without blocking the caller                                                                                                                             |
| `OTEL_BSP_MAX_EXPORT_BATCH_SIZE`                                            | default 512 spans, maximum 1024, capped at queue size                                                                                                                                                          |
| `OTEL_BSP_SCHEDULE_DELAY`                                                   | positive milliseconds, default 5000, maximum 60000                                                                                                                                                             |
| `OTEL_TRACES_SAMPLER`                                                       | `always_on`, `always_off`, `traceidratio`, or their `parentbased_` forms; default `parentbased_always_on`                                                                                                      |
| `OTEL_TRACES_SAMPLER_ARG`                                                   | ratio in `[0,1]` for either ratio sampler                                                                                                                                                                      |
| `OTEL_SERVICE_NAME`                                                         | fixed process service name; defaults to `tnld` or `tnl`; overrides resource `service.name`                                                                                                                     |
| `OTEL_RESOURCE_ATTRIBUTES`                                                  | fixed, operator-declared `service.name`, `service.namespace`, `service.instance.id`, `deployment.environment.name`, `cloud.provider`, `cloud.region`, `cloud.availability_zone`; values at most 128 characters |
| `OTEL_GO_X_OBSERVABILITY`                                                   | SDK queue capacity, size and drop observations; native process startup defaults this SDK feature to `true` when unset                                                                                          |

the general exporter TLS/header/compression/timeout/protocol settings accept
`OTEL_EXPORTER_OTLP_METRICS_*` and `OTEL_EXPORTER_OTLP_TRACES_*` overrides.
HTTPS verification is required; insecure transport, URL userinfo, queries,
fragments and redirects are rejected. invalid supported settings fail process
configuration with the setting name only. exporter failures after configuration
cannot change traffic decisions or process readiness. export has no persistent
queue or automatic request retry: metrics are collected again on the next tick;
failed trace batches are lost. the SDK's metric temporality preference is
supported; application histograms always use explicit boundaries.

process resource facts include the binary version and configured role. deployments
with several identical processes should supply a distinct fixed replica identity
as `service.instance.id`, or add equivalent identity in their receiving pipeline.
the library does not discover cloud metadata or derive tenant identity from the
currently executing request. no collector, backend, dashboard or alert setup is
part of this package.

## spans and attribute boundaries

`Start(ctx, name)` records an authored finite operation; its finish function is
idempotent. `PublisherOperation` additionally records the duration under a closed
operation vocabulary. errors become bounded outcomes, never raw exception text.
span limits are 32 attributes, 256 characters per value, eight events and eight
links, with at most eight attributes on an event/link. a process's SDK errors
are counted without printing receiver URLs, headers or response bodies.

`OwnedHTTPClient` injects W3C trace context only on dedicated control, authority,
private-ingress and private-relay API clients. `APIRequests` extracts that context
and names spans after the matched method/route pattern, never a raw path or URL.
`AuthorizationDecision` records semantic allow/deny results and marks HTTP 200
denials as `denied`. baggage and customer HTTP headers/bodies are not collected.
customer target transports observe connect/TLS locally and never inject tnl trace
headers. target TLS tests exercise both valid and rejected certificates.

tunnel hops retain the existing `visitor_connection_id` as a trace-only correlation
attribute. there is no tunnel wire change or invented parentage across tunnel
streams. existing context-free SQL, control, DNS and certificate observers create
local completed-operation spans from their measured intervals; those are not
automatically children of an API span. certificate `progress` and DNS `pending`
are observations, not trace errors.

`WithIdentity` carries authenticated, scoped team/group/publisher/service/deployment
IDs. publisher operation, connection-attempt, lease and readiness instruments use
those dimensions when available. public and private publishers bind saved service
and publisher identity; group workers add the verified group. deployment provenance
can be supplied by a caller after verification; this foundation does not invent
it. those dimensions never become process-wide tenant attributes. request IDs,
publish-run IDs/numbers, visitor IDs, hostnames, addresses and credentials are not
metric dimensions. the SDK bounds each instrument to 2000 attribute sets per
collection and reports excess series through its overflow attribute.

### current coverage

| boundary              | observations                                                                                                                                                                |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| publisher setup       | public/private startup through first readiness, target preflight, group lease, confirmed public/private heartbeat                                                           |
| publisher connections | public/private connection race duration and selected transport/preference; replacement attempts use the same path                                                           |
| publisher freshness   | last confirmed lease expiry and most recent readiness decision timestamps; failed refresh never extends the lease metric                                                    |
| visitors              | ingress admission/outcomes/open time/bytes; relay public/private registered/ready connections, stream slots, open decisions, copied wire bytes and completion outcomes      |
| target                | public HTTP target connect/TLS; managed TCP/database/HTTP target connect and protocol-aware TLS; no target trace propagation                                                |
| DNS/certificates      | existing worker claim/phase/transition observers, including managed-service claim/provider/verify/advance/save and committed transitions                                    |
| APIs                  | matched control/authority/private API duration and spans; HTTP visitor, browser session, connector, service-certificate, device-login and private visitor recheck decisions |
| database              | passive pool/activity snapshot, sanitized compiled query operations and failures; no SQL text, parameters or scrape-time queries                                            |
| maintenance           | cleanup including service audit; port capacity refreshed in a five-second worker attempt every 30 seconds, retaining last-good values on failure                            |

coverage is not a complete distributed request trace. public visitor TLS and
managed visitor admission/TLS have spans, but HTTP inspection and feedback remain
their own observations. there is no full target-body span, per-SQL row trace,
SQLite identity-state instrumentation, or cloud deployment provenance in this
change. readiness timestamps require freshness checks; they are not live gauges
authorizing access. process replacement resets process-local counters; control
remains the authority for identities, grants, leases, readiness and durable audit.
app-led probes whose caller has no authenticated service identity produce a
process-level observation; neither the project path nor the local registration
ID substitutes for that identity.

### export health

`tnl_observability_export_failures_total{signal}` counts failed metric/trace export
batches; `tnl_observability_export_lost_spans_total` counts spans in failed batches.
SDK `otel.sdk.processor.span.processed` with `error.type=queue_full` counts queue
overflow separately, alongside SDK queue size/capacity instruments. the SDK feature
uses this process's meter provider. `tnl_observability_sdk_errors_total` counts SDK
error callbacks without exporting their text. SDK self-observation also includes
non-duration distributions: benchmark `DurationSummaries` now selects only
histogram names ending in `_seconds`.

these are in-memory observations. a crash, shutdown deadline or unreachable
receiver can lose the final observations themselves. they are not durable usage
or audit totals.

## process and capacity

| Metric                                     | What it shows                         |
| ------------------------------------------ | ------------------------------------- |
| `tnl_process_info{role}`                   | The process's configured role.        |
| `tnl_admission_limit{resource}`            | Effective admission limits.           |
| `tnl_admission_rejections_total{resource}` | Work rejected because a limit is hit. |

Some limits apply **per public URL or hostname**; do not compare those with
process-wide occupancy. Standalone sums the limits of its two logical relays.

## ingress and relay

| Metric                                                        | What it shows                                                                          |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `tnl_ingress_connections{class}`                              | Occupied ingress admission slots.                                                      |
| `tnl_ingress_visitor_connections_total{outcome}`              | Ordinary visitor outcomes.                                                             |
| `tnl_ingress_visitor_stream_open_duration_seconds{outcome}`   | Time to a forwarding decision.                                                         |
| `tnl_ingress_relay_attempts_total{connection_slot,outcome}`   | Internal-forwarding attempts.                                                          |
| `tnl_ingress_routing_last_successful_check_timestamp_seconds` | Most recent successful routing check.                                                  |
| `tnl_ingress_lease_expiration_timestamp_seconds`              | Ingress lease expiry.                                                                  |
| `tnl_relay_publisher_connections_registered`                  | Locally registered publisher connections.                                              |
| `tnl_relay_publisher_connections_ready`                       | Ready publisher connections.                                                           |
| `tnl_relay_visitor_stream_slots_occupied`                     | Occupied relay stream slots.                                                           |
| `tnl_relay_visitor_stream_rejections_total{reason}`           | Non-capacity stream rejections.                                                        |
| `tnl_relay_earliest_lease_expiration_timestamp_seconds`       | Earliest local relay lease expiry.                                                     |
| `tnl_relay_forwarded_bytes_total{kind,direction}`             | Public URL or managed-service wire bytes at copy completion, including PROXY metadata. |
| `tnl_relay_visitor_stream_completions_total{kind,outcome}`    | Completed relay copy loops; not application outcomes.                                  |

Visitor outcomes are recorded when connections end. `forwarded` means ingress
established forwarding, not that visitor TLS or the local service succeeded.
restricted visitors now report the same forwarding boundary instead of retaining
`lookup_missing` after a successful lookup. private relay activity contributes to
the existing process-wide connection/stream occupancy families.
Relay attempt counts can exceed visitor counts when ingress retries. Ready
publisher connections are not the same as database claims.

## control and background work

| Metric                                                                 | What it shows                                                         |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `tnl_control_api_request_duration_seconds{surface,operation,outcome}`  | Completed API requests.                                               |
| `tnl_control_api_requests_in_flight{surface}`                          | Requests still running.                                               |
| `tnl_control_webhook_provider_source_requests_total{provider,outcome}` | Sender-policy lookups by fixed provider and bounded result.           |
| `tnl_control_public_urls_created_total{purpose}`                       | New saved public URLs, excluding idempotent retries.                  |
| `tnl_control_publish_runs_ready_total{purpose}`                        | Publish runs first made ready by public URL purpose.                  |
| `tnl_control_placement_decisions_total{action,outcome}`                | Publish run placement results.                                        |
| `tnl_control_certificate_work_duration_seconds{kind,stage,outcome}`    | Certificate worker attempts.                                          |
| `tnl_control_public_url_certificate_orders_total{domain_kind,plan}`    | New public URL certificate orders committed by this control process.  |
| `tnl_control_dns_work_duration_seconds{kind,phase,outcome}`            | DNS work and verification.                                            |
| `tnl_control_public_url_usage_items_total{result}`                     | Finalized, delivered, or retried items.                               |
| `tnl_control_cleanup_last_success_timestamp_seconds{kind}`             | Last successful cleanup.                                              |
| `tnl_control_guest_trials_last_24h{stage}`                             | Issued, allocated, ready, or ended guest trials from committed state. |
| `tnl_control_public_url_recovery_duration_seconds`                     | Newly observed recovery durations.                                    |

The API `surface` distinguishes control, built-in authority, and private
ingress and relay requests. A histogram's `_count` is its completed attempt
count. Certificate availability is not publisher installation. Usage results
count different kinds of items; do not sum them as one backlog.
certificate orders use fixed `managed|custom` domain kinds and `exact|wildcard`
plans. sum their rates across control replicas. idempotent retries and cached
certificate reuse do not increment the counter; a committed order can fail
before the CA issues a certificate. the counter does not measure the CA's
registered-domain quota or orders created outside this deployment.
Guest stages are `issued`, `allocated`, `ready`, `expired`, `ready_limit`,
and `transfer_limit`. They count trials, not publish runs or pings. Each control
reports the same database-wide 24-hour snapshot; use the maximum across control
replicas rather than summing them. Guest cleanup removes IP digests after one
hour for issuance and after trial expiry plus public URL deletion for access.
Provider source requests are approximate interest, not configured webhook
endpoints or deliveries. The provider label accepts only the fixed enum or
`unknown`; it never contains a public URL, project, or identity.
The `purpose` label is a fixed, client-declared public URL use such as `app`,
`webhooks`, or `oauth`. These process-local counters show activity, not distinct
identities. Query control's saved URLs and publish runs for distinct identities;
URLs saved before purpose tracking are labeled `app` by migration but do not
retroactively increment the creation counter.

For distinct identities rather than process-local counter rates, query control's
committed ready runs. Each identity appears once per purpose in the window:

```sql
SELECT u.purpose, count(DISTINCT r.acting_identity_id) AS identities
FROM control.publish_runs AS r
JOIN control.public_urls AS u ON u.id = r.public_url_id
WHERE r.ready_at >= now() - interval '30 days'
GROUP BY u.purpose
ORDER BY u.purpose;
```

The same purpose can be joined to `control.public_url_usage_buckets` for
connection and byte totals. Ingress cannot see the HTTP path or whether a
provider's webhook reached and succeeded at a local handler.

## service audit

`tnl_service_audit_events_total{result}` counts process-local queue and ingestion
events with fixed results: `queued`, `delivered`, `retry`, `dropped`, `accepted`,
and `duplicate`. It has no service, identity, source IP, or hostname labels.

Queued visitor observations can be lost on a process crash. `dropped` includes
invalid input, queue overflow, and observations lost when bounded shutdown
flushing ends. `delivered` describes a reporter submission; `accepted` and
`duplicate` describe control ingestion. Do not sum those stages as distinct
visitors or treat the counter as a durable audit log. Control's service audit
API reads committed events; transactional management facts commit with their
mutations independently of the visitor queue.

## database

| Metric                                                   | What it shows                              |
| -------------------------------------------------------- | ------------------------------------------ |
| `tnl_database_pool_*`                                    | Pool size, utilization, and waits.         |
| `tnl_database_pool_acquire_duration_seconds{outcome}`    | Time to acquire a connection.              |
| `tnl_database_query_duration_seconds{operation,outcome}` | SQL time after acquisition.                |
| `tnl_database_failures_total{phase,outcome}`             | Connection, transaction, and SQL failures. |

Scraping never queries PostgreSQL or a remote service. server metrics use
fixed operations and outcomes, plus an operator-owned ingress pool ID. publisher
metrics may use the authenticated stable IDs described above; never hostnames,
credentials, visitor IDs or raw URLs. Database-wide
snapshots repeat across control replicas; use their maximum rather than
summing them.
Definitions and role registration live in `internal/observability`; record
events at their ingress, relay, control, or worker boundary.
