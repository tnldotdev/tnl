# Observability

`tnld` exposes process probes and Prometheus metrics on the private address configured by
`TNLD_METRICS_LISTEN`. The default is `127.0.0.1:9090`; an empty value disables
the entire listener, including its health and readiness endpoints. It serves
plain HTTP and must remain private.

The registry includes the standard Go and process collectors. Monitor
file-descriptor pressure with `process_open_fds` and `process_max_fds`; tnl does
not duplicate those metrics under its own prefix.

## Service Health

Choose the probe for the process being monitored:

| Listener             | Path         | Success / failure   | Guarantee                                            |
| -------------------- | ------------ | ------------------- | ---------------------------------------------------- |
| Public control HTTPS | `/v1/health` | 200 JSON            | Control API is serving HTTP                          |
| Public control HTTPS | `/v1/ready`  | 200 / 503 JSON      | PostgreSQL connection and supported schema are ready |
| Private process HTTP | `/health`    | 204, empty          | This process's probe listener is serving             |
| Private process HTTP | `/ready`     | 204 / 503, empty    | Role-specific runtime readiness below                |
| Private process HTTP | `/metrics`   | Prometheus response | Metrics, not a readiness decision                    |

For example, from the process host using the default private address:

```console
curl --fail https://control.tnl.example.com/v1/health
curl --fail https://control.tnl.example.com/v1/ready
curl --fail http://127.0.0.1:9090/ready
```

Private readiness checks differ by role:

- Control checks its listeners, PostgreSQL connection, schema version, and
  public control certificate.
- Ingress checks its lease, routing table, certificate, and listener.
- Relay checks its lease, certificate, and publisher and internal-forwarding
  listeners.
- Standalone checks every role it contains.

Readiness does not prove that every background task, route, or local service is
healthy. Publish a test route for an end-to-end check. `tnl_info{role}` reports
the process role.

## Runtime Metrics

- `tnl_control_requests_total{operation,outcome}` and
  `tnl_control_request_duration_seconds{operation,outcome}` measure control API traffic.
  Operations are matched method/path patterns, such as `POST /v1/routes`, and
  outcomes are `success`, `client_error`, `server_error`, `canceled`, or
  `deadline_exceeded`. HTTP duration covers the handler, including authentication,
  serialization, and any long-poll wait; it is not state-operation or SQL time.
- `tnl_control_requests_in_flight{operation}` reports control requests still
  executing, including requests waiting on the database.
- Control and standalone export `tnl_database_pool_max_connections`,
  `tnl_database_pool_acquired_connections`, `tnl_database_pool_idle_connections`,
  and `tnl_database_pool_total_connections` from their local pgx pool.
  The pool defaults to eight connections per process; `pool_max_conns` in
  `TNLD_DATABASE_URL` overrides the default.
  `tnl_database_pool_acquires_total`, `tnl_database_pool_waited_acquires_total`,
  `tnl_database_pool_acquire_wait_seconds_total`, and
  `tnl_database_pool_canceled_acquires_total` distinguish completed acquisitions,
  successful acquisitions that waited, their cumulative waiting time, and
  canceled acquisitions. These metrics use in-memory statistics and remain
  available when the application pool is exhausted.
- `tnl_database_client_connections{purpose,state}` reports process-local client
  sockets by fixed purpose and the `open` or `connecting` state.
  `tnl_database_client_connection_events_total{purpose,event}` reports cumulative
  `opened`, `closed`, and `failed` events for the same clients.
- `tnl_database_operations_active{operation}` and
  `tnl_database_operation_oldest_age_seconds{operation}` report active
  request-pool operations and the oldest operation age. Operation labels are
  restricted to compiled sqlc names, transaction commands, or `unknown`.
  `tnl_database_operations_omitted` reports active operations beyond the
  bounded 64-operation tracker.
- `tnl_database_query_duration_seconds{operation,outcome}` records completed
  request-pool queries from driver start through completion, including row
  consumption. It includes driver, network, pooler, and PostgreSQL work, but
  excludes acquiring a local pool connection. Names use the same compiled sqlc,
  transaction-command, or `unknown` labels as active operations.
- `tnl_database_guard_held_duration_seconds{operation,outcome}` records the
  driver-observed interval from the first successful guard-query completion in
  a transaction through its commit, rollback, or observed connection failure.
  Guards are `LockLocalTeamForSession`, `LockRelayServicesForPlacement`,
  `GetRelayLeaseForClaim`, `GetRelayLeaseForReady`, `LockIngressRoutingTableClock`,
  `InsertFinalIngressRoutingTableEvent`,
  `LockRouteSessionForUsage`, and `LockIngressLease`. This excludes the acquiring
  query's own wait and is **not exact PostgreSQL lock-held time**: acquisition
  precedes the driver's response, and release precedes the transaction-ending
  response. Outcome describes the ending command; a successful rollback is
  `success` even when the enclosing application operation failed. Unfinished
  windows whose sockets close without a final driver callback are discarded.
  Single-event publication acquires the routing clock inside
  `InsertFinalIngressRoutingTableEvent`, so that guard interval covers only the
  remainder through commit; the query duration includes acquisition and insertion.
  Multi-event publication also has an explicit `LockIngressRoutingTableClock`
  interval. These windows can overlap and must not be summed as exclusive time.
- `tnl_operation_duration_seconds{operation,outcome}` measures completed
  application operations. Control operations are `CreateRouteSession`,
  `HeartbeatRouteSession`, `CloseRouteSession`, `ReadIngressRoutingTableSnapshot`,
  `ReadIngressRoutingTableEvents`, `ReportIngressUsage`, `RenewIngress`,
  `ClaimPublisherConnection`, `MarkPublisherConnectionReady`,
  `AdvanceIngressRoutingRetention`, and `PruneIngressRoutingHistory`. These span
  validation, pool acquisition, SQL, and transaction cleanup; they exclude HTTP
  handling and long-poll idle waits outside the state method. Ingress operations
  are `IngressFetchSnapshot`, `IngressFetchEvents`, `IngressRenewLease`,
  `IngressApplySnapshot`, and `IngressApplyEvents`. Fetch timings are client
  request spans, so event fetches include normal long-poll idle time; apply
  timings measure local routing-table work separately. Application and SQL
  outcomes are `success`, `error`, `canceled`, or `deadline_exceeded`.
- Relay and standalone also record application durations for `RelayRegister`
  and `RelayRenewLease` (control call plus lease validation), `RelayBeginDrain`
  (control's drain acknowledgement), and `RelayDrain` (one local registry drain
  call through completion or cancellation). Registration excludes certificate
  fetching and retry backoff; local drain timing excludes the control request.
- `RelayAdmitPublisherConnection` starts with an established multiplexed
  transport and ends when authentication, claiming, local registration, and
  readiness complete or fail. It excludes the transport's TLS/QUIC handshake,
  failure cleanup, and the long-lived publisher connection's lifetime.
- `RelayOpenVisitorStream` starts after parsing an authenticated internal
  forwarding header and ends on rejection/error or acknowledgement back to
  ingress after the publisher accepts its stream. It includes local capacity and
  assignment checks and publisher-stream opening; it excludes route TLS,
  application response time, and subsequent byte copying. A successfully sent
  rejection is recorded as `error`, with capacity rejections also counted by the
  existing resource counter. Completed open/admission metrics are observable
  while their streams/connections remain active.
- `tnl_relay_leases{state}` reports active and draining local relay leases. A
  standalone process reports both of its logical relay services.
- `tnl_publisher_connections{state}` reports publisher connections by state.
- `tnl_streams_active{stage}` reports active visitor streams observed at the
  `ingress` or `relay` stage. Standalone exports both stages separately.
- `tnl_capacity_rejections_total{resource}` reports operations rejected because
  a resource is full. Resources are `public_connections`, `route_connections`,
  `client_hello_connections`, `challenge_connections`,
  `challenge_hostname_connections`, `control_connections`,
  `relay_tcp_connections`, `publisher_connections`, or `relay_streams`.
  `public_connections` now counts ordinary visitors after classification;
  `draining` records classified connections rejected during ingress drain.
- `tnl_source_limiter_rejections_total` and `tnl_source_limiter_entries` report
  excessive ordinary visitor connection attempts and visitor source-IP table
  usage. Active route certificate checks and standalone control/relay handoffs
  have independent admission budgets and do not consume these source tokens.
- `tnl_ip_allowlist_denials_total` reports visitor connections rejected by route
  IP policy without route or source labels.
- `tnl_forwarded_bytes_total{direction}` reports bytes forwarded through the
  visitor path.

Labels use a fixed set of values. They never contain route IDs, hostnames, team
IDs, membership IDs, ingress IDs, relay IDs, request IDs, error text, or SQL.
Use structured logs for request-specific details. Client responses do not expose
internal details.

Prometheus collection uses only process-local memory and never opens a database
connection. This keeps `/metrics` available during pool exhaustion and avoids
adding PostgreSQL or PgBouncer pressure during a failure.

### Duration Distributions

All duration histograms use seconds with finite boundaries at `0.001`, `0.0025`,
`0.005`, `0.01`, `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5`, `5`, `10`,
`20`, `30`, `60`, and `120`, plus the standard `+Inf` bucket. Completed failures
are included under their own outcome, including timeouts waiting for a pool slot.
Still-running requests appear in in-flight or active-query metrics, not completed
duration histograms.

Local controlstate load tests and benchmark reporting consume these production
histograms. Before/after cumulative count, sum, and bucket differences give the
interval's count, total, mean, and estimated p50/p95/p99. Quantiles interpolate
within buckets; they are unavailable for empty samples or the unbounded bucket.
No exact maximum is inferred from buckets. Reports retain each control process's
registry separately; percentiles must never be averaged across controls.

Local load capture excludes fixture setup and cleanup, joins actors before the
final capture, and retains failed operations in ordinary test logs. Workload
counts, correctness checks, setup time, and recovery workflow wall time stay
test-local. The optional artificial SQL delay composes with the production
tracer: each query excludes its own injected delay, while guard intervals include
earlier delays in the transaction. Hostname lookup uses the production HTTP
handler histogram.

Benchmarks use the standard Prometheus text parser and the same histogram
summary helper as local load tests. All load workers finish setup before the
baseline metrics scrape and wait for that scrape before starting fresh traffic.
They all finish fresh traffic before the final scrape, and wait for collection
before recovery or cleanup. Activation intervals currently bracket the
metrics-owning publisher worker's activation, rather than a synchronized fleet
activation barrier. Reports retain before/final samples outside the bounded
periodic window and mark missing data, counter resets, or restart intervals as
incomplete. Visitor-side DNS, connection, TLS, first-byte, and total durations
retain their distinct observation points, sharing histogram buckets/reporting;
their directly observed maxima are not inferred from histogram buckets.

### Ingress Routing Freshness

Ingress and standalone expose passive routing-controller metrics:

- `tnl_ingress_routing_initialized` indicates an applied snapshot.
- `tnl_ingress_routing_caught_up` indicates that the last successful event response
  confirmed catch-up; failures or a resnapshot requirement clear it.
- `tnl_ingress_routing_last_successful_check_timestamp_seconds` records the last
  successfully applied snapshot or event response, including empty responses.
- `tnl_ingress_routing_last_caught_up_timestamp_seconds` records the last event
  response confirming catch-up. Both timestamps are zero before their first event.
- `tnl_ingress_routing_latest_observed_revision`,
  `tnl_ingress_routing_applied_revision`, and
  `tnl_ingress_routing_known_revision_backlog` report observed progress.
- `tnl_ingress_routing_update_failures_total` counts fetch/apply failures, excluding
  controller shutdown cancellation and resnapshot-required responses.
  `tnl_ingress_routing_resnapshots_total` counts resnapshot-required responses.

These describe successful responses, not control's live revision while a request
is pending. Zero known backlog or a previous catch-up confirmation does not prove
current freshness. Monitor the check timestamp's age alongside failures and
backlog; lease readiness alone does not establish routing freshness.

### Routing History Cleanup

Control and standalone export passive cleanup progress:

- `tnl_routing_history_retained_after_revision`: the greatest retention floor
  this process has observed, initially zero until its first successful update.
- `tnl_routing_history_cleanup_rows_total{action="scanned"|"deleted"}`: committed
  cleanup candidate and deletion counts. Scanned anchors can recur in later sweeps.
- `tnl_routing_history_cleanup_skipped_total`: batches skipped because another
  control held the cleanup lock.

The floor is a shared database revision, not a sum across controls. Counters are
process-local and reset on restart. Pair progress with the cleanup application/SQL
duration histograms and operational error logs. Check PostgreSQL relation sizes,
dead tuples, and autovacuum separately; deleting history does not guarantee an
immediate reduction in physical disk usage. Prometheus collection performs no SQL.

## Database Failure Snapshots

Control and standalone also serve `GET /debug/database` on the private
observability listener. This returns up to 64 non-idle PostgreSQL sessions in
the current database, including session state, wait events, transaction/query
age, query IDs when available, generated query operation names, and blocking
backend PIDs. Query text, parameter values, and connection credentials are not
returned. A `truncated` flag identifies an incomplete session list. Each session
includes at most eight blocking PIDs, with `blocking_pids_truncated` set when
additional blockers were omitted. These limits keep a maximum-shaped snapshot
within the benchmark collector's 64 KiB per-snapshot budget.

Unlike Prometheus collection, this detailed snapshot actively connects to
PostgreSQL and PgBouncer. It remains an explicit diagnostic operation rather
than running on every metrics scrape. Benchmark failure reports collect and
retain these snapshots automatically.

The snapshot uses a separate connection through the configured pooled URL, with
a three-second timeout and at most one collection per process at a time. It can
inspect an exhausted local pgx pool, but it still depends on the external pooler
and PostgreSQL being reachable. The endpoint also captures up to 64 currently
active request-pool SQL operations directly from pgx instrumentation, with elapsed
seconds and an `operations_truncated` flag. Names are restricted to compiled sqlc
query names, transaction commands, or `unknown`; no SQL or arguments are retained.
Connection-initialization queries may be `unknown`. Requests still waiting to
acquire a pool connection have not started SQL and appear only in pool metrics.

The endpoint returns HTTP 200 with local activity even when the upstream snapshot
fails; `error` describes that bounded failure. Database permissions still determine
visibility into PostgreSQL sessions, wait states, and blocking relationships.
Local operation age includes driver/network/pooler time and does not by itself
prove a PostgreSQL lock wait or identify its blocking transaction.

`connections` accounts for local client sockets by fixed purpose: `request_pool`,
`tls_leadership`, `dns_challenge`, `diagnostics`, and `pooler_diagnostics`. Each
reports open and connecting sockets, cumulative successful opens, completed
socket cleanups, and failed connection attempts. Counts are captured before the
observer connects and remain available when the database cannot be reached.
They describe this process's clients, not PostgreSQL backend slots or a
deployment-wide connection limit. Dedicated connections remain excluded from
request-pool SQL activity.

Within the same three-second snapshot budget, a one-second read-only attempt
connects to the `pgbouncer` admin database on the configured pooled endpoint,
using the runtime credentials. `pooler.settings` retains only pool mode and
allowlisted numeric connection/lifetime limits from `SHOW CONFIG`.
`pooler.clients` aggregates `SHOW CLIENTS` states on the reached pooler instance,
including the observer, with an explicit truncation flag above 4,096 clients.
Client identities and addresses
are not returned. A denied or unsupported admin console is recorded in
`pooler.error`; missing settings or counts remain unavailable, never inferred
from the database plan. Local accounting and PostgreSQL diagnostics still work
when pooler inspection is unavailable.

## Alert Queries

File-descriptor utilization is a primary ingress and relay capacity signal:

```promql
process_open_fds / clamp_min(process_max_fds, 1)
```

Warn above `0.80` for 15 minutes and treat above `0.90` for 5 minutes as
critical. Other useful alert conditions include:

```promql
increase(tnl_capacity_rejections_total[5m]) > 0
increase(tnl_source_limiter_rejections_total[5m]) > 0
increase(tnl_ip_allowlist_denials_total[10m]) > 0
sum(increase(tnl_control_requests_total{outcome="server_error"}[10m])) >= 5
```

Control API alerts should require both error volume and ratio to avoid paging on
one failed request:

```promql
sum(increase(tnl_control_requests_total{outcome="server_error"}[10m])) >= 5
and
sum(rate(tnl_control_requests_total{outcome="server_error"}[5m]))
  / clamp_min(sum(rate(tnl_control_requests_total[5m])), 0.001) > 0.02
```

Each deployment should define recording and alert rules for its environment.
This repository defines metric names, their meaning, and allowed label values.
