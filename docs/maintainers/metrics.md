# metrics

Each `tnld` process serves Prometheus metrics on its private observability
listener. Use them to locate a failure boundary, then check the relevant
component. A standalone process exposes control, ingress, and two logical
relays in one registry; split processes expose only their own role's metrics.

## scrape a process

The default listener is `127.0.0.1:9090`. Set `TNLD_METRICS_LISTEN` to another
private address or to an empty value to disable it. To inspect a local process:

```console
curl --silent http://127.0.0.1:9090/metrics
curl --silent --output /dev/null --write-out '%{http_code}\n' http://127.0.0.1:9090/ready
```

`/ready` reports whether that process can serve its role. `/metrics` remains
available when readiness fails. `tnl_process_info{role}` identifies the role;
Prometheus also exports the standard `go_*` and `process_*` families. Every
application metric starts with `tnl_`. Collection reads process memory and
never queries PostgreSQL or a remote service.

## choose a signal

| When you need to know              | Start with                                                                                                                                                                                   |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Why visitors cannot connect        | `tnl_ingress_visitor_connections_total`, then `tnl_ingress_relay_attempts_total` and `tnl_relay_visitor_stream_rejections_total` to locate failed internal forwarding.                       |
| Whether capacity is exhausted      | `tnl_admission_rejections_total{resource}` and `tnl_admission_limit{resource}`. Compare with `tnl_ingress_connections{class}` or `tnl_relay_visitor_stream_slots_occupied` where applicable. |
| Whether routing or leases are old  | `tnl_ingress_routing_last_successful_check_timestamp_seconds`, `tnl_ingress_routing_caught_up`, and the ingress or relay lease-expiration timestamp.                                         |
| Why control requests are slow      | `tnl_control_api_request_duration_seconds`, `tnl_database_pool_acquire_duration_seconds`, and `tnl_database_query_duration_seconds`.                                                         |
| Whether background work progresses | Certificate and DNS work durations and transition counters; public URL usage item counters; cleanup last-success timestamps.                                                                 |

The `surface` label on control API requests distinguishes `control`,
`authority`, `private_ingress`, and `private_relay`. The `operation` label is a
matched HTTP pattern, such as a pattern with `{public_url_id}`, or `unmatched`.
This includes requests rejected during authentication or parameter binding.
The built-in authority surface is absent when the server uses an external
authority.

Counters ending in `_total` count events. A duration histogram's `_count`
already counts its completed observations; use it instead of looking for a
separate requests or attempts counter. For example, completed control API
requests by surface and outcome are:

```promql
sum by (surface, outcome) (
  rate(tnl_control_api_request_duration_seconds_count[5m])
)
```

`tnl_control_api_requests_in_flight` covers requests that have not completed,
including routing long polls. Use its gauge alongside durations when completed
requests stop arriving.

The `public_url_connections`, `denied_public_url_connections`, and
`challenge_hostname_connections` admission limits apply **per key**. Do not
compare them with a process-wide occupancy gauge. Standalone reports the sum
of its two logical relays' connection and stream limits.

## follow a visitor connection

Ingress records one `tnl_ingress_visitor_connections_total{outcome}` when a
classified ordinary visitor connection ends. An outcome of `forwarded` means
ingress established forwarding, **not** that visitor TLS, HTTP, or the local
service succeeded. Held connections appear in the admission and backend-stream
gauges before their terminal outcome is recorded.

`tnl_ingress_visitor_stream_open_duration_seconds` records the forwarding
decision as soon as it is made. `tnl_ingress_relay_attempts_total` counts each
attempt by connection slot, so retries can make its total larger than the
visitor count. Inspection failures and ACME challenge rejections have their
own counters. `tnl_ingress_forwarded_bytes_total{direction}` updates at setup
and after a copy ends, so active long-lived copies may not yet appear in the
byte rate.

At a relay, `tnl_relay_publisher_connections_registered` includes locally
registered connections not yet ready;
`tnl_relay_publisher_connections_ready` includes only ready connections.
Neither is the authoritative count of database claims. Use
`tnl_relay_publisher_connection_exits_total{reason}` to spot unexpected losses
and `tnl_relay_visitor_stream_rejections_total{reason}` to distinguish stale
connection assignments from publisher unavailability. Capacity rejections
are counted separately under `tnl_admission_rejections_total`.

## check freshness and durable work

Ingress routing metrics expose initialization, catch-up, observed/applied and
acknowledged revisions, last-success timestamps, failures, and resnapshots.
For example, inspect the age of the last successful check:

```promql
time() - tnl_ingress_routing_last_successful_check_timestamp_seconds
```

A timestamp of zero means the process has never completed that step. Equal
observed and applied revisions do **not** prove freshness while a routing
request is pending. `tnl_ingress_lease_expiration_timestamp_seconds` and
`tnl_relay_earliest_lease_expiration_timestamp_seconds` describe local leases;
`tnl_relay_local_leases` is not a control-wide valid-lease count.

Control exposes `tnl_control_placement_decisions_total` for new placement and
replenishment, and `tnl_control_connection_assignments_replaced_total` only
after a heartbeat commits its replacements. Certificate claim counters, work
histograms, and transition counters separate empty claims, saved retries, and
committed progress. DNS work histograms distinguish provider failures from
pending verification. Certificate availability does not mean a publisher has
installed it. The control and relay certificate-expiration gauges describe
locally loaded material; zero can mean it has not yet been observed.

`tnl_control_public_url_usage_items_total{result}` separates finalized
buckets, accepted deliveries, persisted retries, and rejected reports. Each
result counts a different kind of item; do not sum them as one backlog. The
ingress `tnl_ingress_usage_retained_buckets` gauge measures local in-memory
work, not deliveries waiting in PostgreSQL. Cleanup last-success timestamps
help distinguish idle work from a loop that has stopped making progress.

`tnl_control_public_url_recovery_duration_seconds` measures newly committed
recovery observations, not the historical PostgreSQL total. If observations
stall, compare it with `tnl_ingress_recovery_observations_pending` and the
ingress recovery-attempt counter. Replays are not counted as new recoveries.

## diagnose PostgreSQL contention

`tnl_database_pool_*` provides pool limits, utilization, waits, and canceled
acquisitions. `tnl_database_pool_acquire_duration_seconds` includes waits and
failed acquisitions; `tnl_database_query_duration_seconds` starts **after**
acquisition. `tnl_database_failures_total{phase,outcome}` identifies acquire,
begin, query, commit, and rollback failures. An acquisition failure cannot have
a compiled SQL operation name.

The database client-connection families count local sockets, not PostgreSQL
backend slots. The guard-held duration is a driver-observed interval, not an
exact lock duration. Active-operation gauges come from a bounded local tracker;
check `tnl_database_operations_omitted` when interpreting them. A scrape never
acquires a database connection, including when the pool is exhausted.

## change a metric

Definitions and role registration live in `internal/observability`; the code
that observes an event belongs at its actual boundary in ingress, relay,
control state, or the relevant worker. Use fixed labels and explicit units.
Never put a hostname, public URL ID, identity, connection ID, error message,
raw URL, credential, or SQL text in a label. Count a durable transition only
after its transaction or save succeeds, and keep collectors free of I/O.

Update the observability tests and any runtime/load selectors that read the
family name. Follow the checks in [contributing](../../contributing.md); use a
focused PostgreSQL integration test when the event boundary is a database
commit.
