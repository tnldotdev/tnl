# observability

`tnld` serves private health, readiness, metrics, and database diagnostics from
`TNLD_METRICS_LISTEN`. The default is `127.0.0.1:9090`. Keep this listener on a
private network.

An empty `TNLD_METRICS_LISTEN` disables the entire listener, including its
health and readiness endpoints.

## check process health

Use the checks in this order:

```text
/health succeeds?
   | no  -> process or probe listener is unavailable
   v yes
/ready succeeds?
   | no  -> inspect the role dependency and logs
   v yes
test route succeeds?
   | no  -> inspect DNS, ingress, relay, publisher, and target
   v yes
end-to-end path is serving
```

The endpoints are:

| Listener             | Path         | Result              | Meaning                                                  |
| -------------------- | ------------ | ------------------- | -------------------------------------------------------- |
| Public control HTTPS | `/v1/health` | 200 JSON            | The control API serves HTTP.                             |
| Public control HTTPS | `/v1/ready`  | 200 or 503 JSON     | PostgreSQL and the supported schema are ready.           |
| Private process HTTP | `/health`    | 204 or failure      | This process's probe listener is serving.                |
| Private process HTTP | `/ready`     | 204 or 503          | The role-specific checks below pass.                     |
| Private process HTTP | `/metrics`   | Prometheus response | Metrics are available. This is not a readiness decision. |

For example:

```console
curl --fail https://control.tnl.example.com/v1/ready
curl --fail http://127.0.0.1:9090/ready
```

Private readiness checks these dependencies:

| Role       | Ready when                                                                          |
| ---------- | ----------------------------------------------------------------------------------- |
| Control    | Listeners, PostgreSQL, schema version, and public certificate are ready.            |
| Ingress    | Lease, routing table, certificate, and visitor listener are ready.                  |
| Relay      | Lease, certificate, publisher listener, and internal forwarding listener are ready. |
| Standalone | Every contained role is ready.                                                      |

Readiness does not prove that every route, publisher, or local service works.
Publish a test route for an end-to-end check.

## monitor the control api

| Metric                                                    | Meaning                                                                 |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| `tnl_control_requests_total{operation,outcome}`           | Completed control API requests.                                         |
| `tnl_control_request_duration_seconds{operation,outcome}` | Full HTTP handler duration, including authentication and serialization. |
| `tnl_control_requests_in_flight{operation}`               | Control requests still running or waiting on the database.              |

Outcomes are `success`, `client_error`, `server_error`, `canceled`, and
`deadline_exceeded`. Operation labels use fixed method and path patterns, never
route IDs or hostnames.

## monitor postgresql pressure

| Metric                                         | Meaning                                    |
| ---------------------------------------------- | ------------------------------------------ |
| `tnl_database_pool_max_connections`            | Configured local pgx pool limit.           |
| `tnl_database_pool_acquired_connections`       | Pool connections currently checked out.    |
| `tnl_database_pool_idle_connections`           | Idle pool connections.                     |
| `tnl_database_pool_total_connections`          | Total local pool connections.              |
| `tnl_database_pool_acquires_total`             | Completed pool acquisitions.               |
| `tnl_database_pool_waited_acquires_total`      | Successful acquisitions that had to wait.  |
| `tnl_database_pool_acquire_wait_seconds_total` | Cumulative wait for pool connections.      |
| `tnl_database_pool_canceled_acquires_total`    | Pool acquisitions canceled before success. |

The request pool defaults to eight connections per process. The
`pool_max_conns` PostgreSQL URL parameter overrides it.

These metrics remain available when the pool is exhausted:

| Metric                                                       | Meaning                                             |
| ------------------------------------------------------------ | --------------------------------------------------- |
| `tnl_database_client_connections{purpose,state}`             | Local database sockets that are open or connecting. |
| `tnl_database_client_connection_events_total{purpose,event}` | Open, close, and failed connection events.          |
| `tnl_database_operations_active{operation}`                  | Active request-pool operations.                     |
| `tnl_database_operation_oldest_age_seconds{operation}`       | Age of the oldest active operation.                 |
| `tnl_database_operations_omitted`                            | Operations beyond the bounded tracker.              |

Completed work is measured by:

| Metric                                                        | Meaning                                                                               |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `tnl_database_query_duration_seconds{operation,outcome}`      | Driver, network, pooler, PostgreSQL, and row-consumption time after pool acquisition. |
| `tnl_database_guard_held_duration_seconds{operation,outcome}` | Approximate driver-observed transaction guard interval.                               |
| `tnl_operation_duration_seconds{operation,outcome}`           | Full application operation, including pool acquisition and transaction cleanup.       |

Guard duration is not exact PostgreSQL lock-held time. Use it to find long
transaction windows, then use database diagnostics to determine whether a lock,
query, network, or pooler caused the delay.

## monitor ingress and relay capacity

| Metric                                    | Meaning                                                        |
| ----------------------------------------- | -------------------------------------------------------------- |
| `tnl_relay_leases{state}`                 | Active and draining local relay leases.                        |
| `tnl_publisher_connections{state}`        | Publisher connections by state.                                |
| `tnl_streams_active{stage}`               | Active visitor streams at ingress or relay.                    |
| `tnl_capacity_rejections_total{resource}` | Work rejected because a process-local resource was full.       |
| `tnl_source_limiter_rejections_total`     | Ordinary visitor connections rejected by source rate limiting. |
| `tnl_source_limiter_entries`              | Active visitor source buckets.                                 |
| `tnl_ip_allowlist_denials_total`          | Connections rejected by route IP policy.                       |
| `tnl_forwarded_bytes_total{direction}`    | Bytes forwarded through the visitor path.                      |

Capacity resources include visitor connections, route connections, ClientHello
inspection, certificate challenges, standalone service handoffs, publisher
connections, and relay streams.

`tnl_ip_allowlist_denials_total` intentionally has no route or source label.
Use aggregate policy-denial trends without exposing visitor addresses.

The standard Go and process collectors are also enabled. File descriptors are a
primary ingress and relay capacity signal:

```promql
process_open_fds / clamp_min(process_max_fds, 1)
```

## monitor routing freshness

Ingress and standalone expose routing-controller state:

| Metric                                                        | Meaning                                                |
| ------------------------------------------------------------- | ------------------------------------------------------ |
| `tnl_ingress_routing_initialized`                             | A routing snapshot has been applied.                   |
| `tnl_ingress_routing_caught_up`                               | The last successful event response confirmed catch-up. |
| `tnl_ingress_routing_last_successful_check_timestamp_seconds` | Last applied snapshot or event response.               |
| `tnl_ingress_routing_last_caught_up_timestamp_seconds`        | Last response that confirmed catch-up.                 |
| `tnl_ingress_routing_latest_observed_revision`                | Latest revision reported by control.                   |
| `tnl_ingress_routing_applied_revision`                        | Latest revision applied locally.                       |
| `tnl_ingress_routing_known_revision_backlog`                  | Known unapplied revision count.                        |
| `tnl_ingress_routing_update_failures_total`                   | Fetch and apply failures.                              |
| `tnl_ingress_routing_resnapshots_total`                       | Required full resnapshots.                             |

Zero known backlog does not prove current freshness while a request is pending.
Alert on the age of the last successful check together with failures and backlog.

## monitor routing history cleanup

Control and standalone expose cleanup progress:

| Metric                                           | Meaning                                                   |
| ------------------------------------------------ | --------------------------------------------------------- |
| `tnl_routing_history_retained_after_revision`    | Greatest shared retention floor observed by this process. |
| `tnl_routing_history_cleanup_rows_total{action}` | Rows scanned or deleted by committed cleanup batches.     |
| `tnl_routing_history_cleanup_skipped_total`      | Batches skipped because another control was cleaning.     |

The floor is a shared database revision, not a value to sum across controls.
Counters are process-local and reset after restart.

Deleting history creates dead tuples and WAL. Check PostgreSQL relation size,
autovacuum, and free-space reuse separately.

## interpret duration histograms

Duration metrics use seconds. They include finite buckets from 1ms through two
minutes plus `+Inf`.

Calculate percentiles from the combined bucket counts for the interval. Do not
average percentiles from separate control processes. An empty sample has no
percentile, and the unbounded bucket does not provide an exact maximum.

Still-running work appears in in-flight and active-operation metrics, not in
completed duration histograms.

## inspect a database failure

Control and standalone serve `GET /debug/database` on the private observability
listener. Use it during a failure; do not scrape it as a metric.

The response includes bounded, redacted information about:

- non-idle PostgreSQL sessions and wait events;
- transaction and query age;
- blocking backend process IDs;
- active local request-pool operations;
- local database socket counts;
- selected PgBouncer settings and client-state counts when available.

It never returns SQL text, query parameters, credentials, client identities, or
client addresses.

The endpoint uses a separate connection and a three-second total timeout. It can
inspect an exhausted local pgx pool, but it still depends on PgBouncer and
PostgreSQL being reachable. It returns local activity with HTTP 200 even when an
upstream snapshot fails; the `error` field describes that failure.

Database permissions determine which PostgreSQL sessions and blockers are
visible. PgBouncer admin-console denial is reported separately and does not
prevent local accounting.

## start with these alerts

Warn when file-descriptor use stays above 80% for 15 minutes. Treat use above
90% for five minutes as critical.

Other useful starting conditions are:

```promql
increase(tnl_capacity_rejections_total[5m]) > 0
increase(tnl_source_limiter_rejections_total[5m]) > 0
increase(tnl_ip_allowlist_denials_total[10m]) > 0
```

Require both error volume and error ratio before paging on the control API:

```promql
sum(increase(tnl_control_requests_total{outcome="server_error"}[10m])) >= 5
and
sum(rate(tnl_control_requests_total{outcome="server_error"}[5m]))
  / clamp_min(sum(rate(tnl_control_requests_total[5m])), 0.001) > 0.02
```

Also alert on certificate renewal failures, expired ingress or relay leases,
routing freshness, and insufficient ready publisher connections. Tune every
threshold for the deployment's normal traffic and capacity.

## understand metric privacy

Metric labels use fixed, bounded values. They never contain route IDs,
hostnames, team or membership IDs, process identities, request IDs, error text,
or SQL.

Prometheus collection reads process memory only. It does not open database
connections or add PostgreSQL pressure during a failure.
