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
healthy. Publish a test route for an end-to-end check. `tnl_info{mode}` reports
the process role.

## Runtime Metrics

- `tnl_control_requests_total{operation,outcome}` and
  `tnl_control_request_duration_seconds{operation}` measure control API traffic.
  Operations are matched method/path patterns, such as `POST /v1/routes`, and
  outcomes are `success`, `client_error`, `server_error`, or `canceled`.
- `tnl_control_requests_in_flight{operation}` reports control requests still
  executing, including requests waiting on the database.
- Control and standalone export `tnl_database_pool_max_connections`,
  `tnl_database_pool_acquired_connections`, `tnl_database_pool_idle_connections`,
  and `tnl_database_pool_total_connections` from their local pgx pool.
  `tnl_database_pool_acquires_total`, `tnl_database_pool_waited_acquires_total`,
  `tnl_database_pool_acquire_wait_seconds_total`, and
  `tnl_database_pool_canceled_acquires_total` distinguish completed acquisitions,
  successful acquisitions that waited, their cumulative waiting time, and
  canceled acquisitions. These metrics use in-memory statistics and remain
  available when the application pool is exhausted.
- `tnl_routes{state}` reports stored routes by state.
- `tnl_relay_leases{state}` reports control-owned relay leases in a relay or
  standalone process.
- `tnl_publisher_connections{state}` reports publisher connections by state.
- `tnl_streams_active` reports active visitor streams in the process.
- `tnl_capacity_rejections_total{resource}` reports operations rejected because
  a resource is full.
- `tnl_source_limiter_rejections_total` and `tnl_source_limiter_entries` report
  excessive connection attempts and source-IP table usage.
- `tnl_ip_allowlist_denials_total` reports visitor connections rejected by route
  IP policy without route or source labels.
- `tnl_forwarded_bytes_total{direction}` reports bytes forwarded through the
  visitor path.

Labels use a fixed set of values. They never contain route IDs, hostnames, team
IDs, membership IDs, ingress IDs, relay IDs, request IDs, error text, or SQL.
Use structured logs for request-specific details. Client responses do not expose
internal details.

## Database Failure Snapshots

Control and standalone also serve `GET /debug/database` on the private
observability listener. This returns up to 64 non-idle PostgreSQL sessions in
the current database, including session state, wait events, transaction/query
age, query IDs when available, generated query operation names, and blocking
backend PIDs. Query text, parameter values, and connection credentials are not
returned. A `truncated` flag identifies incomplete snapshots.

The snapshot uses a separate connection through the configured pooled URL, with
a three-second timeout and at most one collection per process at a time. It can
inspect an exhausted local pgx pool, but it still depends on the external pooler
and PostgreSQL being reachable. A failed snapshot returns HTTP 503 with a bounded
diagnostic error. Database permissions determine visibility into other sessions.

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
