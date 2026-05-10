# Observability

`tnld` exposes Prometheus metrics on the private address configured by
`TNLD_METRICS_LISTEN`. The default is `127.0.0.1:9090`; an empty value disables
the listener.

The registry includes the standard Go and process collectors. In particular,
monitor file-descriptor pressure with `process_open_fds` and
`process_max_fds`; tnl does not duplicate those metrics under its own prefix.

## Service Health

Probe the public control hostname over HTTPS:

```console
curl --fail https://tnl.example.com/v1/health
curl --fail https://tnl.example.com/v1/ready
```

`/v1/health` checks control TLS and HTTP serving. `/v1/ready` additionally runs
a bounded SQLite check. DNS remains in `/v1/capabilities`; only a test route
checks DNS, ACME, relay, worker, and publisher behavior end to end.

The main availability signals are:

- `tnl_api_requests_total{operation,result}` and
  `tnl_api_request_duration_seconds{operation}` for control-plane availability.
- `tnl_sqlite_operation_duration_seconds{operation}` and
  `tnl_sqlite_errors_total{operation,reason}` for state contention and failure.
- `tnl_sqlite_pool_connections{state}`, `tnl_sqlite_pool_waits_total`, and
  `tnl_sqlite_pool_wait_seconds_total` for database-pool pressure.
- `tnl_worker_sessions_active{role}` and
  `tnl_worker_session_disconnects_total{role,reason}` for edge/worker health.
- `tnl_worker_routes_active`, `tnl_worker_route_capacity`, and
  `tnl_capacity_rejections_total{resource="worker_routes"}` for route capacity.
- `tnl_tailcat_failures_total{operation,reason}` for Tailcat setup failures,
  including `process_file_limit` and `system_file_limit`.
- `tnl_route_session_heartbeats_total{result}`,
  `tnl_route_session_min_seconds_remaining{status}`, and
  `tnl_route_removals_total{reason}` for route-session continuity.
- `tnl_route_coordinator_stage_duration_seconds{stage}` for distinguishing
  per-route lock waits, worker attachment, publishing, and state updates.

Labels use bounded values. Route IDs, hostnames, identities, workers, request
IDs, errors, and SQL text are deliberately excluded from metric labels.
Unexpected API and Tailcat errors are instead written to logs with request or
route correlation fields and sanitized responses remain unchanged.

## Alert Queries

File-descriptor utilization is the primary capacity signal:

```promql
process_open_fds / clamp_min(process_max_fds, 1)
```

Warn above `0.80` for 15 minutes and treat above `0.90` for 5 minutes as
critical. The forced-DERP capacity benchmark observed approximately four open
FDs per active route, but this is an estimate; the utilization ratio is
authoritative.

Other useful alert conditions are:

```promql
increase(tnl_tailcat_failures_total{reason=~"process_file_limit|system_file_limit"}[5m]) > 0
increase(tnl_sqlite_errors_total{reason=~"busy|locked"}[10m]) > 0
tnl_worker_sessions_active{role="edge"} == 0
increase(tnl_worker_session_disconnects_total{reason!="shutdown"}[10m]) > 3
increase(tnl_route_removals_total{reason="session_expired"}[10m]) > 0
tnl_route_session_min_seconds_remaining{status="active"} < 15
increase(tnl_capacity_rejections_total{resource="worker_routes"}[5m]) > 0
```

Gate the session-margin query on `tnl_routes{status="active"} > 0`, because the
minimum is zero when no active routes exist. API alerts should require both
error volume and ratio to avoid paging on one failed request:

```promql
sum(increase(tnl_api_requests_total{result="server_error"}[10m])) >= 5
and
sum(rate(tnl_api_requests_total{result="server_error"}[5m]))
  / clamp_min(sum(rate(tnl_api_requests_total[5m])), 0.001) > 0.02
```

Deployment repositories should own concrete recording and alert rules. This
repository owns metric names, semantics, and bounded label values.
