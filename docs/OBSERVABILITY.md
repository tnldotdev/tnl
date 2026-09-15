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

Private readiness checks the role's current state: control checks its listeners,
PostgreSQL/schema, and managed public control certificate; ingress checks its
lease, routing table, certificate readiness, and listener; relay checks its lease,
certificate, and publisher/internal-forwarding listeners. Standalone checks all
composed roles. These checks do not prove that every background operation or
individual route/local service is healthy; publish a test route for an end-to-end
check. `tnl_info{mode}` identifies each process's role.

## Runtime Metrics

- `tnl_control_requests_total{operation,outcome}` and
  `tnl_control_request_duration_seconds{operation}` measure control API traffic.
- `tnl_routes{state}` reports durable routes by lifecycle state.
- `tnl_relay_leases{state}` reports control-owned relay leases in a relay or
  standalone process.
- `tnl_publisher_connections{state}` reports publisher connections by durable
  lifecycle state.
- `tnl_streams_active` reports active visitor streams in the process.
- `tnl_capacity_rejections_total{resource}` reports operations rejected by a
  bounded resource.
- `tnl_source_limiter_rejections_total` and `tnl_source_limiter_entries` report
  abusive connection starts and pressure on the bounded source table.
- `tnl_ip_allowlist_denials_total` reports visitor connections rejected by route
  IP policy without route or source labels.
- `tnl_forwarded_bytes_total{direction}` reports bytes forwarded through the
  visitor path.

Labels use fixed enumerated values. Route IDs, hostnames, team IDs, membership
IDs, ingress IDs, relay IDs, request IDs, error text, and SQL text are
deliberately excluded from metric labels. Correlation details belong in
structured logs; client responses remain sanitized.

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

Deployment repositories should define recording and alert rules appropriate for
their environment. This repository defines metric names, semantics, and allowed
label values.
