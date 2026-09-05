# Observability

`tnld` exposes Prometheus metrics on the private address configured by
`TNLD_METRICS_LISTEN`. The default is `127.0.0.1:9090`; an empty value disables
the listener.

The registry includes the standard Go and process collectors. Monitor
file-descriptor pressure with `process_open_fds` and `process_max_fds`; tnl does
not duplicate those metrics under its own prefix.

## Service Health

Probe the public control hostname over HTTPS:

```console
curl --fail https://control.tnl.example.com/v1/health
curl --fail https://control.tnl.example.com/v1/ready
```

`/v1/health` reports whether the control API is serving. `/v1/ready` includes
PostgreSQL schema readiness, public control certificate availability, service CA
availability, and required background dependencies. `tnl_info{mode}` identifies
the role of each `tnld` process.

Ingress readiness requires an unexpired service certificate and ingress lease,
a current ingress routing table, and a live public listener. Relay readiness
requires an unexpired service certificate and relay lease, current relay
transport material, and live publisher and internal-forwarding listeners.

## Runtime Metrics

- `tnl_control_requests_total{operation,outcome}` and
  `tnl_control_request_duration_seconds{operation}` measure control API traffic.
- `tnl_routes{state}` reports durable routes by lifecycle state.
- `tnl_ingress_leases{state}` and `tnl_relay_leases{state}` report control-owned
  process leases.
- `tnl_publisher_connections{state}` reports publisher connections by durable
  lifecycle state.
- `tnl_streams_active{role}` reports active visitor streams in ingress and relay
  processes.
- `tnl_capacity_rejections_total{resource}` reports operations rejected by a
  bounded resource.
- `tnl_service_enrollments_total{role,outcome}` reports enrollment and renewal
  outcomes without token or process identifiers.
- `tnl_service_certificate_expiry_seconds{role}` reports the remaining lifetime
  of the active service certificate.
- `tnl_source_limiter_rejections_total` and `tnl_source_limiter_entries` report
  abusive connection starts and pressure on the bounded source table.
- `tnl_ip_allowlist_denials_total` reports visitor connections rejected by route
  IP policy without route or source labels.
- `tnl_forwarded_bytes_total{direction}` reports bytes forwarded through the
  visitor path.

Labels use fixed enumerated values. Route IDs, hostnames, team IDs, membership
IDs, ingress IDs, relay IDs, enrollment-token IDs, request IDs, error text, and
SQL text are deliberately excluded from metric labels. Correlation details
belong in structured logs; client responses remain sanitized.

## Alert Queries

File-descriptor utilization is a primary ingress and relay capacity signal:

```promql
process_open_fds / clamp_min(process_max_fds, 1)
```

Warn above `0.80` for 15 minutes and treat above `0.90` for 5 minutes as
critical. Other useful alert conditions include:

```promql
increase(tnl_capacity_rejections_total[5m]) > 0
increase(tnl_service_enrollments_total{outcome="error"}[10m]) > 0
tnl_service_certificate_expiry_seconds < 600
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
