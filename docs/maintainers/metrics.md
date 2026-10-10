# metrics

Each `tnld` process serves `/metrics` on its private observability listener
(`127.0.0.1:9090` by default). Split roles expose their own metrics; standalone
exposes control, ingress, and both logical relays together. Application metrics
start with `tnl_`. Prometheus also exports `go_*` and `process_*` metrics.

## process and capacity

| Metric                                     | What it shows                         |
| ------------------------------------------ | ------------------------------------- |
| `tnl_process_info{role}`                   | The process's configured role.        |
| `tnl_admission_limit{resource}`            | Effective admission limits.           |
| `tnl_admission_rejections_total{resource}` | Work rejected because a limit is hit. |

Some limits apply **per public URL or hostname**; do not compare those with
process-wide occupancy. Standalone sums the limits of its two logical relays.

## ingress and relay

| Metric                                                        | What it shows                             |
| ------------------------------------------------------------- | ----------------------------------------- |
| `tnl_ingress_connections{class}`                              | Occupied ingress admission slots.         |
| `tnl_ingress_visitor_connections_total{outcome}`              | Ordinary visitor outcomes.                |
| `tnl_ingress_visitor_stream_open_duration_seconds{outcome}`   | Time to a forwarding decision.            |
| `tnl_ingress_relay_attempts_total{connection_slot,outcome}`   | Internal-forwarding attempts.             |
| `tnl_ingress_routing_last_successful_check_timestamp_seconds` | Most recent successful routing check.     |
| `tnl_ingress_lease_expiration_timestamp_seconds`              | Ingress lease expiry.                     |
| `tnl_relay_publisher_connections_registered`                  | Locally registered publisher connections. |
| `tnl_relay_publisher_connections_ready`                       | Ready publisher connections.              |
| `tnl_relay_visitor_stream_slots_occupied`                     | Occupied relay stream slots.              |
| `tnl_relay_visitor_stream_rejections_total{reason}`           | Non-capacity stream rejections.           |
| `tnl_relay_earliest_lease_expiration_timestamp_seconds`       | Earliest local relay lease expiry.        |

Visitor outcomes are recorded when connections end. `forwarded` means ingress
established forwarding, not that visitor TLS or the local service succeeded.
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
| `tnl_control_tcp_port_pool_ports{pool,state}`                          | Available, claimed, quarantined, and configured TCP ports per pool.   |
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

## database

| Metric                                                   | What it shows                              |
| -------------------------------------------------------- | ------------------------------------------ |
| `tnl_database_pool_*`                                    | Pool size, utilization, and waits.         |
| `tnl_database_pool_acquire_duration_seconds{outcome}`    | Time to acquire a connection.              |
| `tnl_database_query_duration_seconds{operation,outcome}` | SQL time after acquisition.                |
| `tnl_database_failures_total{phase,outcome}`             | Connection, transaction, and SQL failures. |

Scraping never queries PostgreSQL or a remote service. Metric labels use
fixed operations and outcomes, plus a bounded operator-owned ingress pool ID;
never public URL IDs, hostnames, credentials, or raw URLs. The pool gauge is a
database-wide snapshot on each control process, so use the maximum across
replicas rather than summing it.
Definitions and role registration live in `internal/observability`; record
events at their ingress, relay, control, or worker boundary.
