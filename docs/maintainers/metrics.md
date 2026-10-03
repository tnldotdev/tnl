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

| Metric                                                                | What it shows                                                         |
| --------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `tnl_control_api_request_duration_seconds{surface,operation,outcome}` | Completed API requests.                                               |
| `tnl_control_api_requests_in_flight{surface}`                         | Requests still running.                                               |
| `tnl_control_placement_decisions_total{action,outcome}`               | Publish run placement results.                                        |
| `tnl_control_certificate_work_duration_seconds{kind,stage,outcome}`   | Certificate worker attempts.                                          |
| `tnl_control_dns_work_duration_seconds{kind,phase,outcome}`           | DNS work and verification.                                            |
| `tnl_control_public_url_usage_items_total{result}`                    | Finalized, delivered, or retried items.                               |
| `tnl_control_cleanup_last_success_timestamp_seconds{kind}`            | Last successful cleanup.                                              |
| `tnl_control_guest_trials_last_24h{stage}`                            | Issued, allocated, ready, or ended guest trials from committed state. |
| `tnl_control_public_url_recovery_duration_seconds`                    | Newly observed recovery durations.                                    |

The API `surface` distinguishes control, built-in authority, and private
ingress and relay requests. A histogram's `_count` is its completed attempt
count. Certificate availability is not publisher installation. Usage results
count different kinds of items; do not sum them as one backlog.
Guest stages are `issued`, `allocated`, `ready`, `expired`, `ready_limit`,
and `transfer_limit`. They count trials, not publish runs or pings. Each control
reports the same database-wide 24-hour snapshot; use the maximum across control
replicas rather than summing them. Guest cleanup removes IP digests after one
hour for issuance and after trial expiry plus public URL deletion for access.

## database

| Metric                                                   | What it shows                              |
| -------------------------------------------------------- | ------------------------------------------ |
| `tnl_database_pool_*`                                    | Pool size, utilization, and waits.         |
| `tnl_database_pool_acquire_duration_seconds{outcome}`    | Time to acquire a connection.              |
| `tnl_database_query_duration_seconds{operation,outcome}` | SQL time after acquisition.                |
| `tnl_database_failures_total{phase,outcome}`             | Connection, transaction, and SQL failures. |

Scraping never queries PostgreSQL or a remote service. Metric labels use
fixed operations and outcomes, never hostnames, IDs, credentials, or raw URLs.
Definitions and role registration live in `internal/observability`; record
events at their ingress, relay, control, or worker boundary.
