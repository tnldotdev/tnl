# metrics

Each `tnld` process serves `/metrics` on its private observability listener. The
registry is local to that process; standalone exposes control, ingress, and two
logical relays in one registry. Prometheus' `go_*` and `process_*` families are
also present. Application families use `tnl_` and are grouped by the component
that makes the observation. A counter's `_total` suffix and a histogram's
`_count`, `_sum`, and `_bucket` series follow Prometheus conventions.

Metrics use fixed labels only. HTTP operations are matched route patterns, SQL
operations are compiled query names or fixed transaction commands, and worker
states/outcomes are closed sets. No hostnames, public url IDs, identities,
publisher connection IDs, credentials, error messages, raw URLs, or SQL text
are metric labels. Scraping performs no database or network I/O. Histograms
use `DurationBucketsSeconds()` unless their help text describes a separate age
scale. Histograms' `_count` already counts attempts; do not add a duplicate
counter for every duration sample.

## process and admission

| Family                                     | Roles                      | Meaning                                                                                                                                                                                                                                                           |
| ------------------------------------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tnl_process_info{role}`                   | all                        | One for this process's configured role.                                                                                                                                                                                                                           |
| `tnl_admission_limit{resource}`            | ingress, relay, standalone | Resolved limits. In standalone, the relay connection and stream limits are summed over its two logical relays. `public_url_connections`, `denied_public_url_connections`, and `challenge_hostname_connections` are limits **per key**, not process-wide capacity. |
| `tnl_admission_rejections_total{resource}` | ingress, relay, standalone | Rejections because the corresponding resource is full. Draining is excluded.                                                                                                                                                                                      |
| `tnl_ingress_draining_rejections_total`    | ingress, standalone        | Rejections during draining, independently of capacity.                                                                                                                                                                                                            |

Compare an admission limit with its _corresponding_ occupancy gauge, where one
exists. A per-key limit cannot be divided into process-wide occupancy. The
publisher connection limit is not the number of ready connections; control
also accounts for database claims that a relay has not registered locally.

## control

| Family                                                                | Meaning                                                                                                                                                                                                                                                                                                                   |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tnl_control_api_request_duration_seconds{surface,operation,outcome}` | Public control, built-in authority, private ingress, and private relay HTTP requests. `surface` is `control`, `authority`, `private_ingress`, or `private_relay`; `operation` is a matched pattern or `unmatched`. Includes authentication/binding failures and long-poll waits. `_count` is the completed request count. |
| `tnl_control_api_requests_in_flight{surface}`                         | Requests executing now, including long polls.                                                                                                                                                                                                                                                                             |
| `tnl_control_operation_duration_seconds{operation,outcome}`           | Fixed control-state operations, including placement and routing-table reads.                                                                                                                                                                                                                                              |
| `tnl_control_publish_run_readiness_duration_seconds{outcome}`         | Completed readiness checks. `_count` counts decisions including errors.                                                                                                                                                                                                                                                   |
| `tnl_control_publish_run_readiness_age_seconds{outcome}`              | Age at a readiness decision, excluding errors.                                                                                                                                                                                                                                                                            |
| `tnl_control_placement_decisions_total{action,outcome}`               | Committed new publish-run placement, final insufficient-service/capacity results, and committed replenishment outcomes. An unavailable replenishment means at least one required slot could not be placed.                                                                                                                |
| `tnl_control_connection_assignments_replaced_total{reason}`           | Connection assignments replaced in a committed heartbeat, by `failed_ready`, `expired`, or `unavailable`. A pending decision that rolls back is not counted.                                                                                                                                                              |
| `tnl_control_public_url_recovery_duration_seconds`                    | Newly committed recovery observations in this process. Replayed observations do not count. This is not a readout of the cumulative PostgreSQL histogram.                                                                                                                                                                  |
| `tnl_control_tls_certificate_expiration_timestamp_seconds`            | Earliest loaded control certificate expiration; zero until all configured hostnames have loaded material. Present when a local certificate source is configured.                                                                                                                                                          |

The authority API is absent when an external authority is configured. Private
API patterns are determined before cluster authentication so rejected requests
can still be attributed without recording identifiers. A forwarded visitor
does not imply successful visitor TLS, HTTP, or local-service response.

### background work

| Family                                                                | Meaning                                                                                                                                                                                            |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tnl_control_certificate_claims_total{kind,outcome}`                  | Public url or relay transport certificate claim attempts, including empty/error results.                                                                                                           |
| `tnl_control_certificate_work_duration_seconds{kind,stage,outcome}`   | Claimed worker iterations through save. A saved retry is `retry`, not success; `_count` counts iterations.                                                                                         |
| `tnl_control_certificate_transitions_total{kind,state}`               | Committed availability, installation, cleanup, and terminal-failure transitions. Public url installation is counted at publisher acknowledgement, not when certificate material becomes available. |
| `tnl_control_public_url_certificate_milestone_age_seconds{milestone}` | Issuance creation to certificate availability or completed DNS cleanup. `ready` does **not** mean installed at the publisher.                                                                      |
| `tnl_control_dns_work_duration_seconds{kind,phase,outcome}`           | DNS authority, public url, and ACME challenge claim/provider/verification/save/cleanup work. Pending verification and saved retry outcomes are distinguishable from success.                       |
| `tnl_control_dns_transitions_total{kind,state}`                       | Committed authority and public url DNS transitions, including failure.                                                                                                                             |
| `tnl_control_public_url_usage_work_total{phase,outcome}`              | Usage finalization and delivery-store calls, including empty claims and errors.                                                                                                                    |
| `tnl_control_public_url_usage_items_total{result}`                    | Committed incomplete runs, finalized buckets, accepted deliveries, persisted retries, and permanent rejections; each result has its own unit.                                                      |
| `tnl_control_public_url_usage_receiver_duration_seconds{outcome}`     | Outgoing receiver request duration, including HTTP, transport, and invalid-response failures.                                                                                                      |
| `tnl_control_public_url_usage_last_success_timestamp_seconds{phase}`  | Unix time of the last successful finalization call or committed accepted delivery; zero before success.                                                                                            |
| `tnl_control_cleanup_runs_total{kind,outcome}`                        | Expired publish-run, ephemeral public url, routing floor, and routing-prune calls.                                                                                                                 |
| `tnl_control_cleanup_items_total{kind}`                               | Committed expired publish runs or deleted ephemeral public urls. Routing-history scanned/deleted rows are counted separately.                                                                      |
| `tnl_control_cleanup_last_success_timestamp_seconds{kind}`            | Last successful cleanup call; zero before success.                                                                                                                                                 |
| `tnl_control_routing_history_cleanup_rows_total{action}`              | Committed scanned/deleted rows.                                                                                                                                                                    |
| `tnl_control_routing_history_cleanup_skipped_total`                   | Prune attempts skipped by the guard.                                                                                                                                                               |
| `tnl_control_routing_history_retained_after_revision`                 | Highest retention floor observed by **this** control process, not a live database revision.                                                                                                        |

## ingress

| Family                                                      | Meaning                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tnl_ingress_connections{class}`                            | Occupied admission slots for ClientHello inspection, ordinary visitors, denied visitors, challenges, control handoff, and relay TCP handoff. No per-public-url series.                                                                                                                         |
| `tnl_ingress_backend_streams`                               | Tracked backend connections, including setup, challenges, and denied visitor handling. Updated in order under the server lock.                                                                                                                                                                 |
| `tnl_ingress_visitor_connections_total{outcome}`            | One terminal outcome per classified ordinary visitor. `forwarded` means ingress established forwarding, **not** that visitor TLS or the local service succeeded. Inspection failures and challenges have separate metrics. Held streams count on close; occupancy gauges show them while open. |
| `tnl_ingress_visitor_stream_open_duration_seconds{outcome}` | Admission through the forwarding decision; observed as soon as that decision is made, not after copy completion. `_count` excludes connections rejected before an open attempt.                                                                                                                |
| `tnl_ingress_relay_attempts_total{connection_slot,outcome}` | Per-attempt failure or commitment, with only slots `0`, `1`, or `unknown`. Multiple attempts can belong to one visitor.                                                                                                                                                                        |
| `tnl_ingress_forwarded_bytes_total{direction}`              | Aggregate forwarded bytes by direction, recorded at setup and when a stream copy ends. Long-lived active copies can lag until close.                                                                                                                                                           |
| `tnl_ingress_inspection_failures_total{stage}`              | ClientHello inspection failures before hostname classification.                                                                                                                                                                                                                                |
| `tnl_ingress_challenge_rejections_total{reason}`            | Rejected TLS-ALPN challenges.                                                                                                                                                                                                                                                                  |
| `tnl_ingress_operation_duration_seconds{operation,outcome}` | Fixed lease, routing, relay-connection, and usage-report operations.                                                                                                                                                                                                                           |
| `tnl_ingress_lease_expiration_timestamp_seconds`            | Current local ingress lease expiry; zero before registration or after loss.                                                                                                                                                                                                                    |
| `tnl_ingress_routing_*`                                     | Passive routing initialization, catch-up status, observed/applied/acknowledged revisions, last-success timestamps, update failures, and resnapshots. Zero revision difference alone does not establish freshness during a pending request.                                                     |
| `tnl_ingress_usage_retained_buckets`                        | Usage buckets retained in memory (dirty, pending, or still active), not the control database delivery backlog.                                                                                                                                                                                 |
| `tnl_ingress_recovery_observations_pending`                 | Ingress recovery observations still awaiting a successful or stale response.                                                                                                                                                                                                                   |
| `tnl_ingress_recovery_observation_attempts_total{outcome}`  | Success, stale, retry, and canceled reporting attempts.                                                                                                                                                                                                                                        |

## relay

| Family                                                         | Meaning                                                                                                                                     |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `tnl_relay_local_leases{state}`                                | Local active/draining relay leases; not a control-wide lease count.                                                                         |
| `tnl_relay_earliest_lease_expiration_timestamp_seconds`        | Earliest known local relay lease expiry, including both logical relays in standalone; zero before registration/loss.                        |
| `tnl_relay_transport_certificate_expiration_timestamp_seconds` | Earliest relay transport certificate expiry observed in this process; zero before locally observed material.                                |
| `tnl_relay_publisher_connections_registered`                   | Locally registered connections, including those not ready; not authoritative PostgreSQL claims.                                             |
| `tnl_relay_publisher_connections_ready`                        | Publisher connections marked ready.                                                                                                         |
| `tnl_relay_publisher_connection_exits_total{reason}`           | Exits after readiness, expected or unexpected.                                                                                              |
| `tnl_relay_visitor_stream_slots_occupied`                      | Forwarding slots including opens in progress.                                                                                               |
| `tnl_relay_visitor_stream_rejections_total{reason}`            | Non-capacity rejections such as a stale connection assignment or publisher unavailability. Capacity is in `tnl_admission_rejections_total`. |
| `tnl_relay_operation_duration_seconds{operation,outcome}`      | Fixed admission, disconnect, control, drain, and stream-open operations. Open ends at stream acceptance, not visitor disconnect.            |

## database (control and standalone)

`tnl_database_pool_*` reports connection limit, acquired/idle/total
connections, successful/waited/canceled acquisitions, and total wait time.
`tnl_database_pool_acquire_duration_seconds{outcome}` includes time waiting to
acquire a request-pool connection, even when acquisition fails.
`tnl_database_query_duration_seconds{operation,outcome}` times compiled SQL or
fixed transaction commands **after** acquisition. A failed acquisition has no
SQL operation name. `tnl_database_failures_total{phase,outcome}` separates
acquire, begin, query, commit, and rollback failures. The driver-observed
`tnl_database_guard_held_duration_seconds` does not measure exact PostgreSQL
lock tenure. `tnl_database_client_connections` and
`tnl_database_client_connection_events_total` report local client sockets, not
backend pooler slots. `tnl_database_operations_active`,
`tnl_database_operation_oldest_age_seconds`, and
`tnl_database_operations_omitted` describe the bounded local tracer. Every
database family is gathered from memory; no scrape acquires a connection.
