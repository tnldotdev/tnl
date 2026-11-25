# checking keepalive

See the [demo readme](../readme.md) for an introduction.

From the repository root:

```sh
mise exec -- task js:keepalive:test
```

`task js:keepalive:handoff` uses Chrome and an empty test deployment to check
browser handoffs, certificate reuse, final-host outage, and restart.

`task js:keepalive:restart` closes Chrome and reopens its saved profile on
the ramp fleet. It checks that the seed and its next volunteer reuse the
certificate. See [operations](../operations.md#load-tests).

### measure a handoff

To check just the instruments, run `mise exec -- task js:keepalive:measurement-check`.
It uses Chrome, compressed fixture files and a loopback server. No publisher or
provider account is needed.

The separate `js:keepalive:handoff` task requires an empty test deployment and
actually starts browser publishers. For an approved run, pass `SITE`, `START`,
and `REPORT=/path/to/new-report.ndjson`. `PEER_PROXY` optionally places the
second browser on a different network. Both site origins must serve the same
instrumented build. Without `REPORT`, events go to stdout.

Each line has a run-local ID, epoch milliseconds and a scenario phase:

- `turn`: times for volunteering, invitation, copy, hash verification and
  publication; the first independent response from the exact publisher URL
  with the expected service run ID, file size and SHA-256. A seed has no
  invitation. Incomplete turns retain available milestones. Count encoded HTTP
  bytes from Chrome network completion events separately from decoded manifest
  bytes; use only `completeWireSample: true` for whole-copy comparisons. This
  is not socket overhead, provider egress or a billing measurement.
- `hosts`: every 20 seconds, probe the harness's current participants. Count
  distinct publisher identities that supplied a verified file for their current
  run during that round. This is neither a gossip estimate nor an enrollment count.
- `visitor`: a separate Chrome context fetches fresh HTML and JavaScript from
  the public proxy and verifies both. `VISITOR_INTERVAL_MS` defaults to 2,000;
  slow samples skip slots instead of catching up in a burst. Deliberate final-host
  outage is recorded separately. The summary includes failures, skipped slots
  and p50/p95/p99 for successful page-plus-script loads. It also summarizes
  invitation-to-verified latency and complete HTTP copy sizes for successful
  volunteer handoffs, excluding seed turns.
- `infrastructure` (optional): `METRICS=/path/to/queries.json` samples a
  Prometheus-compatible instant-query endpoint every 15 seconds. Provide
  one aggregate query per measurement for the **test** deployment. Missing,
  ambiguous or non-finite results are `null`, not zero. Example for an isolated
  metrics store:

  ```json
  {
    "endpoint": "http://127.0.0.1:9090/api/v1/query",
    "queries": {
      "ingress_connections": "sum(tnl_ingress_connections)",
      "relay_a_publishers": "sum(tnl_relay_publisher_connections_ready{job=\"relay-a\"})",
      "relay_b_publishers": "sum(tnl_relay_publisher_connections_ready{job=\"relay-b\"})",
      "relay_streams": "sum(tnl_relay_visitor_stream_slots_occupied)",
      "capacity_rejections_per_s": "sum(rate(tnl_admission_rejections_total[2m]))",
      "forwarded_bytes_per_s": "sum(rate(tnl_ingress_forwarded_bytes_total[2m]))",
      "oldest_routing_snapshot_age_s": "time() - min(tnl_ingress_service_routing_observed_timestamp_seconds)",
      "pool_wait_s_per_s": "sum(rate(tnl_database_pool_acquire_wait_seconds_total[2m]))"
    }
  }
  ```

  Match the job labels to the deployment. Add queries for machine CPU/memory,
  routing-refresh duration, database lock waits and Worker requests when those
  series are available from the deployment's monitoring. Snapshot age and
  pool acquisition time are not substitutes for refresh duration or lock waits.
  For a remote endpoint use HTTPS; supply an optional read-only bearer token
  through `KEEPALIVE_METRICS_TOKEN`. Reports contain query names and numeric
  values, not upstream labels, URLs, tokens, IPs, invitations or raw errors.

## scale qualification

Each host offers one invitation at a time. It aims for at least three hosts,
then roughly one per 50 observed visitor tabs. Peer counts are approximate.
Two browsers on the same network can hand off. If a volunteer disappears, the
invitation expires. The donor checks the replacement at its exact publisher
address before finishing a handoff. The Worker checks the donor's invitation
before requesting a one-use enrollment key. Returning identities can reuse
their existing grant.

For an existing coordinator-backed deployment, stop new turns on the old
release and let active turns drain (including the one-hour first host) before
applying the Worker migration that retires its old reservations.

Volunteer selection uses finite requests with 5–15 second retry jitter. Peer
responses request connection closure, including HTTP/2 GOAWAY, so random probes
and presence reports do not retain idle relay streams. Tabs report on arrival
and renew about every 40 seconds. If a tab closes, its counting host drops
the lease within two minutes; other hosts can see an older count.

At an estimated 20,000 tabs, hosts start counting a stable one-in-four
sample. They count each sampled tab as four and return to counting every
tab when their estimate drops to 10,000. Tabs outside the sample can still
volunteer. They read the latest count at the edge instead of opening a tunnel
for each renewal. If the edge has no fresh estimate, they contact a counting
host. The estimate can be high or low; it also affects how many volunteers
are invited.

If a presence request loses its connection before headers arrive, the tab tries the same
host once more within the original five seconds. Both attempts refresh one
tab lease. Startup allows three minutes; replacement begins four minutes before
the turn ends.

Qualify 3, 10, 30, 100, 300, then 1,000 hosts. At each stage measure open visitor
connections, gossip bytes, startup time, bundle transfer and verification,
browser memory, relay load, and capacity rejections. Run multiple replacement
cycles, a volunteer surge, slow transfers, and loss of either relay service.
Count visitors separately from hosts. Configuration ceilings and simulations
are not proof of real-browser throughput.
