# checking keepalive

See the [demo readme](../readme.md) for an introduction.

From the repository root:

```sh
mise exec -- task js:keepalive:test
mise exec -- task js:keepalive:test:browser
```

The routine tests build the page and budget the whole initial script graph
(115 KB minified / 35 KB gzip), plus all optional scripts (160 KB / 58 KB).
The browser check runs that build under the site's CSP in Chrome with fixture
peers and a fixture publisher worker. It checks background check-ins, host
reports, asset verification, volunteering, stopping and failed lazy loads.

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
      "pool_acquire_s_per_s": "sum(rate(tnl_database_pool_acquire_duration_seconds_sum[2m]))"
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

### coordination without external services

```sh
mise exec -- task js:keepalive:coordination \
  HOSTS=500 MINUTES=10 SCENARIO=growth SEED=1 REPORT=/path/to/new-report.json
```

The simulation runs production `Gossip` and `maybeStart` decisions, with JSON
serialization and validation on a virtual network. It does not start browsers,
call control, use Docker, or load ingress and relays.

- `SCENARIO`: `growth`, `loss` (25% abrupt loss), `partition` (two minutes), or
  `turnover` (normal 15-minute turns). Use `MINUTES=30` for repeated turnover.
- `HOSTS`: 3–1000 initial hosts, introduced over one minute.
- `LATENCY_MS`: 1–1000, with deterministic jitter; `LOSS`: 0–0.5 per direction.
- `SEED`: repeatable randomness.
- `DISCOVERY`: `shared` supplies an optimistic fresh shared-address report every
  27–33 seconds, matching the browser's periodic rediscovery cadence but not the
  Worker's cache. `none` tests loss of this discovery path. Turnover results without
  rediscovery must not be reported as the normal system's behavior.
- `DEPARTURE`: `current` uses production departure selection. `insertion` replays
  the earlier first-three-peers selection for a controlled comparison.
- `POLICY`: `visitors` uses production recruitment. `capacity` applies the proposed
  rule only inside the simulation and requires both `READER_BYTES_PER_SECOND`
  (synthetic total offered reader demand) and `SAFE_BYTES_PER_HOST` (fixture budget).
  Synthetic byte observations are proportional to each view's reader estimate,
  not measurements of real browser delivery.

Reports contain settings, source hashes, JSON bytes, exchange failures, joins,
departures, and 15-second distributions of roster and audience views. A recruitment
safety limit retains a partial report and exits unsuccessfully. Failure counts
include dead-peer probes; they are not page-load failures.
JSON totals count serialized attempts and replies, including requests that a
virtual link cannot deliver. They are not measured wire bytes or provider egress.
With `REPORT`, the task also writes `REPORT.checkpoints.ndjson` as each sample is
taken, so a crash does not erase all observations. An `end` record is required to
call a checkpoint stream complete. The simulator releases retired gossip owners
and stops with a failed partial report around 50% of its V8 heap limit, leaving
room for old-space pressure and recording the result.
A `harness_memory_limit` outcome is a generator bound, not server or browser
capacity evidence.
Run `mise exec -- task js:keepalive:coordination:check` to check complete reports
and failed memory-bounded reports in separate low-heap processes.

Reader placement is an explicit fixture: 50 readers per initial host, instantly
redistributed as membership changes. It does not model lease expiration or
audience sampling. The turnover fixture supplies a volunteer at each donor tick
and a fixed 30-second startup, not a measured browser startup or a real HTTP
invitation confirmation. It retains the production 12-second confirmation receipt
before early donor departure, the worker's 0–5 second replacement jitter, and its
fresh-surplus retirement check without requiring a replacement. Natural turn
expiry sends final reports; the loss scenario does not. Test real admissions
separately. Earlier reports without these lifecycle paths are superseded fixture
results, not evidence that the real worker cannot reduce surplus capacity.

### reader and connection load

Check the generator before a live run:

```sh
mise exec -- task js:keepalive:load:check
```

This runs the public load task against compressed loopback assets, checks fresh
and reused connections, and proves corrupt transfers remain failures.

For an already-running, approved ramp fleet:

```sh
mise exec -- task js:keepalive:load:readers \
  SITE=https://ramp.keepthisalive.com ALLOW_RAMP_LOAD=1 \
  MANIFEST=/path/to/pinned-release.json RELEASE=EXPECTED_RELEASE_ID \
  REPORT=/path/to/new-report.ndjson RATES=1,5,10 SECONDS=60
```

The task verifies the pinned HTML then JavaScript within one six-second budget
per scheduled open. It uses HTTP/1.1, not Chrome rendering or HTTP/2. `WORKLOAD=connection`
fetches only the small HTML asset; `CONNECTIONS=reuse` enables keep-alive instead
of the default fresh connections. A direct `TARGET` must be an exact ramp
publisher origin with its expected service `RUN`. `CONCURRENCY` bounds in-flight
opens. `METRICS` enables the infrastructure observer described above.

The schedule does not slow down when requests fail. Late, capacity-limited, and
canceled slots remain in the denominator and are never replayed. Each stage
reports attempted and scheduled work separately. All stages run through ordinary
failures; the task exits unsuccessfully if any stage completes less than 99% of
scheduled opens within the deadline. Interrupted runs are incomplete.

The task records transfer status, TCP/TLS/header timing, encoded response-body
bytes, decoded verified bytes, connection reuse, and generator CPU/memory/event-loop
delay. Encoded body bytes exclude HTTP headers and TCP/TLS framing; they are not
provider billing measurements.

Ramp hostnames have separate application state but still share production tnl
servers. This task caps shared-backend load at 10 arrivals/second and stops if the
independent tunnel probe fails. It does not start or stop publishers: the fleet
owner must block certificate issuance, collect server monitoring through the final
load minute, and verify every endpoint offline at teardown. Deliberate saturation,
higher-rate server capacity tests, and server fault injection require an isolated
backend and its own resource limits.

`recruitment.ts` contains an observation-only capacity rule for comparisons. Its
tests use fixture budgets, not production capacity claims. No serving or
recruitment behavior changes until calibration establishes a safe per-host budget.

## scale qualification

Each host offers one invitation at a time. It aims for at least three hosts,
then roughly one per 50 observed visitor tabs. Peer counts are approximate.
Two browsers on the same network can hand off. If a volunteer disappears, the
invitation expires. The donor checks the replacement at its exact publisher
address before finishing a handoff. The Worker checks the donor's invitation
before requesting a one-use enrollment key. Returning identities can reuse
their existing grant.
On departure, the donor sends its final report to the confirmed successor first,
then peers expected to remain beyond the replacement window. This remains
best-effort work with at most three recipients and a one-second deadline; older
departing peers are only fallback recipients.
Routine gossip prefers fresh, non-suspect peers in three of every four probe
slots. The fourth includes quiet peers so suspended hosts can recover. If no
fresh peer is known, every slot can try quiet peers.

For an existing coordinator-backed deployment, stop new turns on the old
release and let active turns drain (including the one-hour first host) before
applying the Worker migration that retires its old reservations.

Volunteer selection uses finite requests with 5–15 second retry jitter. Peer
responses request connection closure, including HTTP/2 GOAWAY, so random probes
and presence reports do not retain idle relay streams. Tabs report on arrival
and renew about every two minutes. The counting host drops a tab six minutes
after its last check-in; other hosts can see an older count.

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

Allow at least two minutes at each checkpoint when testing the normal check-in
rate. At 100 hosts and 50 tabs per host, that's 5,000 check-ins in two minutes.
Report shorter intervals separately as stress tests.

### match a failure before HTTP

For a Node probe that opens a fresh HTTPS connection, call `newVisitorProbeTag`
from `connection-diagnostics.ts`. Pass its `ALPNProtocols` to `https.request`
and keep `clientHelloId` with the transport timings if the probe fails. The
publisher still negotiates HTTP/1.1. Do not reuse the tag or save raw TLS data.

Search ingress logs for `client_hello_id`. On a match, use
`visitor_connection_id` and `publisher_connection_id` to find the relay
attempt and the browser's `publisher visitor` or `publisher http request`
console line. For example, `last_progress=application_entered` with no
`headers_ms` means that the request reached the handler, but the publisher
did not start response headers. An EOF in a later hop does not locate the
failure on its own.

An ingress failure before it reads the ClientHello cannot be matched this way.
Check `tnl_ingress_early_closes_total` for the reason and
`tnl_diagnostic_samples_total` for logs dropped by the sample budget. In the
ramp Worker, search for `keepalive_proxy_file` and the `CF-Ray` value. The
summary separates host discovery, time to headers, and body reading or
validation. `searchBudgetLeftMs` is the Worker's budget at the start of that
attempt, not the browser's deadline.

For a control watch `503`, search separately for its response `request_id`
in `request_ids`.
