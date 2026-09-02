# Fly Benchmark Progress

This is a temporary implementation handoff for the Fly benchmark effort. Keep
it current at commit boundaries and delete it only after the implementation,
approved Fly runs, reports, and resulting capacity and scale-in decisions are
complete.

## Objective

Answer three questions with repeatable evidence:

1. What route density is safe for `performance-1x` workers?
2. Does a pool of up to ten small workers scale predictably behind one fixed
   `performance-2x` edge?
3. Can graceful worker drain and publisher session reacquisition support
   conservative automatic scale-in?

Establish the current runtime baseline before changing worker reconnect or
data-plane architecture.

## Decisions

- Use one fixed `performance-2x` edge and `performance-1x` workers.
- Hosted policy has a two-worker minimum and ten-worker maximum. One-worker
  smoke and density qualification cells are allowed.
- Force DERP for baseline capacity, scaling, and drain qualification.
- Use current graceful drain and publisher reacquisition for the first
  scale-in tests.
- Do not add primary/standby placement, cross-worker reassignment, stream byte
  replay, or edge promotion in this effort.
- Existing streams may reset during worker loss. Recovery applies to new
  connections after publisher reacquisition.
- Label workload inputs as assumed until privacy-preserving aggregate observed
  data replaces them.
- Do not select customer pricing from benchmark results.
- Do not create Fly or DNS resources without explicit user approval.
- Commit and push small, tested changes as work progresses.
- Do not use subagents for this effort.

## Simplified Milestones

1. Benchmark foundation: fix cleanup ownership, add profiles, add read-only
   planning, then introduce result schema v2 and reporting.
2. Capacity baseline: run smoke, density, and scale suites.
3. Scale-in qualification: add dynamic/action barriers and run manual drain
   suites under traffic.
4. Autoscaler qualification: validate a one-worker-at-a-time 4 to 3 to 2 policy
   with a two-worker floor.

Transport comparison, efficiency, long soak, observed-data import, future
data-plane separation, and the benchmark skill remain deferred until these
milestones work.

## Completed And Pushed

### `6391707 fix: let benchmark publishers own route cleanup`

- `publisher.Run` is now the normal route deletion owner.
- `tnlbench` cancels publishers, waits for them, verifies captured routes are
  absent, and removes hostnames afterward.
- Explicit route deletion runs only when verification finds a remaining route.
- Fallback deletion is logged and leaves the cell failed for investigation.
- Added normal-owner and fallback tests.
- Verified with `go test ./cmd/tnlbench` and
  `go test -race ./cmd/tnlbench`.

### `8b76625 feat: add profile-driven benchmark planning`

- Added `benchmarks/workloads/agent-worktrees-assumed-v1.json` with the agreed
  deterministic assumed workload and phase durations.
- Added `benchmarks/suites/p1-horizontal.json` with `smoke`, `density`, and
  target-dependent `scale` matrices.
- Added `benchmarks/pricing/fly-sjc.json` using the 2026-09-02 official Fly SJC
  rates for default-memory `performance-1x` and `performance-2x` Machines.
- Added `tnlbench plan` and made the old runtime command explicit as
  `tnlbench driver`.
- Added strict JSON decoding, cross-profile validation, environment overrides,
  deterministic matrix expansion, expected row counts, duration estimates,
  and compute/public-egress spend estimates.
- Added `go:bench-fly:plan`.
- Updated the legacy shell to invoke `tnlbench driver`.
- Smoke plan currently expands to one edge, one worker, 25 routes, one driver,
  66 seconds expected, 153 seconds maximum, about $0.0051 expected, and about
  $0.0113 maximum modeled spend.
- `scale` intentionally fails planning until
  `BENCH_ROUTES_PER_WORKER` supplies a qualified density.

### `71a2d9c feat: add mergeable benchmark results`

- Added result schema v2 with cell, repetition, shard, configuration, phase,
  resource, cleanup, and failure fields.
- Added fixed cumulative duration histograms that merge counts before report
  percentiles are calculated.
- The driver now emits a schema-v2 row on success or ordinary failure.
- Added `tnlbench report` and `go:bench-fly:report`; they read
  `results.jsonl`, validate shard identities, merge phase histograms, and write
  `report.json` plus `report.md`.
- Updated legacy result extraction to select schema version 2.

### `642db7f feat: run planned Fly benchmark cells`

- Reworked `scripts/bench-fly.sh` to require `BENCH_APPROVED=1`, consume the
  machine-readable plan, and run the expanded `smoke`, `density`, or `scale`
  cells with the planned edge, worker, driver, route, repetition, and timeout
  values.
- Added a per-run directory with `manifest.json`, `results.jsonl`, generated
  reports, and failure diagnostics.
- The runner checks the final row count against the plan.
- A failed cell is retained and stops the suite without retry. Per user
  direction, actual benchmark failures will be reported without runtime fixes
  or reruns intended to obtain a preferred result.

### `8baf406 feat: use persistent public benchmark ingress`

- Restored the benchmark files after an accidental local deletion; the user
  confirmed those deletions were not intentional.
- Created persistent Fly app `tnl-bench` and allocated dedicated IPv4
  `149.248.193.175` with explicit user approval. The address costs about
  $2/month. No Machines are currently running.
- Vercel DNS now delegates `tnl.wtf`, and `*.bench.tnl.wtf` resolves publicly
  to `149.248.193.175` through Cloudflare and Google resolvers.
- The runner now retains the app/IP, uses a unique control hostname per cell,
  relies on production Let's Encrypt plus system roots for control TLS, and
  removes the DNS hook and private control-CA inputs.
- Added optional driver certificate/key inputs so all generated routes can use
  one real `*.bench.tnl.wtf` wildcard certificate.
- Added system CA certificates to the benchmark image.

## Current Operational State

- Let's Encrypt issued the ignored local `*.bench.tnl.wtf` wildcard certificate
  for 2026-09-02 through 2026-12-01. Its chain, hostname, expiration window,
  private key, and key pairing were validated locally.
- The temporary `_acme-challenge.bench.tnl.wtf` TXT record was removed after
  issuance and is absent from Vercel's authoritative nameserver.
- The persistent app currently has no Machines.

## Benchmark Outcomes

### Smoke `09022129-2aa6`

- Explicitly approved run from clean git SHA
  `ee0fbc81d472b675797be8b6032642a036cb4f9c` in SJC.
- The image built and pushed. The first edge launch request received a transient
  registry manifest 404; the runner's existing Machine-launch retry then
  started edge Machine `7812320cd3d668`.
- The edge emitted repeated `acme/autocert: missing certificate` TLS handshake
  errors during readiness checks.
- Login-token retrieval then failed because `/usr/local/bin/tnl` was absent
  from the benchmark image.
- No worker or driver Machine was created, `results.jsonl` contains zero rows,
  and `tnlbench report` correctly refused to report an empty result set. This
  run produced no capacity or latency evidence.
- The run is preserved under `bench-results/09022129-2aa6/`. The edge Machine
  was destroyed; the persistent app and dedicated IPv4 remain.
- Per user direction, the failed smoke was not retried and no runtime or policy
  changes were made in response.

## Important Limitations

- The read-only plan command is safe and does not call Fly, DNS, ACME, or
  certificate services.
- The profile-driven Fly runner currently covers capacity smoke, density, and
  horizontal scale cells. It does not yet coordinate worker drain or run an
  autoscaler.
- Driver schema v2 currently records activation, one all-route correctness
  wave, and cleanup. Representative sustained traffic, persistent streams,
  burst, and churn still need driver implementation before drain qualification.

## Next Steps

1. Do not run another benchmark until the failed smoke outcome is reviewed and
   a separate future run is explicitly approved.
2. Run density scouting, rerun the candidate knee and adjacent point three
   times, then record an approximately 80% scheduling target.
3. Run the 1/2/4/8/10-worker scale matrix at that target.
4. Add manual drain coordination and qualify 3 to 2 and 4 to 3.
5. Qualify the pinned hosted autoscaler policy through 4 to 3 to 2 before
   changing the authoritative `tnl.dev` policy.

## Commands Verified So Far

```sh
go test ./cmd/tnlbench
go test -race ./cmd/tnlbench
mise exec -- task go:test
mise exec -- task go:format-check
go vet ./cmd/tnlbench
bash -n scripts/bench-fly.sh
BENCH_SUITE=smoke mise exec -- task go:bench-fly:plan
BENCH_SUITE=smoke BENCH_PLAN_FORMAT=json mise exec -- task go:bench-fly:plan
```

## Key Files

- `cmd/tnlbench/main.go`: current driver and cleanup lifecycle.
- `cmd/tnlbench/plan.go`: profile decoding, validation, expansion, and pricing.
- `cmd/tnlbench/barrier.go`: hardcoded barriers that still need generalizing.
- `scripts/bench-fly.sh`: plan-driven persistent-app Fly runner for smoke,
  density, and horizontal-scale cells.
- `Taskfile.yml`: benchmark task entry points.
- `docs/benchmarks/README.md`: historical benchmark results and outdated
  scaling guidance; rewrite after new evidence exists.
- `internal/publisher/publisher.go`: publisher deletion, heartbeat, drain, and
  session reacquisition behavior.
- `internal/routes/coordinator.go`: process-local worker placement and drain.
- `internal/workercontrol/edge.go`: edge-side worker session behavior.
- `internal/workercontrol/worker.go`: worker drain notification.
- `cmd/tnld/main.go`: worker reconnect loop and engine lifetime.
- `../tnl.dev/deploy/server/autoscaler.yml`: authoritative hosted autoscaler
  policy, intentionally unchanged during manual baseline qualification.

## Safety And Interpretation

- A passing smoke run validates the harness, not capacity.
- Hard capacity is the highest repeatably passing density before a resource or
  performance knee. Ambiguous knees must stay ambiguous in the report.
- The scheduling target is an explicit selected input, expected to be about
  80% of qualified hard capacity.
- Scale-in route count uses destination workers times scheduling target.
- Never merge shard p95 values; merge fixed histogram buckets first.
- Never label `auto` transport as direct.
- Preserve failed rows and cleanup diagnostics. Do not discard runs to produce
  a preferred outcome.
