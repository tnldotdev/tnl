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

## Current Uncommitted Work

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

## Important Limitation

The existing `scripts/bench-fly.sh` is still the legacy topology/matrix runner.
It does not consume the new machine-readable plan and ignores `BENCH_SUITE`.
Do not run the documented profile command until the orchestrator is rewritten;
otherwise it would run the legacy default matrix. The read-only plan command is
safe and does not call Fly, DNS, ACME, or certificate services.

## Next Steps

1. Finish verification, commit, and push the profile/planner foundation.
2. Add the result-v2 cell/shard envelope, mergeable histograms, structured
   partial failures, and `tnlbench report`.
3. Make driver phases profile-defined and make the shell consume JSON plan
   cells instead of expanding its own matrix.
4. Rewrite Fly orchestration for one `performance-2x` edge and
   `performance-1x` workers, complete run directories, diagnostics, and exact
   row/cleanup checks.
5. Run the cheap smoke suite, inspect results, and fix benchmark defects.
6. Run density scouting, rerun the candidate knee and adjacent point three
   times, then record an approximately 80% scheduling target.
7. Run the 1/2/4/8/10-worker scale matrix at that target.
8. Add manual drain coordination and qualify 3 to 2 and 4 to 3.
9. Qualify the pinned hosted autoscaler policy through 4 to 3 to 2 before
   changing the authoritative `tnl.dev` policy.

## Commands Verified So Far

```sh
go test ./cmd/tnlbench
go test -race ./cmd/tnlbench
BENCH_SUITE=smoke mise exec -- task go:bench-fly:plan
BENCH_SUITE=smoke BENCH_PLAN_FORMAT=json mise exec -- task go:bench-fly:plan
```

## Key Files

- `cmd/tnlbench/main.go`: current driver and cleanup lifecycle.
- `cmd/tnlbench/plan.go`: profile decoding, validation, expansion, and pricing.
- `cmd/tnlbench/barrier.go`: hardcoded barriers that still need generalizing.
- `scripts/bench-fly.sh`: legacy Fly runner awaiting plan-driven rewrite.
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
