# Capacity Testing Working Log

This is a **temporary working log**, not production sizing guidance. At the end
of the capacity-testing campaign, **delete this file** and replace it with
`docs/benchmarks/capacity.md`: a fully written account of the findings, measured
operating envelope, recommended production resources, failure headroom, and
remaining uncertainty. Preserve useful evidence links in that final document.

## Scope And Measurement Rules

- Measure ready-route scaling, fresh-connection throughput, bandwidth, held
  streams, failure capacity, and endurance using the shared workload and local
  separated topology. Cold-activation optimization has a separate owner.
- Keep the 64-route, 160-request/sec, 32KiB reference reproducible. Record setup
  separately and declare admission/resource overrides before each experiment.
- Preserve the five-second visitor budget, offered traffic, failed artifacts,
  route/assignment correctness, no-replay boundary, and final usage reconciliation.
- Record generator limits separately from server limits. Recommendations require
  repeated measurements and capacity during failure, not extrapolation from a
  successful smoke run.
- Local validation is authorized; Fly execution requires separate approval.

## 2026-09-21 — Admission-Limit Setup

Starting baseline revision: `e8ab242`. The admission-limit validation ran after
the independent TypeScript tooling migration at `d6a278e`, with admission-limit
and cold-activation instrumentation in the tested tree. Production source-limit
configuration landed in `d16df04`; the independent runtime admission profile and
fixture plumbing landed in `07a2d26`. The remaining Task/Compose and coordinator
plumbing overlaps cold-activation files and must land separately without mixing
the two concerns.

Setup:

- Exposed production source-connection rate/burst configuration (defaults 50/sec
  and 200), scoped to each ingress process and source IPv4 address or IPv6 /64.
- Pass explicit source, visitor, per-route, publisher, relay-stream, and QUIC
  admission limits through Task/Compose into the existing production settings.
- Save requested and component-applied limits with benchmark artifacts.
- Validated configuration parsing, enforcement, and a small overridden runtime
  profile before starting capacity ramps.

Validation evidence:

- Production configuration/rate enforcement: focused race tests and vet passed
  for `internal/tnldconfig`, `internal/config`, `internal/ingress`,
  `internal/sourcelimiter`, and `cmd/tnld`.
- Default race-enabled runtime smoke: 160/160 steady, 640/640 relay-restart,
  and 160/160 shutdown requests succeeded. No failures, timeouts, missed offers,
  queue expiry, source-limit rejections, or final accounting mismatches.
- Override runtime: source rate 400/sec, burst 80, visitor limit 12,000,
  route limit 750, publisher limit 64, relay stream capacity 512, and QUIC stream
  limit 128. Ingress and both relays reported exact requested values.
- The override offered 240 fresh connections/sec across four sources for
  30/40/30-second windows: 7,200/9,600/7,200 successful requests, with no
  failures, timeouts, missed offers, queue expiry, or source-limit rejections.
  This exceeds the old sustained 50/sec/source limit for long enough that its
  200-token burst would have been exhausted.
- Both runs ended with exact usage reconciliation and zero active sessions,
  publisher connections, or reservations. All owned containers exited zero and
  the isolated Compose project left no containers, networks, or volumes.

Retained local evidence:

- `bench-results/capacity-admission-default.log`
- `bench-results/capacity-admission-default/`
- `bench-results/capacity-admission-override.log`
- `bench-results/capacity-admission-override/`

These runs validate configuration and harness propagation, not maximum capacity.
No new production-sizing conclusion has been established yet.
