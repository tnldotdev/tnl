# Route-Path Benchmark

`tnlbench` models and measures the complete route path: public ingress, one
internal forwarding hop, a ready publisher connection on a relay, the publisher,
and the local service. It supports these deployment topologies:

- `standalone`: one `tnld` process composing control, ingress, and two logical
  relay services.
- `split`: a control service, an ingress service, and at least two independently
  addressable relay services.

The capacity model accounts for two publisher connections per route. A cell with
`N` relay processes and a target of `R` publisher connections per relay process
therefore contains `N * R / 2` routes, subject to placement across two distinct
relay services.

## Plan

Planning is read-only. It does not call Fly, DNS, PostgreSQL, ACME, or
certificate services.

```console
BENCH_SUITE=smoke mise exec -- task go:bench-fly:plan
BENCH_SUITE=scale BENCH_CONNECTIONS_PER_RELAY=600 \
  mise exec -- task go:bench-fly:plan
BENCH_SUITE=smoke BENCH_PLAN_FORMAT=json \
  mise exec -- task go:bench-fly:plan
```

The suite and workload profile contracts use schema version 2. The current
profile plans `auto` transport selection and labels its workload assumptions as
assumed rather than observed.

## Execute

There is currently no Fly execution command. The previous launcher targeted a
removed deployment architecture and was deleted rather than retaining an
inoperable compatibility path.

A replacement runner must not be added until the PostgreSQL-backed control API
can complete route and route-session lifecycles. It must provision and clean up:

- PostgreSQL migration and pooled serving credentials.
- A control service, an ingress service, and at least two relay services.
- Automatic public control TLS and service enrollment.
- One ingress enrollment token and one token per relay service.
- Service-CA relay transport identities and publisher trust bundles.
- Explicit `TNLD_LOGIN_TOKEN` bootstrap configuration.
- Public TCP ingress plus TCP and UDP for each relay service.

Running a replacement on Fly will require explicit approval, `BENCH_SUITE`, and
`BENCH_APPROVED=1`. A plan is not execution approval.

## Driver Results

The driver emits result schema version 3, with one JSON object per driver shard.
It records route activation, request correctness, cleanup, aggregate usable
publisher connections, and ingress and relay resource samples. `auto` transport
results must not be reported as QUIC-only unless the run records observed
transport selection.

Merge a completed run with:

```console
BENCH_RUN=bench-results/<run-id> mise exec -- task go:bench-fly:report
```

The report command validates shard identities, merges fixed histogram buckets,
and writes `report.json` and `report.md`. It never averages shard percentiles.

No pre-cutover capacity result qualifies the current control/ingress/relay runtime.
New capacity or scale-in guidance requires approved runs against this
architecture. Existing streams may reset during relay loss; the relevant
recovery measure is whether new visitor connections resume through the other
ready publisher connection.
