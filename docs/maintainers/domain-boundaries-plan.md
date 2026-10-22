# domain boundaries plan

make authorization and lifecycle decisions explicit before organizing their owners.
the companion [role organization plan](reorganization-plan.md) covers placement.

## accepted scope

- parse external protocols, stored states, revisions, and selectors into owned
  values; reject contradictory inputs before starting work.
- distinguish submitted identity from verified authority. keep human sessions,
  publisher grants, workload sessions, and service credentials separate.
- bind certificate issuance to the exact public URL or service run and approved
  certificate plan. keep visitor TLS independent from target trust.
- carry current registration, run, assignment, lease, and process identity through
  admission. replacement cannot replay admitted application traffic.
- make state changes failure-atomic. retain transaction and lock order, including
  cancellation and revocation in the same transaction where required.
- keep connection reservation, pending opens, drain, forced close, and joined
  cleanup under one lifetime owner with exactly-once release.
- treat workload expiry as a fixed deadline: shortening is allowed, extension is
  rejected. keep process, session, lease, and stream lifetimes distinct.
- record accepted readiness against the captured registration and run. later
  invalidation cannot undo acceptance or restart its automatic checker budget.
- validate stored projections and bounded aggregation before publishing results;
  remove adapters and duplicate validation after callers use the defining boundary.

use the lowest sufficient behavioral tests. current invariants and their sources
belong in [architecture](architecture.md); work logs and check results belong in PRs.
