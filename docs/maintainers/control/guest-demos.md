# guest ready-time authority

Guest demos have 20 cumulative minutes of ready authority, including idle time,
one active demo, and a 72-hour credential. Control starts charging at readiness
and persists `ready_deadline` from the remaining budget and credential expiry.
Heartbeat cannot move that deadline. Guest traffic has no cumulative byte cap.

[`guest_serving_deadline`](../../../internal/control/state/migrations/00001_baseline.sql)
bounds publisher leases, preparation, policy, and signed visitor permissions.
Before readiness, the remaining allowance bounds each observation without starting
a ready interval. Ingress acknowledges installed preparation over the private
control API, but refuses guest visitor lookup, source signing, and connection
binding until control publishes the ready projection. Signed visitor permissions
also require guest readiness. Public HTTP readiness probes happen after that
transition, so preparation needs no visitor traffic or outstanding serving tail.
Guest policy carries `connection_deadline`; ingress and publisher
bind even idle connections to the locally confirmed policy lifetime. Their existing
connection owners release capacity when those connections close.

`serving_until` retains the latest issued ready horizon. Closing settles that
horizon once in the closure transaction. Replacement waits for its tail to expire:
closing a control record cannot fence an offline process. A normal stop can charge
a short unused tail; late cleanup cannot charge past the last issued horizon.
A failed closure transaction settles nothing.

The fresh PostgreSQL baseline is `tnl-control-fresh-v1-guest-ready-without-usage-accounting`.
Migration repeat, serving startup, and readiness require its exact version and
identity. This requires a fresh database and coordinated server stop/start.
