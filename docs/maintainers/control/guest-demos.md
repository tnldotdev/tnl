# guest ready-time authority

guest demos have 20 cumulative minutes of ready authority, including idle time,
one active demo, and a 72-hour credential. control starts each interval at readiness
and persists `ready_deadline` from the remaining budget and credential expiry.
heartbeat cannot move that deadline.

[`guest_serving_deadline`](../../../internal/control/state/migrations/00001_baseline.sql)
also bounds preparation, publisher leases, signed visitor permissions, both policy
leases, and stream-capacity allocations. before readiness, remaining time bounds
each observation; it does not start a ready interval. publishers renew a short
preparation lease before its expiry rather than waiting the ordinary 15 seconds.
application arrival uses prepared local authority, not a control call.

`serving_until` retains the latest issued ready horizon. closing a run settles
through that horizon once, even if it is offline or idle. replacement waits for
that tail to expire: closing a control record cannot fence an offline process.
late cleanup charges no time after the last issued horizon. normal stops can
therefore charge a short unused tail rather than refund authority still usable
by the previous owner. a failed closure transaction settles nothing.

ingress and publisher policy guards close existing connections locally at their
confirmed bounds when control is unavailable. connection and byte-rate limits
remain server-owned; there is no cumulative byte allowance or hosted usage report.

the fresh PostgreSQL baseline is `tnl-control-fresh-v1-practical-cutover`.
migration repeat, open, and readiness require its exact version and identity.
retained ingress-run fences and guest deadlines belong to that baseline; this is
not a deployed-state migration procedure.
