# guest ready-time authority

guest demos have 20 cumulative minutes of ready authority, including idle time,
one active demo, and a 72-hour credential. control starts the interval only after
the publication is ready. it persists `ready_deadline` once from the remaining
budget and credential expiry; renewal cannot move that deadline.

publisher leases, ingress projections, and visitor-policy leases are capped at
the deadline. before readiness, a policy lease is conservatively capped by the
remaining budget from the observation time. ingress and publisher policy guards
close existing visitor connections locally when their lease expires, including
when control is unavailable.

`serving_until` records the latest authority issued to the active run. closing
the run settles its interval once through that horizon, capped by the ready
deadline. a restarted demo waits until that authority expires; closing a control
record alone cannot fence an offline process. late recovery charges no time after
the last issued horizon. this can charge the short outstanding lease tail after
a normal stop, rather than refund time that an offline owner might still use.

the trial's connection and byte-rate limits are server-owned. they do not track
cumulative transfer. guest source digests and the public URL's IP policy remain
independent of usage accounting. see [guest state](../../../internal/control/state/guests.go)
and [settlement queries](../../../internal/control/state/queries/guest_trials.sql).
