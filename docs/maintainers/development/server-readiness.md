# server readiness

use the private process listener's `/health` for liveness and `/ready` for traffic
readiness. `/health` is local and remains successful during dependency outages or
drain. `/ready` checks the role's existing lease, routing, listener, certificate,
database, and configured Route 53 credential boundaries as applicable. exporter
availability never affects either check.

`GET /debug/roles` returns a no-store JSON observation with `snapshot_at`,
`started_at`, the configured `role`, an ephemeral `process_run_id`, aggregate
`ready`, `draining`, and safe role projections. the aggregate readiness check has
a two-second deadline. per-role fields describe local listeners and controller
state; control's local listener readiness is separate from aggregate database and
provider readiness. ingress and relay projections include their configured identity,
distinct process run, last successful renewal, confirmed lease deadline/revision,
drain deadline, routing revision/check time where applicable, and local registered
publisher connection/visitor stream counts. registered connections are not a count
of ready database claims. the endpoint projects explicit fields rather than raw
coordination responses.

SIGTERM begins the existing bounded drain and immediately clears process readiness.
component contexts keep their process-owned observability context through drain;
shutdown joins them before shutting down exporters. ingress stops new visitor
admission and relay drains existing publisher connections through the existing
role boundaries. control readiness is false throughout shutdown and its public
API rejects new public URL runs, managed run preparation/start, and signed runtime
start with HTTP 503 and `Retry-After`. existing renewals and cleanup retain their
ordinary authentication/state boundaries while admitted work drains.

relay can remain live and unready during control loss, and renews through its
existing retry loop. after ingress's confirmed lease expires, its controller ends
that process run. its audit identity cannot be reused. automatic in-process replacement after ingress
lease loss is not implemented here; a supervisor still needs bounded restart
backoff for that case. the separated lifecycle tests qualify forwarding, drain,
and lease fail-closed behavior; they do not qualify a Kubernetes operator.

## publisher observations

the existing authenticated project status includes each publisher group's
`current_revision`, member `observed_revision`, `acknowledged_at`, `snapshot_at`,
confirmed lease expiry, and signed runtime status. an acknowledgement stops being
healthy when the applied revision changes, its group lease expires, or a new
signed runtime epoch starts. runtime start clears the previous health and
acknowledgement in the same transaction, under the team lock shared with
acknowledgement. equal or reversed request timestamps cannot carry health into a
replacement. recovering a lost start reply for the same epoch preserves health.
runtime activity is evaluated from current state at the same snapshot time;
failed observation calls do not extend its last-seen time or lease. acknowledgement
health is publisher-reported configuration health, not an application probe or
proof that every service connection is ready.

the timestamp is part of the fresh PostgreSQL baseline and the control OpenAPI
source. callers must use a current snapshot and revision rather than retaining a
healthy result indefinitely. runtime status retains its existing provenance:
control-observed receipt/source facts and explicitly publisher-reported deployment
metadata. configured/running AWS or Kubernetes facts remain infrastructure-owned
and require that provider's IAM outside control. there is no desired-version
database or cloud controller in this change.
