package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

// these projections deliberately omit lease credentials, network hash keys,
// hostnames, addresses, certificate material, and provider configuration.
type roleDiagnostic struct {
	Role                           string     `json:"role"`
	ConfiguredIdentity             string     `json:"configured_identity,omitempty"`
	ProcessRunID                   string     `json:"process_run_id,omitempty"`
	LastSeenAt                     time.Time  `json:"last_seen_at"`
	LeaseExpiresAt                 time.Time  `json:"lease_expires_at"`
	LeaseRevision                  int64      `json:"lease_revision"`
	Ready                          bool       `json:"ready"`
	Draining                       bool       `json:"draining"`
	DrainDeadline                  *time.Time `json:"drain_deadline,omitempty"`
	RoutingRevision                int64      `json:"routing_revision,omitempty"`
	RoutingCheckedAt               *time.Time `json:"routing_checked_at,omitempty"`
	RegisteredPublisherConnections int64      `json:"registered_publisher_connections"`
	VisitorStreams                 int64      `json:"visitor_streams"`
}

type processDiagnostic struct {
	SnapshotAt   time.Time         `json:"snapshot_at"`
	StartedAt    time.Time         `json:"started_at"`
	Role         daemonconfig.Role `json:"role"`
	ProcessRunID string            `json:"process_run_id"`
	Draining     bool              `json:"draining"`
	Ready        bool              `json:"ready"`
	Roles        []roleDiagnostic  `json:"roles"`
}

func (d *daemon) roleDiagnostics(role daemonconfig.Role, now time.Time) processDiagnostic {
	snapshot := processDiagnostic{SnapshotAt: now, StartedAt: d.startedAt, Role: role, ProcessRunID: d.processRunID, Draining: d.draining.Load(), Roles: []roleDiagnostic{}}
	if role.RunsControl() {
		snapshot.Roles = append(snapshot.Roles, roleDiagnostic{Role: "control", ProcessRunID: d.processRunID, LastSeenAt: now, Ready: d.readyControl(role, now) == nil, Draining: snapshot.Draining})
	}
	for _, runtime := range d.ingresses {
		if runtime.controller == nil {
			continue
		}
		lease, routing := runtime.controller.Lease(), runtime.controller.RoutingStatus()
		ready := !snapshot.Draining && runtime.controller.Ready(now) && (runtime.privateOnly || runtime.server != nil && runtime.server.Ready())
		if runtime.serviceCertificate != nil {
			ready = ready && runtime.serviceCertificate.ready(now)
		}
		entry := roleDiagnostic{Role: "ingress", ConfiguredIdentity: runtime.configuredIdentity, ProcessRunID: runtime.processRunID, LastSeenAt: lease.RenewedAt, LeaseExpiresAt: lease.LeaseExpiresAt, LeaseRevision: lease.IngressLeaseRevision, Ready: ready, Draining: snapshot.Draining || lease.Draining, DrainDeadline: lease.DrainDeadline, RoutingRevision: routing.AppliedRevision, RoutingCheckedAt: &routing.LastSuccessfulCheck}
		snapshot.Roles = append(snapshot.Roles, entry)
	}
	for _, runtime := range d.relays {
		if runtime.controller == nil {
			continue
		}
		lease := runtime.controller.Lease()
		entry := roleDiagnostic{Role: "relay", ConfiguredIdentity: runtime.configuredIdentity, ProcessRunID: runtime.processRunID, LastSeenAt: lease.RenewedAt, LeaseExpiresAt: lease.LeaseExpiresAt, LeaseRevision: lease.RelayLeaseRevision, Ready: !snapshot.Draining && runtime.controller.Ready(now) && runtime.registry != nil && runtime.internalListener != nil, Draining: snapshot.Draining || lease.Draining, DrainDeadline: lease.DrainDeadline}
		if runtime.registry != nil {
			entry.RegisteredPublisherConnections, entry.VisitorStreams = runtime.registry.Load()
		}
		if runtime.serviceRegistry != nil {
			connections, streams := runtime.serviceRegistry.Load()
			entry.RegisteredPublisherConnections += connections
			entry.VisitorStreams += streams
		}
		snapshot.Roles = append(snapshot.Roles, entry)
	}
	return snapshot
}

func (d *daemon) withRoleDiagnostics(next http.Handler, role daemonconfig.Role) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", next)
	mux.HandleFunc("GET /debug/roles", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		snapshot := d.roleDiagnostics(role, time.Now().UTC())
		snapshot.Ready = d.ready(ctx, role, snapshot.SnapshotAt) == nil
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot)
	})
	return mux
}
