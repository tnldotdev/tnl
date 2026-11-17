package state

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationAppliedServiceServingChangesStillRetirePublication(t *testing.T) {
	for _, change := range []string{"target", "target trust", "http access", "team access", "visitor tls", "native target", "native protocol"} {
		t.Run(change, func(t *testing.T) {
			registered, protocol, public := true, "http", true
			if change == "native target" || change == "native protocol" {
				registered, protocol = false, "tcp"
				public = change != "native protocol"
			}
			f := newAppliedEndpointFixture(t, protocol, registered, public)
			ctx := t.Context()
			q := controlstatedb.New(f.d.pool)
			actualGrant, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{
				ID: f.access.GrantID, PublisherIdentityID: f.access.ID,
			})
			if err != nil {
				t.Fatal(err)
			}
			r := f.nextRequest(t)
			binding := r.Configuration.Services["api"]
			switch change {
			case "target", "native target":
				binding.Target = "replacement.internal:8080"
			case "target trust":
				binding.TargetTLS = &ProjectTargetTLS{Hostname: "target.example.test"}
			case "http access":
				binding.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted"}}
			case "team access":
				binding.Access = nil
			case "visitor tls":
				binding.RequirePostQuantum = new(true)
			case "native protocol":
				binding.Protocol = "postgres"
				r.ServiceDeclarations = map[string]string{"api": "postgres", "sibling": "tcp"}
			}
			r.Configuration.Services["api"] = binding
			if _, err := f.d.ApplyProjectConfiguration(ctx, r); err != nil {
				t.Fatal("real serving change failed", err)
			}
			stored, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
			if err != nil || stored.State != "closed" || !stored.ClosedAt.Valid ||
				stored.PublisherGrantID != f.access.GrantID || stored.CertificateHostname != f.service.Endpoint.Hostname ||
				stored.CertificateDomainID != text(f.service.DomainID) {
				t.Fatal("serving change retained the old run or rewrote captured certificate facts", err)
			}
			var slots, closures int
			if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open`,
				f.run.RunID).Scan(&slots); err != nil || slots != 0 {
				t.Fatal("serving change retained old connection slots", err)
			}
			if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1 AND run_id=$2 AND event_type='run.close'`,
				f.service.ID, f.run.RunID).Scan(&closures); err != nil || closures != 1 {
				t.Fatal("serving change did not record exactly one run closure", err)
			}
			if _, err := f.d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, r.Now,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old serving token remained current", err)
			}
			renewal := f.connector.request
			renewal.Action, renewal.PreviousPairID, renewal.PreviousGeneration = "renew", f.pair.ID, f.pair.DeliveryGeneration
			renewal.RequestedAt = r.Now
			f.connector.sign(t, &renewal)
			if renewed, err := f.d.RenewConnectorPeerPair(f.connector.visitor, testVisitorIssuer, renewal, r.Now); err == nil || renewed.ID != "" {
				t.Fatal("serving change renewed the connector session on the retired run")
			}
			if _, err := f.d.HeartbeatServiceRun(ctx, f.sibling.ServiceID, f.sibling.RunID, f.sibling.Token, r.Now,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
				t.Fatal("serving change retired an unrelated sibling run", err)
			}
			service, err := f.d.GetService(ctx, f.service.ID, f.request.ActorID)
			wantTrust := f.service.TrustRevision
			if change == "target trust" || change == "native protocol" {
				wantTrust++
			}
			if err != nil || service.ID != f.service.ID || service.TrustRevision != wantTrust {
				t.Fatal("serving change lost saved identity or the target-trust revision boundary", err)
			}
			grant, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{
				ID: f.access.GrantID, PublisherIdentityID: f.access.ID,
			})
			if err != nil || !reflect.DeepEqual(grant.Protocols, actualGrant.Protocols) ||
				registered && grant.RevokedAt.Valid || !registered && !grant.RevokedAt.Valid {
				t.Fatal("serving change mutated immutable protocols or replaced the wrong grant authority", err)
			}
			if !registered {
				if _, err := f.d.PrepareServiceRun(ctx, service.ID, f.access.PublisherIdentity, "stale-grant", r.Now,
					ServiceRunRequest{Metadata: service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("retired actual grant prepared a replacement run", err)
				}
			}
			if change == "native protocol" {
				assignments, err := f.d.GetDeploymentPublisherAssignments(ctx, f.replicas[0].lease.AccessToken, r.Now)
				if err != nil {
					t.Fatal(err)
				}
				for _, assignment := range assignments.Services {
					if assignment.Service == "api" {
						t.Fatal("captured TCP enrollment widened to PostgreSQL")
					}
				}
			}
		})
	}
}
