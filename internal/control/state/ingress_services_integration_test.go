package state

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationIngressServicesReadsReadyRunsWithoutVisitorWrites(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	ctx := t.Context()
	lease := registerServiceHTTPAdmissionIngress(t, ctx, f, "routing-reader")
	var before int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		snapshot, err := f.database.ReadIngressServices(ctx, lease.IngressLeaseIdentity, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if !snapshot.ObservedAt.Equal(f.now) || !snapshot.ValidUntil.Equal(minTime(f.now.Add(f.database.servingTolerance()), lease.ServingUntil)) || len(snapshot.Runs) != 1 {
			t.Fatal("routing did not return one current, short-lived run", snapshot.ObservedAt, snapshot.ValidUntil, len(snapshot.Runs))
		}
		run := snapshot.Runs[0]
		if run.ServiceID != f.service.ID || run.RunID != f.run.RunID || run.RunNumber != f.run.RunNumber ||
			run.Protocol != "http" || run.Port != 443 || run.Hostname != f.service.Endpoint.Hostname || run.EndpointRevision < 1 ||
			!run.ValidUntil.Equal(snapshot.ValidUntil) || len(run.Relays) != 2 || run.Anonymous {
			t.Fatal("routing changed the ready service, endpoint, or deadline")
		}
		for _, relay := range run.Relays {
			matched := false
			for _, assignment := range f.run.Connections {
				if relay.PublisherConnectionID == assignment.PublisherConnectionID &&
					relay.ConnectionSlot == assignment.ConnectionSlot && relay.ConnectionAssignmentRevision == assignment.Revision &&
					relay.RelayServiceID == assignment.RelayServiceID {
					matched = true
				}
			}
			current := f.leases[relay.RelayServiceID]
			if !matched || relay.RelayRunID != current.RelayRunID || relay.RelayLeaseRevision != int64(current.RelayLeaseRevision) ||
				!relay.LeaseExpiresAt.Equal(current.ServingUntil) {
				t.Fatal("routing returned a different assignment or relay process")
			}
		}
		authority, err := tunnelv1.ReadVisitorSourceAuthority(run.SourceAuthority)
		if err != nil || authority.IngressID != lease.IngressID || authority.IngressRunID != lease.IngressRunID ||
			authority.IngressLeaseRevision != lease.IngressLeaseRevision || authority.EndpointRevision != run.EndpointRevision ||
			authority.ValidUntil != run.ValidUntil.Unix() {
			t.Fatal("source authority did not name the current ingress lease", err)
		}
		binding := tunnelv1.VisitorSourceBinding{
			ServiceID: run.ServiceID, ServiceRunID: run.RunID, RunNumber: uint64(run.RunNumber),
			VisitorConnectionID: mustOpaqueID(t, "vc_"),
			Source:              netip.MustParseAddrPort("192.0.2.30:50000"), Destination: netip.MustParseAddrPort("198.51.100.10:443"),
		}
		proof, err := visitortoken.SignVisitorSource([32]byte(run.SourceKey), authority, 1, binding, f.now)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(f.run.Token))
		if err != nil {
			t.Fatal(err)
		}
		master, err := visitortoken.ServiceVisitorSourceKey(digest[:], run.RunID, uint64(run.RunNumber))
		if err != nil || visitortoken.VerifyVisitorSource(master, proof, binding, authority.VisitorPolicyRevision, f.now) != nil {
			t.Fatal("the run's publisher could not verify ingress source evidence", err)
		}
		binding.Source = netip.MustParseAddrPort("192.0.2.31:50000")
		if visitortoken.VerifyVisitorSource(master, proof, binding, authority.VisitorPolicyRevision, f.now) == nil {
			t.Fatal("source evidence allowed a different visitor address")
		}
	}
	var after int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("routing reads wrote visitor records", before, after)
	}
}

func TestIntegrationIngressServicesRejectsStaleIngress(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	lease := registerServiceHTTPAdmissionIngress(t, t.Context(), f, "routing-lease")
	for _, test := range []struct {
		name     string
		identity IngressLeaseIdentity
		now      time.Time
	}{
		{"unknown", IngressLeaseIdentity{IngressID: "missing", IngressRunID: lease.IngressRunID, IngressLeaseRevision: lease.IngressLeaseRevision}, f.now},
		{"process", IngressLeaseIdentity{IngressID: lease.IngressID, IngressRunID: mustOpaqueID(t, "ir_"), IngressLeaseRevision: lease.IngressLeaseRevision}, f.now},
		{"revision", IngressLeaseIdentity{IngressID: lease.IngressID, IngressRunID: lease.IngressRunID, IngressLeaseRevision: lease.IngressLeaseRevision + 1}, f.now},
		{"expired", lease.IngressLeaseIdentity, lease.ServingUntil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := f.database.ReadIngressServices(t.Context(), test.identity, test.now); !errors.Is(err, ErrIngressLeaseStale) {
				t.Fatal("routing accepted a stale ingress lease", err)
			}
		})
	}
	if _, err := f.database.BeginIngressDrain(t.Context(), lease.IngressLeaseIdentity, f.now, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ReadIngressServices(t.Context(), lease.IngressLeaseIdentity, f.now); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("routing accepted a draining ingress", err)
	}
}

func TestIntegrationIngressServicesDoesNotWaitForPublicationLocks(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	lease := registerServiceHTTPAdmissionIngress(t, t.Context(), f, "routing-locks")
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(context.WithoutCancel(t.Context())); err != nil {
			t.Error("release publication locks", err)
		}
	}()
	for _, query := range []string{
		`SELECT id FROM control.services WHERE id=$1 FOR UPDATE`,
		`SELECT id FROM control.service_runs WHERE service_id=$1 FOR UPDATE`,
		`SELECT publisher_connection_id FROM control.service_connection_slots WHERE service_id=$1 FOR UPDATE`,
	} {
		if _, err := tx.Exec(t.Context(), query, f.service.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, lease.IngressID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	snapshot, err := f.database.ReadIngressServices(ctx, lease.IngressLeaseIdentity, f.now)
	if err != nil || len(snapshot.Runs) != 1 {
		t.Fatal("routing waited for a publication writer", err, len(snapshot.Runs))
	}
}

func TestIntegrationIngressServicesDropsUnavailableRuns(t *testing.T) {
	for _, test := range []struct {
		name  string
		query string
	}{
		{"private", `UPDATE control.services SET public=false WHERE id=$1`},
		{"disabled", `UPDATE control.services SET enabled=false WHERE id=$1`},
		{"retired endpoint", `UPDATE control.service_endpoints SET retired_at=clock_timestamp(),reusable_after=clock_timestamp()+interval '1 minute' WHERE service_id=$1`},
		{"unhealthy", `UPDATE control.service_runs SET healthy=false WHERE service_id=$1`},
		{"expired publisher", `UPDATE control.service_runs SET serving_until=serving_observed_at+interval '1 microsecond' WHERE service_id=$1`},
		{"expired certificate", `UPDATE control.service_runs SET certificate_expires_at='2000-01-01' WHERE service_id=$1`},
		{"old certificate", `UPDATE control.service_runs SET certificate_hostname='old.example' WHERE service_id=$1`},
		{"closed run", `UPDATE control.service_runs SET state='closed',closed_at=clock_timestamp() WHERE service_id=$1`},
		{"closed connections", `UPDATE control.service_connection_slots SET state='closed' WHERE service_id=$1`},
		{"old relay process", `UPDATE control.relay_leases SET relay_lease_revision=relay_lease_revision+1 WHERE relay_id IN (SELECT relay_id FROM control.service_connection_slots WHERE service_id=$1)`},
		{"expired relays", `UPDATE control.relay_leases SET serving_until=renewed_at+interval '1 microsecond' WHERE relay_id IN (SELECT relay_id FROM control.service_connection_slots WHERE service_id=$1)`},
		{"draining relays", `UPDATE control.relay_leases SET draining=true WHERE relay_id IN (SELECT relay_id FROM control.service_connection_slots WHERE service_id=$1)`},
		{"revoked grant", `UPDATE control.publisher_grants SET revoked_at=clock_timestamp() WHERE id IN (SELECT publisher_grant_id FROM control.service_runs WHERE service_id=$1)`},
		{"revoked publisher", `UPDATE control.publisher_identities SET revoked_at=clock_timestamp() WHERE id IN (SELECT publisher_identity_id FROM control.service_runs WHERE service_id=$1)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newPublicServiceHTTPAdmissionFixture(t)
			lease := registerServiceHTTPAdmissionIngress(t, t.Context(), f, "routing-removal")
			before, err := f.database.ReadIngressServices(t.Context(), lease.IngressLeaseIdentity, f.now)
			if err != nil || len(before.Runs) != 1 {
				t.Fatal("fixture did not publish a visible run", err, len(before.Runs))
			}
			if _, err := f.database.pool.Exec(t.Context(), test.query, f.service.ID); err != nil {
				t.Fatal(err)
			}
			after, err := f.database.ReadIngressServices(t.Context(), lease.IngressLeaseIdentity, f.now.Add(time.Second))
			if err != nil || len(after.Runs) != 0 {
				t.Fatal("routing retained an unavailable run", err, len(after.Runs))
			}
		})
	}
}

func TestIntegrationPublicEndpointPolicyChangesWithoutRevokingRunPolicy(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	ctx := t.Context()
	lease := registerServiceHTTPAdmissionIngress(t, ctx, f, "routing-policy")
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	before, err := f.database.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now)
	if err != nil || before.Policy.PublicEndpoint == nil {
		t.Fatal("publisher policy omitted its public endpoint", err)
	}
	endpoint := *before.Policy.PublicEndpoint
	if endpoint.Hostname != f.service.Endpoint.Hostname || endpoint.Port != 443 || endpoint.EndpointRevision != f.service.EndpointRevision {
		t.Fatal("publisher policy changed the current public endpoint")
	}
	for _, public := range []bool{false, true} {
		at := f.now.Add(time.Second)
		if public {
			at = at.Add(time.Second)
		}
		_, err := f.database.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
			TeamID: f.project.TeamID, ActorID: f.project.ActorID, ProjectKey: f.project.ProjectKey,
			SourceFingerprint: f.project.SourceFingerprint, Service: "web", WorktreeKey: "review",
			Configuration: ProjectServiceConfiguration{Target: "localhost:3000", Public: &public}, Now: at,
		})
		if err != nil {
			t.Fatal(err)
		}
		current, err := f.database.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
		if err != nil || !current.Policy.Enabled || current.Policy.Hostname != before.Policy.Hostname ||
			current.Policy.MetadataRevision != before.Policy.MetadataRevision {
			t.Fatal("public reachability changed the run's independent connector policy or target trust", err)
		}
		if !public && current.Policy.PublicEndpoint != nil {
			t.Fatal("disabled public endpoint remained in publisher policy")
		}
		if public && (current.Policy.PublicEndpoint == nil || current.Policy.PublicEndpoint.EndpointRevision <= endpoint.EndpointRevision ||
			current.Policy.PublicEndpoint.Hostname != endpoint.Hostname || current.Policy.PublicEndpoint.Port != endpoint.Port) {
			t.Fatal("re-enabled public endpoint did not receive its current revision")
		}
		snapshot, err := f.database.ReadIngressServices(ctx, lease.IngressLeaseIdentity, at)
		if err != nil || public && len(snapshot.Runs) != 1 || !public && len(snapshot.Runs) != 0 {
			t.Fatal("ingress routing disagreed with current public reachability", err, len(snapshot.Runs))
		}
		if public && (snapshot.Runs[0].RunID != f.run.RunID || snapshot.Runs[0].RunNumber != f.run.RunNumber) {
			t.Fatal("re-enabling the endpoint replaced its retained service run")
		}
	}
}
