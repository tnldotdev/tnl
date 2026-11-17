package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationCompanyRestoredHTTPAndTCPRunsAndPendingTeamEnrollment(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	member := addAuthorityMember(t, d, now, owner, team.ID, "restored-managed", TeamRoleAdmin)
	if err := d.EnsurePrimaryIngressPool(ctx, "192.0.2.10", "", now); err != nil {
		t.Fatal(err)
	}
	registerTestIngress(t, d, now)
	leases := map[string]RelayLease{}
	for slot := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("restored-offboard-%d", slot))
		registration.ConnectionCapacity = 100
		lease, err := d.RegisterRelay(ctx, registration, now, 48*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	type active struct {
		fixture   servicePublicationFixture
		private   ed25519.PrivateKey
		ownership string
	}
	var runs []active
	var services []string
	for _, protocol := range []string{"http", "tcp"} {
		publicEndpoint := protocol == "http"
		service, err := d.CreateServiceAt(ctx, team.ID, member.IdentityID, "restored-"+protocol, "restored-"+protocol,
			ServicePlacement{}, now, ServiceMetadata{Protocol: protocol, PublisherPool: true},
			&ProjectServiceConfiguration{Protocol: protocol, Target: "localhost:3000", Public: &publicEndpoint})
		if err != nil {
			t.Fatal(err)
		}
		services = append(services, service.ID)
		for _, ownership := range []string{"member", "team"} {
			request := standaloneEnrollmentRequest(t, d, service, member.IdentityID, protocol+"-"+ownership, now)
			request.Ownership, request.Protocols = ownership, []string{protocol}
			enrollment, err := d.IssuePublisherEnrollment(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			f := servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, leases: leases}
			f.start(t, protocol+"-"+ownership, now)
			prepareServingPublisher(t, f)
			runs = append(runs, active{f, private, ownership})
		}
	}
	r := appliedProjectRequest(t, d, now)
	r.TeamID, r.ActorID, r.ProjectKey = team.ID, member.IdentityID, "offboard-pending-team"
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "localhost:3000"},
	}}
	r = selectedProjectRequest(r, "pending")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	pending, err := testDeploymentPublisherEnrollment(d, ctx, team.ID, r.ProjectKey, "pending", member.IdentityID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerPrincipal := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	connection := companyTestConnection(t, d, team.ID, ownerPrincipal, "managed", now)
	companyTestEligibility(t, d, connection, member.IdentityID, 1, true, now)
	companyTestEligibility(t, d, connection, member.IdentityID, 2, false, now)
	closedMembers, openTeam := 0, 0
	for _, active := range runs {
		f := active.fixture
		var closed bool
		if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`,
			f.run.RunID).Scan(&closed); err != nil {
			t.Fatal(err)
		}
		if active.ownership == "member" {
			if !closed {
				t.Error("offboarding left a member-owned run open", f.service.Protocol)
			}
			closedMembers++
			if _, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Error("offboarding allowed a member-owned heartbeat", f.service.Protocol, err)
			}
			proof, err := publisherproof.Sign(f.publisher.ID, f.publisher.KeyID, f.publisher.GrantID, publisherTestAudience, active.private, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.ExchangePublisherAssertion(ctx, f.publisher.ID, f.publisher.GrantID, publisherTestAudience, proof, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Error("offboarding allowed member-owned publisher exchange", f.service.Protocol, err)
			}
		} else {
			if closed {
				t.Error("offboarding closed a team-owned run", f.service.Protocol)
			}
			openTeam++
			if _, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
				t.Error("team-owned run depended on its offboarded creator", f.service.Protocol, err)
			}
		}
	}
	if closedMembers != 2 || openTeam != 2 {
		t.Fatal("offboarding fixture did not exercise all four protocol/ownership combinations")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	redeemed, err := d.RedeemDeploymentPublisherEnrollment(ctx, pending.Key, public, now)
	if err != nil || redeemed.DeploymentID == "" {
		t.Fatal("offboarding invalidated pre-issued team deployment enrollment", err)
	}
	var saved int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services
		WHERE id=ANY($1::text[]) AND enabled AND deleted_at IS NULL`, services).Scan(&saved); err != nil || saved != 2 {
		t.Fatal("offboarding destroyed a saved HTTP or TCP service", err)
	}
}
