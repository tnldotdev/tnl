package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func reviewPublisher(t *testing.T, d *Database, service ServiceRecord, editor, membershipID string, policyRevision uint64, now time.Time) (PublisherIdentity, ed25519.PrivateKey) {
	t.Helper()
	e, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID}, Name: "test", Kind: "installed", EditorID: editor, EditorMembershipID: membershipID, PolicyRevision: policyRevision, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	return p, private
}

func TestIntegrationPublisherRevocationRechecksWaitingEditor(t *testing.T) {
	for _, mutation := range []string{"identity", "grant"} {
		for _, change := range []string{"removed", "demoted"} {
			t.Run(mutation+"/"+change, func(t *testing.T) {
				d, now, owner, team := newAuthorityTeam(t)
				_, member := allocationVisitorMember(t, d, team.ID, owner, "reviewer", TeamRoleAdmin, now)
				service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "shared-review", "shared-review", ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"})
				if err != nil {
					t.Fatal(err)
				}
				ownerMember, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: team.ID, IdentityID: owner})
				if err != nil {
					t.Fatal(err)
				}
				p, _ := reviewPublisher(t, d, service, owner, ownerMember.ActorMembershipID, uint64(ownerMember.PolicyRevision), now)
				if err := d.AuthorizePublisherManagement(t.Context(), team.ID, p.ID, member.IdentityID); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				q := controlstatedb.New(gate)
				if _, err := q.LockLocalTeamForMutation(ctx, team.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := q.LockPublisherIdentity(ctx, p.ID); err != nil {
					t.Fatal(err)
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				revoked := make(chan error, 1)
				revoke := func(editor string) error {
					if mutation == "identity" {
						return d.RevokePublisherIdentity(ctx, team.ID, p.ID, editor, now)
					}
					return d.RevokePublisherGrant(ctx, team.ID, p.ID, p.GrantID, editor, now)
				}
				workers.Go(func() { revoked <- revoke(member.IdentityID) })
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), revoked)
				revision, err := q.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{TeamID: team.ID, UpdatedAt: timestamp(now)})
				if err != nil {
					t.Fatal(err)
				}
				if change == "removed" {
					_, err = q.RemoveTeamMembership(ctx, controlstatedb.RemoveTeamMembershipParams{MembershipID: member.ID, TeamID: team.ID, AuthorityRevision: revision, RemovedAt: timestamp(now), RemovedByIdentityID: text(owner)})
				} else {
					_, err = q.UpdateMembershipRole(ctx, controlstatedb.UpdateMembershipRoleParams{MembershipID: member.ID, TeamID: team.ID, Role: "member", AuthorityRevision: revision, UpdatedAt: timestamp(now)})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, revoked); !errors.Is(err, ErrPublisherIdentity) {
					t.Fatalf("stale editor revoked %s after being %s: %v", mutation, change, err)
				}
				var changed bool
				query := `SELECT revoked_at IS NOT NULL FROM control.publisher_identities WHERE id=$1`
				id := p.ID
				if mutation == "grant" {
					query, id = `SELECT revoked_at IS NOT NULL FROM control.publisher_grants WHERE id=$1`, p.GrantID
				}
				if err := d.pool.QueryRow(ctx, query, id).Scan(&changed); err != nil || changed {
					t.Fatalf("rejected revocation committed: %t, %v", changed, err)
				}
				if err := revoke(owner); err != nil {
					t.Fatalf("current owner could not revoke: %v", err)
				}
			})
		}
	}
}

func TestIntegrationPublisherHeartbeatDomainReleaseLockOrder(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	domain, err := d.ClaimTeamDomain(t.Context(), ClaimDomainRequest{
		IdentityID: owner, TeamID: team.ID, Domain: "publisher-release.example.test",
		IdempotencyKey: "release-domain", RequestDigest: sha256.Sum256([]byte("release-domain")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := d.ClaimDNSAuthorityWork(t.Context(), "publisher-release", now, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatal("custom domain authority was not queued", found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers = "ready", "ZRELEASE", []string{"ns-1.example.test"}
	if _, err := d.SaveDNSAuthorityWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	// control derives the owner's local hostname beneath this custom domain;
	// organization-local services cannot claim a shared domain-level hostname.
	service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "shared", "release-service",
		ServicePlacement{DomainID: domain.ID}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	if service.DomainID != domain.ID || service.Endpoint == nil {
		t.Fatal("release fixture did not select the custom domain")
	}
	member, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: team.ID, IdentityID: owner})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reviewPublisher(t, d, service, owner, member.ActorMembershipID, uint64(member.PolicyRevision), now)
	registerCertificatePlanRelays(t, d, now)
	f := servicePublicationFixture{database: d, now: now, service: service, publisher: p}
	f.start(t, "release-race", now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: service.ID}); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	heartbeat, release := make(chan error, 1), make(chan error, 1)
	workers.Go(func() {
		_, err := d.HeartbeatServiceRun(ctx, service.ID, f.run.RunID, f.run.Token,
			now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		heartbeat <- err
	})
	heartbeatPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), heartbeat)
	workers.Go(func() {
		release <- d.ReleaseTeamDomain(ctx, owner, team.ID, domain.ID, now.Add(2*time.Second))
	})
	// heartbeat holds team/service admission before waiting for the run.
	// domain release must serialize behind it, never invert that lock order.
	waitForPostgresBlock(t, ctx, d, heartbeatPID, release)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, heartbeat); err != nil {
		t.Fatalf("heartbeat deadlocked with domain release: %v", err)
	}
	if err := awaitIntegrationResult(t, ctx, release); err != nil {
		t.Fatalf("domain release did not finish: %v", err)
	}
	var closed bool
	if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at IS NOT NULL AND NOT assignments_open
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatalf("release failed to close run: %t, %v", closed, err)
	}
	var disabled bool
	if err := d.pool.QueryRow(ctx, `SELECT NOT enabled FROM control.services WHERE id=$1`, service.ID).Scan(&disabled); err != nil || !disabled {
		t.Fatalf("released domain left its service enabled: %t, %v", disabled, err)
	}
}

func TestIntegrationPublisherRetiredKeyOnlyRecoversExactRun(t *testing.T) {
	d, now, actor, leases := newPublishRunPrerequisites(t)
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "retired", "retired",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	p, private := reviewPublisher(t, d, service, actor.ActingIdentityID, actor.MembershipID, 1, now)
	access := publisherAccess(t, d, p, private, "", now)
	f := servicePublicationFixture{database: d, now: now, service: service, publisher: p, leases: leases}
	f.start(t, "original", now)
	other := f.sibling(t, "unstarted", now)
	grant, err := d.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{
		PublisherIdentityID: p.ID, Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: other.service.ID},
		EditorID: actor.ActingIdentityID, EditorMembershipID: actor.MembershipID, PolicyRevision: 1, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	unstartedPublisher := p
	unstartedPublisher.GrantID, unstartedPublisher.Scope.ServiceID = grant, other.service.ID
	unstarted, err := d.PrepareServiceRun(t.Context(), other.service.ID, unstartedPublisher, "unstarted", now,
		ServiceRunRequest{Metadata: other.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	public, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := mustOpaqueID(t, opaqueid.PublisherIdentityKeyPrefix)
	audience := "https://control.example/v1/publisher-keys/rotate"
	proof, err := publisherproof.Sign(p.ID, keyID, p.GrantID, audience, replacement, now)
	if err != nil {
		t.Fatal(err)
	}
	currentProof, err := publisherproof.Sign(p.ID, p.KeyID, p.GrantID, publisherproof.RotationAudience(audience, keyID, public), private, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RotatePublisherKey(t.Context(), access.Token, "", keyID, audience, public, proof, currentProof, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatalf("bounded old token unexpectedly expired: %v", err)
	}
	retry, err := d.StartServiceRun(t.Context(), service.ID, f.run.RunID, f.run.RunNumber, p, now)
	if err != nil || retry.Token != f.run.Token || retry.RunID != f.run.RunID || retry.RunNumber != f.run.RunNumber {
		t.Fatalf("retired key could not recover its exact run: %v", err)
	}
	if _, err := d.StartServiceRun(t.Context(), service.ID, f.run.RunID, f.run.RunNumber+1, p, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("retired key changed its run binding: %v", err)
	}
	if _, err := d.StartServiceRun(t.Context(), other.service.ID, unstarted.RunID, unstarted.RunNumber, unstartedPublisher, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("retired key started a merely prepared run: %v", err)
	}
	current := p
	current.KeyID = keyID
	if _, err := d.StartServiceRun(t.Context(), service.ID, f.run.RunID, f.run.RunNumber, current, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("replacement key adopted another key's run: %v", err)
	}
	if err := d.CloseServiceRun(t.Context(), service.ID, f.run.RunID, f.run.Token, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartServiceRun(t.Context(), service.ID, f.run.RunID, f.run.RunNumber, p, now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("retired key resurrected its closed run: %v", err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), service.ID, p, "new-attempt", now.Add(2*time.Second),
		ServiceRunRequest{Metadata: service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("retired key prepared a new run: %v", err)
	}
	f.publisher = current
	previous := f.run
	f.start(t, "new-attempt", now.Add(2*time.Second))
	if f.run.RunID == previous.RunID || f.run.RunNumber <= previous.RunNumber {
		t.Fatal("current key reused the closed run")
	}
}

func TestIntegrationPublisherSavedPurposesHaveExactGrants(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now := f.database, f.now
	member, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{
		TeamID: f.project.TeamID, IdentityID: f.project.ActorID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// app and integration handlers now use ordinary HTTP services. keep every
	// former purpose case and prove protocol variants use the same exact grants.
	for _, name := range []string{"app", "oauth", "webhooks", "alias", "demo", "tcp", "mysql", "postgres", "kubernetes"} {
		t.Run(name, func(t *testing.T) {
			var service ServiceRecord
			if name == "tcp" || name == "mysql" || name == "postgres" || name == "kubernetes" {
				var err error
				service, err = d.CreateServiceAt(t.Context(), f.project.TeamID, f.project.ActorID, name, name,
					ServicePlacement{}, now, ServiceMetadata{Protocol: name}, nil)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				service = f.local(t, name, nil)
			}
			p, private := reviewPublisher(t, d, service, f.project.ActorID, member.ActorMembershipID, uint64(member.PolicyRevision), now)
			a := publisherAccess(t, d, p, private, "", now)
			if got, err := d.AuthenticatePublisherAccess(t.Context(), a.Token, "", now); err != nil ||
				got.Scope != (PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID}) {
				t.Fatalf("%s exact grant unavailable: %+v, %v", name, got, err)
			}
			forged := p
			forged.Scope.ServiceID = f.service.ID
			if _, err := d.GetServiceForPublisher(t.Context(), f.service.ID, forged, now); !errors.Is(err, ErrServiceAccess) {
				t.Fatalf("%s grant expanded beyond its persisted service: %v", name, err)
			}
			if _, err := d.PrepareServiceRun(t.Context(), f.service.ID, forged, "foreign", now,
				ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
				t.Fatalf("%s grant prepared another service: %v", name, err)
			}
			publication := servicePublicationFixture{database: d, now: now, service: service, publisher: p, leases: f.leases}
			publication.start(t, "purpose-"+name, now)
			if err := d.CloseServiceRun(t.Context(), service.ID, publication.run.RunID, publication.run.Token, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrationPublisherSharedGrantSurvivesIssuerRemoval(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	_, member := allocationVisitorMember(t, d, team.ID, owner, "issuer", TeamRoleAdmin, now)
	service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "shared", "durable-shared", ServicePlacement{}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: team.ID, IdentityID: member.IdentityID})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reviewPublisher(t, d, service, member.IdentityID, member.ID, uint64(actor.PolicyRevision), now)
	registerCertificatePlanRelays(t, d, now)
	f := servicePublicationFixture{database: d, now: now, service: service, publisher: p}
	f.start(t, "durable-shared", now)
	if err := d.RemoveMembership(t.Context(), owner, team.ID, member.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 64}
	if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, f.run.RunID, f.run.Token, now.Add(2*time.Second), health); err != nil {
		t.Fatalf("issuer departure erased its explicitly issued shared grant: %v", err)
	}
	if err := d.RevokePublisherGrant(t.Context(), team.ID, p.ID, p.GrantID, member.IdentityID, now.Add(3*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("departed issuer retained grant management: %v", err)
	}
	if err := d.RevokePublisherGrant(t.Context(), team.ID, p.ID, p.GrantID, owner, now.Add(3*time.Second)); err != nil {
		t.Fatalf("current owner could not revoke durable grant: %v", err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, f.run.RunID, f.run.Token, now.Add(4*time.Second), health); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("revoked shared grant remained live: %v", err)
	}
}
