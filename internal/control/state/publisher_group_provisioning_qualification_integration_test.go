package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

// capture durable mutation facts, not projected runtime timestamps or credentials.
func provisioningProjectFacts(t *testing.T, d *Database, team, project string) []byte {
	t.Helper()
	var facts []byte
	err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'project',(SELECT to_jsonb(p) FROM control.applied_projects p WHERE team_id=$1 AND project_key=$2),
		'environments',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM control.environments e WHERE team_id=$1 AND project_key=$2),
		'collections',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM control.collections c WHERE team_id=$1 AND project_key=$2),
		'definitions',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.revision) FROM control.service_definitions d WHERE team_id=$1 AND project_key=$2),
		'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM control.project_publisher_groups g WHERE team_id=$1 AND project_key=$2),
		'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.group_id) FROM control.publisher_group_bindings b JOIN control.project_publisher_groups g ON g.id=b.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'creations',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.idempotency_key) FROM control.environment_creations c WHERE team_id=$1 AND project_key=$2),
		'services',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM control.services s WHERE s.id IN(SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2)),
		'enrollments',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM control.publisher_group_enrollments e JOIN control.project_publisher_groups g ON g.id=e.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'enrollment_services',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.enrollment_id,s.service) FROM control.environment_publisher_enrollment_services s JOIN control.publisher_group_enrollments e ON e.id=s.enrollment_id JOIN control.project_publisher_groups g ON g.id=e.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'provisioning',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM control.machine_provisioning_grants g WHERE team_id=$1 AND project_key=$2),
		'publishers',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM control.publisher_identities p JOIN control.publisher_group_members m ON m.publisher_identity_id=p.id JOIN control.project_publisher_groups g ON g.id=m.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.cursor) FROM control.service_audit_events a WHERE a.team_id=$1 AND a.service_id IN(SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2))
	)::text`, team, project).Scan(&facts)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func TestIntegrationPublisherGroupProvisioningExistingTenantIsolation(t *testing.T) {
	f := newProvisioningEnvironmentFixture(t)
	ctx := t.Context()
	request := f.request(t)
	request.Name = "shared"
	own, err := f.d.CreateEnvironment(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	otherSession, err := f.d.CreateOIDCControlSession(ctx, "tunnels.example.test", OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: "tenant-b-owner", DisplayName: "tenant-b-owner", AssertionDigest: digest, AssertionExpiry: f.now.Add(time.Hour)}, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	otherOwner := otherSession.Identity.Identity.ID
	teamRequest := authorityTeamRequest(otherOwner)
	teamRequest.DisplayName = "tenant-b"
	otherTeam, err := f.d.CreateTeam(ctx, teamRequest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	otherProject := environmentPublisherTestProject{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, ActorID: otherOwner, SourceFingerprint: f.r.SourceFingerprint, AccessToken: otherSession.AccessToken, Now: f.now}
	otherDefinition := environmentPublisherDefinition(t, f.d, otherProject, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	otherCollection, _ := createTestCollection(t, f.d, otherProject, f.collection.Name, otherDefinition.Revision)
	otherManager, err := f.d.AuthenticateEnvironmentPublisherManager(ctx, otherSession.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	foreignRequest := request
	foreignRequest.TeamID, foreignRequest.ActorID, foreignRequest.Manager = otherTeam.ID, otherOwner, otherManager
	foreignRequest.CollectionID, foreignRequest.ExpectedCollectionRevision = otherCollection.ID, otherCollection.MutationRevision
	foreign, err := f.d.CreateEnvironment(ctx, foreignRequest)
	if err != nil {
		t.Fatal(err)
	}
	if otherTeam.ID == f.r.TeamID || foreign.ID == own.ID || foreign.Name != own.Name || foreign.AppliedDefinitionRevision != own.AppliedDefinitionRevision || foreign.Services[0].Service == "" || foreign.Services[0].Service != own.Services[0].Service {
		t.Fatal("tenant fixture did not collide on project/definition/environment selectors")
	}
	enrollment, err := f.d.IssueEnvironmentPublisherEnrollment(ctx, IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: EnvironmentPublisherSelection{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, EnvironmentID: foreign.ID, Manager: otherManager}, ExpectedRevision: foreign.MutationRevision, ExpectedConfigurationHash: foreign.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Minute, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemEnvironmentPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	beforeOwn := provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)
	beforeForeign := provisioningProjectFacts(t, f.d, otherTeam.ID, f.r.ProjectKey)
	read, _ := f.authority(t, ProvisioningRead)
	if _, err = f.d.InspectEnvironments(ctx, otherTeam.ID, f.r.ProjectKey, read); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("listed another existing tenant", err)
	}
	update, _ := f.authority(t, ProvisioningUpdate)
	enroll, _ := f.authority(t, ProvisioningEnroll)
	revoke, _ := f.authority(t, ProvisioningRevokeMember)
	retire, _ := f.authority(t, ProvisioningRetire)
	for _, selector := range []string{foreign.ID, foreign.Name} {
		want := ErrMachineDenied
		if selector == foreign.Name {
			want = ErrEnvironmentInvalid
		}
		if _, err = f.d.InspectEnvironment(ctx, otherTeam.ID, f.r.ProjectKey, selector, read); !errors.Is(err, want) {
			t.Fatal("read another existing tenant", err)
		}
		mutation := ApplyEnvironmentRequest{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, Manager: update, EnvironmentApplication: EnvironmentApplication{EnvironmentID: selector, ExpectedRevision: foreign.MutationRevision, DefinitionRevision: foreign.AppliedDefinitionRevision, Targets: EnvironmentTargets{"api": {Address: "192.0.2.99:3000"}}}, Now: f.now}
		if _, err = f.d.ApplyEnvironment(ctx, mutation); !errors.Is(err, want) {
			t.Fatal("mutated another existing tenant", err)
		}
		selection := EnvironmentPublisherSelection{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, EnvironmentID: selector, Manager: enroll}
		if _, err = f.d.IssueEnvironmentPublisherEnrollment(ctx, IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: selection, ExpectedRevision: foreign.MutationRevision, ExpectedConfigurationHash: foreign.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Minute, IdempotencyKey: "foreign-enrollment", Now: f.now}); !errors.Is(err, want) {
			t.Fatal("enrolled another existing tenant", err)
		}
		selection.Manager = revoke
		if err = f.d.RevokeEnvironmentPublisher(ctx, selection, member.PublisherIdentityID, f.now); !errors.Is(err, want) {
			t.Fatal("revoked another tenant's member", err)
		}
		if err = f.d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, Manager: retire, EnvironmentID: selector, ExpectedRevision: foreign.MutationRevision, Now: f.now}); !errors.Is(err, want) {
			t.Fatal("retired another existing tenant", err)
		}
	}
	foreignRequest.ActorID, foreignRequest.Manager = "", request.Manager
	if _, err = f.d.CreateEnvironment(ctx, foreignRequest); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("replayed another tenant's creation key", err)
	}
	// selecting the original tenant must not let a foreign immutable ID bypass
	// the team predicate, even though all friendly selectors are identical.
	if _, err = f.d.InspectEnvironment(ctx, f.r.TeamID, f.r.ProjectKey, foreign.ID, read); !errors.Is(err, ErrEnvironmentNotFound) {
		t.Fatal("foreign ID crossed the original tenant", err)
	}
	if !bytes.Equal(beforeOwn, provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)) || !bytes.Equal(beforeForeign, provisioningProjectFacts(t, f.d, otherTeam.ID, f.r.ProjectKey)) {
		t.Fatal("denied cross-tenant operations changed durable state")
	}
	var used int
	if err = f.d.pool.QueryRow(ctx, `SELECT enrollment_used FROM control.machine_provisioning_grants WHERE id=$1`, f.grant.ID).Scan(&used); err != nil || used != 0 {
		t.Fatal("cross-tenant denial spent enrollment budget", used, err)
	}
}

func TestIntegrationPublisherGroupProvisioningExpiryDuringServiceLock(t *testing.T) {
	for _, operation := range []ProvisioningOperation{ProvisioningUpdate, ProvisioningCreate} {
		for _, expiry := range []string{"token", "grant"} {
			t.Run(string(operation)+"/"+expiry, func(t *testing.T) {
				f := newProvisioningEnvironmentFixture(t)
				firstRequest := f.request(t)
				environment, err := f.d.CreateEnvironment(t.Context(), firstRequest)
				if err != nil {
					t.Fatal(err)
				}
				_, token := f.authority(t, operation)
				deadline := time.Now().Add(1500 * time.Millisecond)
				if expiry == "token" {
					digest := sha256.Sum256([]byte(token.Credential))
					_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_sessions SET expires_at=$2 WHERE credential_digest=$1`, digest[:], deadline)
				} else {
					_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_grants SET expires_at=$2 WHERE id=$1`, f.grant.ID, deadline)
				}
				if err != nil {
					t.Fatal(err)
				}
				manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), credentials.AccessToken(token.Credential))
				if err != nil {
					t.Fatal(err)
				}
				before := provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)
				gate, err := f.d.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if operation == ProvisioningCreate {
					// creation no longer locks sibling services. block its real shared
					// publication reservation boundary after the new parent is inserted.
					err = lockAppliedPublicationReservations(t.Context(), gate)
				} else {
					_, err = gate.Exec(t.Context(), `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, environment.Services[0].ServiceID)
				}
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				entered, done := make(chan time.Time, 1), make(chan error, 1)
				at := time.Now()
				createRequest := firstRequest
				createRequest.Manager = manager
				createRequest.Name, createRequest.IdempotencyKey, createRequest.Now = "blocked", "customer/blocked", at
				workers.Go(func() {
					entered <- time.Now()
					var e error
					if operation == ProvisioningCreate {
						_, e = f.d.CreateEnvironment(ctx, createRequest)
					} else {
						_, e = f.d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Manager: manager, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: environment.MutationRevision, DefinitionRevision: environment.AppliedDefinitionRevision, Targets: EnvironmentTargets{"api": {Address: "192.0.2.42:3001"}}}, Now: at})
					}
					done <- e
				})
				pid := waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
				var query string
				if err = f.d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
					t.Fatal(err)
				}
				boundary := "ORDER BY service.id FOR UPDATE OF service"
				if operation == ProvisioningCreate {
					boundary = "tnl:relay-assignment-totals"
				}
				if !strings.Contains(query, boundary) {
					t.Fatal("mutation did not reach its resource-lock boundary")
				}
				started := awaitIntegrationResult(t, ctx, entered)
				blockedAt := time.Now()
				if !started.Before(deadline) || !blockedAt.Before(deadline) {
					t.Fatal("credential expired before the observed resource wait")
				}
				// wait for the actual captured deadline, never an arbitrary readiness
				// delay. the observed database lock above proves work was in flight.
				timer := time.NewTimer(time.Until(deadline.Add(time.Millisecond)))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				releasedAt := time.Now()
				if !releasedAt.After(deadline) {
					t.Fatal("service lock released before credential expiry")
				}
				if err = gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrControlAuthentication) {
					t.Fatal("expired mutation committed after resource-lock wait", err)
				}
				if !bytes.Equal(before, provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)) {
					t.Fatal("expired mutation changed bindings, revision, creation keys or audit")
				}
				if operation == ProvisioningCreate {
					// a keyed replay of an existing group must reauthorize too;
					// neither it nor the rolled-back allocation may return an ID.
					for _, replay := range []CreateEnvironmentRequest{firstRequest, createRequest} {
						replay.Manager, replay.Now = manager, releasedAt
						result, e := f.d.CreateEnvironment(ctx, replay)
						if !errors.Is(e, ErrControlAuthentication) || result.ID != "" {
							t.Fatal("expired keyed replay returned a resource", e)
						}
					}
					if !bytes.Equal(before, provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)) {
						t.Fatal("expired replay changed durable state")
					}
				}
			})
		}
	}
}
