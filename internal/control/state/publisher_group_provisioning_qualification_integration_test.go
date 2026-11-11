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
)

// capture durable mutation facts, not projected runtime timestamps or credentials.
func provisioningProjectFacts(t *testing.T, d *Database, team, project string) []byte {
	t.Helper()
	var facts []byte
	err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'project',(SELECT to_jsonb(p) FROM control.applied_projects p WHERE team_id=$1 AND project_key=$2),
		'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM control.project_publisher_groups g WHERE team_id=$1 AND project_key=$2),
		'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.group_id) FROM control.publisher_group_bindings b JOIN control.project_publisher_groups g ON g.id=b.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'creations',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.idempotency_key) FROM control.publisher_group_creations c WHERE team_id=$1 AND project_key=$2),
		'services',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM control.services s WHERE s.id IN(SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2)),
		'enrollments',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM control.publisher_group_enrollments e JOIN control.project_publisher_groups g ON g.id=e.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'publishers',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM control.publisher_identities p JOIN control.publisher_group_members m ON m.publisher_identity_id=p.id JOIN control.project_publisher_groups g ON g.id=m.group_id WHERE g.team_id=$1 AND g.project_key=$2),
		'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.cursor) FROM control.service_audit_events a WHERE a.team_id=$1 AND a.service_id IN(SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2))
	)::text`, team, project).Scan(&facts)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func TestIntegrationPublisherGroupProvisioningExistingTenantIsolation(t *testing.T) {
	f, current := groupProvisioningFixture(t)
	ctx := t.Context()
	create := provisioningToken(t, f, ProvisioningCreate)
	request := provisionedGroupRequest(f, current, create.Credential)
	request.Creation.Name = "shared"
	own, err := f.d.CreateBoundPublisherGroup(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	const otherOwner = "tenant-b-owner"
	insertAuthorityIdentity(t, f.d, otherOwner, "", false, f.now)
	teamRequest := authorityTeamRequest(otherOwner)
	teamRequest.DisplayName = "tenant-b"
	otherTeam, err := f.d.CreateTeam(ctx, teamRequest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	otherProject, err := f.d.ApplyProjectConfiguration(ctx, ApplyProjectConfigurationRequest{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, ActorID: otherOwner, SourceFingerprint: f.r.SourceFingerprint, Configuration: current.Configuration, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	foreignRequest := request
	foreignRequest.TeamID, foreignRequest.ActorID, foreignRequest.Caller, foreignRequest.ExpectedRevision = otherTeam.ID, otherOwner, GroupCaller{}, otherProject.Revision
	foreign, err := f.d.CreateBoundPublisherGroup(ctx, foreignRequest)
	if err != nil {
		t.Fatal(err)
	}
	if otherTeam.ID == f.r.TeamID || foreign.ID == own.ID || foreign.Name != own.Name || foreign.From != own.From {
		t.Fatal("tenant fixture did not collide on project/template/group selectors")
	}
	enrollment, err := f.d.IssuePublisherGroupEnrollment(ctx, otherTeam.ID, f.r.ProjectKey, foreign.ID, otherOwner, 1, time.Minute, f.now)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemPublisherGroupEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	beforeOwn := provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)
	beforeForeign := provisioningProjectFacts(t, f.d, otherTeam.ID, f.r.ProjectKey)
	read := provisioningToken(t, f, ProvisioningRead)
	if _, err = f.d.ListManagedPublisherGroups(ctx, otherTeam.ID, f.r.ProjectKey, ProvisioningGroupCaller(read.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("listed another existing tenant", err)
	}
	update, enroll, revoke, retire := provisioningToken(t, f, ProvisioningUpdate), provisioningToken(t, f, ProvisioningEnroll), provisioningToken(t, f, ProvisioningRevokeMember), provisioningToken(t, f, ProvisioningRetire)
	for _, selector := range []string{foreign.ID, foreign.Name} {
		if _, err = f.d.GetManagedPublisherGroupForCaller(ctx, otherTeam.ID, f.r.ProjectKey, selector, ProvisioningGroupCaller(read.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("read another existing tenant", err)
		}
		mutation := GroupBindingMutationRequest{TeamID: otherTeam.ID, ProjectKey: f.r.ProjectKey, Group: selector, Caller: ProvisioningGroupCaller(update.Credential), ExpectedRevision: foreign.Revision, Bindings: PublisherGroupBindings{"boundapi": {Target: "192.0.2.99:3000"}}, Now: f.now}
		if _, err = f.d.UpdateBoundPublisherGroup(ctx, mutation); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("mutated another existing tenant", err)
		}
		if _, err = f.d.IssuePublisherGroupEnrollmentForCaller(ctx, otherTeam.ID, f.r.ProjectKey, selector, ProvisioningGroupCaller(enroll.Credential), 1, time.Minute, f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("enrolled another existing tenant", err)
		}
		if err = f.d.RevokePublisherGroupMemberForCaller(ctx, otherTeam.ID, f.r.ProjectKey, selector, member.PublisherIdentityID, ProvisioningGroupCaller(revoke.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("revoked another tenant's member", err)
		}
		mutation.Caller = ProvisioningGroupCaller(retire.Credential)
		if err = f.d.RetireBoundPublisherGroup(ctx, mutation); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("retired another existing tenant", err)
		}
	}
	foreignRequest.ActorID, foreignRequest.Caller = "", ProvisioningGroupCaller(create.Credential)
	if _, err = f.d.CreateBoundPublisherGroup(ctx, foreignRequest); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("replayed another tenant's creation key", err)
	}
	// selecting the original tenant must not let a foreign immutable ID bypass
	// the team predicate, even though all friendly selectors are identical.
	if _, err = f.d.GetManagedPublisherGroupForCaller(ctx, f.r.TeamID, f.r.ProjectKey, foreign.ID, ProvisioningGroupCaller(read.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
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
				f, current := groupProvisioningFixture(t)
				firstToken := provisioningToken(t, f, ProvisioningCreate)
				firstRequest := provisionedGroupRequest(f, current, firstToken.Credential)
				group, err := f.d.CreateBoundPublisherGroup(t.Context(), firstRequest)
				if err != nil {
					t.Fatal(err)
				}
				token := provisioningToken(t, f, operation)
				deadline := f.now.Add(10 * time.Second)
				if expiry == "token" {
					digest := sha256.Sum256([]byte(token.Credential))
					_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_sessions SET expires_at=$2 WHERE credential_digest=$1`, digest[:], deadline)
				} else {
					_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_grants SET expires_at=$2 WHERE id=$1`, f.grant.ID, deadline)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)
				gate, err := f.d.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err = gate.Exec(t.Context(), `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, group.Services[0].ServiceID); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				entered, done := make(chan time.Time, 1), make(chan error, 1)
				at := deadline.Add(-time.Second)
				createRequest := provisionedGroupRequest(f, AppliedProjectConfiguration{Revision: group.Revision}, token.Credential)
				createRequest.Creation.IdempotencyKey, createRequest.Now = "customer/blocked", at
				workers.Go(func() {
					entered <- time.Now()
					var e error
					if operation == ProvisioningCreate {
						_, e = f.d.CreateBoundPublisherGroup(ctx, createRequest)
					} else {
						_, e = f.d.UpdateBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Group: group.ID, Caller: ProvisioningGroupCaller(token.Credential), ExpectedRevision: group.Revision, Bindings: PublisherGroupBindings{"boundapi": {Target: "192.0.2.42:3001"}}, Now: at})
					}
					done <- e
				})
				pid := waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
				var query string
				if err = f.d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(query, "ORDER BY service.id FOR UPDATE OF service") {
					t.Fatal("mutation did not reach the service-lock boundary")
				}
				started := awaitIntegrationResult(t, ctx, entered)
				// the authorization clock started before this observed service
				// wait. its entire remaining lifetime elapsing after observation
				// is therefore a conservative bound, independent of scheduling.
				blockedAt := time.Now()
				timer := time.NewTimer(time.Until(blockedAt.Add(deadline.Sub(at))))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				releasedAt := at.Add(time.Since(started))
				if !releasedAt.After(deadline) {
					t.Fatal("service lock released before credential expiry")
				}
				if err = gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrMachineDenied) {
					t.Fatal("expired mutation committed after service-lock wait", err)
				}
				if !bytes.Equal(before, provisioningProjectFacts(t, f.d, f.r.TeamID, f.r.ProjectKey)) {
					t.Fatal("expired mutation changed bindings, revision, creation keys or audit")
				}
				if operation == ProvisioningCreate {
					// a keyed replay of an existing group must reauthorize too;
					// neither it nor the rolled-back allocation may return an ID.
					for _, replay := range []CreateBoundPublisherGroupRequest{firstRequest, createRequest} {
						replay.Caller, replay.Now = ProvisioningGroupCaller(token.Credential), releasedAt
						result, e := f.d.CreateBoundPublisherGroup(ctx, replay)
						if !errors.Is(e, ErrMachineDenied) || result.ID != "" {
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
