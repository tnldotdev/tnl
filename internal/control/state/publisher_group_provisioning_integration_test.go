package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func groupProvisioningFixture(t *testing.T) (machineFixture, AppliedProjectConfiguration) {
	t.Helper()
	f := newMachineFixture(t, "signing_key")
	current, err := f.d.GetProjectConfiguration(t.Context(), f.r.TeamID, f.r.ProjectKey, f.r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	f.r.ExpectedRevision = current.Revision
	f.r.Configuration = current.Configuration
	service := f.r.Configuration.Services["api"]
	service.Access = &ProjectServiceAccess{Team: true}
	f.r.Configuration.Services["api"] = service
	f.r.Configuration.PublisherGroups["bound"] = ProjectPublisherGroup{Template: true}
	f.r.Configuration.Services["boundapi"] = ProjectServiceConfiguration{PublisherGroup: "bound", TargetBinding: "group", Access: &ProjectServiceAccess{Team: true}}
	current, err = f.d.ApplyProjectConfiguration(t.Context(), f.r)
	if err != nil {
		t.Fatal(err)
	}
	g := f.grant
	g.Templates = []string{"bound"}
	f.grant, err = f.d.CreateProvisioningGrant(t.Context(), g, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f, current
}

func provisioningToken(t *testing.T, f machineFixture, operation ProvisioningOperation) ProvisioningSession {
	t.Helper()
	session, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, operation, f.provisioningProof(t, operation), machineTestAudience, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func provisionedGroupRequest(f machineFixture, current AppliedProjectConfiguration, token string) CreateBoundPublisherGroupRequest {
	return CreateBoundPublisherGroupRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Caller: ProvisioningGroupCaller(token), ExpectedRevision: current.Revision, Now: f.now, Creation: PublisherGroupCreation{Template: "bound", IdempotencyKey: "customer/42", Bindings: PublisherGroupBindings{"boundapi": {Target: "192.0.2.42:3000"}}}}
}

func TestIntegrationPublisherGroupProvisioningScopeAndProvenance(t *testing.T) {
	f, current := groupProvisioningFixture(t)
	ctx := t.Context()
	create := provisioningToken(t, f, ProvisioningCreate)
	request := provisionedGroupRequest(f, current, create.Credential)
	resource, err := f.d.CreateBoundPublisherGroup(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.d.CreateBoundPublisherGroup(ctx, request)
	if err != nil || replayed.ID != resource.ID || replayed.Revision != resource.Revision {
		t.Fatal("create replay changed identity or revision", err)
	}
	service := resource.Services[0].ServiceID
	var machine, grant string
	var human *string
	if err = f.d.pool.QueryRow(ctx, `SELECT created_by_identity_id,created_by_machine_id,provisioning_grant_id FROM control.services WHERE id=$1`, service).Scan(&human, &machine, &grant); err != nil {
		t.Fatal(err)
	}
	if human != nil || machine != f.machine.ID || grant != f.grant.ID {
		t.Fatal("service creator borrowed a human identity")
	}
	var owners, teams int
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE kind='identity' OR auto_owner),count(*) FILTER(WHERE kind='team' AND created_by_machine_id=$2 AND provisioning_grant_id=$3) FROM control.visitor_grants WHERE service_id=$1`, service, f.machine.ID, f.grant.ID).Scan(&owners, &teams); err != nil {
		t.Fatal(err)
	}
	if owners != 0 || teams != 1 {
		t.Fatal("provisioning created personal access or lost explicit template policy", owners, teams)
	}
	read := provisioningToken(t, f, ProvisioningRead)
	groups, err := f.d.ListManagedPublisherGroups(ctx, f.r.TeamID, f.r.ProjectKey, ProvisioningGroupCaller(read.Credential), f.now)
	if err != nil || len(groups) != 1 || groups[0].ID != resource.ID {
		t.Fatal("template-filtered list", err, len(groups))
	}
	if _, err = f.d.GetManagedPublisherGroupForCaller(ctx, f.r.TeamID, f.r.ProjectKey, f.group, ProvisioningGroupCaller(read.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("other template read", err)
	}
	if _, err = f.d.GetManagedPublisherGroupForCaller(ctx, f.r.TeamID, "other", resource.ID, ProvisioningGroupCaller(read.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("cross-project read", err)
	}
	if _, err = f.d.GetProjectConfiguration(ctx, f.r.TeamID, f.r.ProjectKey, read.Credential); err == nil {
		t.Fatal("provisioning became full configuration access")
	}
	if _, err = f.d.AuthenticateAccessToken(ctx, credentials.AccessToken(read.Credential), f.now); err == nil {
		t.Fatal("provisioning became human authentication")
	}
	if _, err = f.d.ListWorkloadServices(ctx, read.Credential, f.now); err == nil {
		t.Fatal("provisioning became visitor access")
	}
	enroll := provisioningToken(t, f, ProvisioningEnroll)
	e, err := f.d.IssuePublisherGroupEnrollmentForCaller(ctx, f.r.TeamID, f.r.ProjectKey, resource.ID, ProvisioningGroupCaller(enroll.Credential), 1, time.Minute, f.now)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemPublisherGroupEnrollment(ctx, e.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.d.pool.QueryRow(ctx, `SELECT created_by_identity_id,created_by_machine_id,provisioning_grant_id FROM control.publisher_identities WHERE id=$1`, member.PublisherIdentityID).Scan(&human, &machine, &grant); err != nil {
		t.Fatal(err)
	}
	if human != nil || machine != f.machine.ID || grant != f.grant.ID {
		t.Fatal("enrolled identity lost actual issuer")
	}
	var exact int
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1 AND service_id=$2 AND created_by_identity_id IS NULL AND created_by_machine_id=$3 AND provisioning_grant_id=$4 AND revoked_at IS NULL`, member.PublisherIdentityID, service, f.machine.ID, f.grant.ID).Scan(&exact); err != nil {
		t.Fatal(err)
	}
	if exact != 1 {
		t.Fatal("enrollment lost exact service scope or provenance", exact)
	}
	update := provisioningToken(t, f, ProvisioningUpdate)
	wrong := GroupBindingMutationRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Group: f.group, Caller: ProvisioningGroupCaller(update.Credential), ExpectedRevision: resource.Revision, Now: f.now}
	if _, err = f.d.UpdateBoundPublisherGroup(ctx, wrong); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("updated another template", err)
	}
	wrong.Group, wrong.Caller = resource.ID, ProvisioningGroupCaller(read.Credential)
	if _, err = f.d.UpdateBoundPublisherGroup(ctx, wrong); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("read token authorized update", err)
	}
	updated, err := f.d.UpdateBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Group: resource.ID, Caller: ProvisioningGroupCaller(update.Credential), ExpectedRevision: resource.Revision, Bindings: PublisherGroupBindings{"boundapi": {Target: "192.0.2.42:3001"}}, Now: f.now})
	if err != nil || updated.Services[0].ServiceID != service {
		t.Fatal("update replaced service", err)
	}
	after, err := f.d.GetProjectConfiguration(ctx, f.r.TeamID, f.r.ProjectKey, f.r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(current.Configuration)
	afterJSON, _ := json.Marshal(after.Configuration)
	if !bytes.Equal(beforeJSON, afterJSON) || current.ConfigurationHash != after.ConfigurationHash {
		t.Fatal("machine edited saved declaration")
	}
	page, err := f.d.ListServiceAudit(ctx, f.r.TeamID, f.r.ActorID, ServiceAuditFilter{ServiceID: service, Limit: 256}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	seenJoin, seenApply := false, false
	for _, event := range page.Events {
		if event.EventType != "apply" && event.EventType != "publisher.join" {
			continue
		}
		if event.ActorIdentityID != "" || event.ActorMachineID != f.machine.ID || event.ActorProvisioningGrantID != f.grant.ID {
			t.Fatal("incorrect audit actor", event.EventType)
		}
		seenJoin = seenJoin || event.EventType == "publisher.join"
		seenApply = seenApply || event.EventType == "apply"
	}
	if !seenJoin || !seenApply {
		t.Fatal("missing machine management audit")
	}
	revoke := provisioningToken(t, f, ProvisioningRevokeMember)
	if err = f.d.RevokePublisherGroupMemberForCaller(ctx, f.r.TeamID, f.r.ProjectKey, resource.ID, member.PublisherIdentityID, ProvisioningGroupCaller(revoke.Credential), f.now); err != nil {
		t.Fatal(err)
	}
	retire := provisioningToken(t, f, ProvisioningRetire)
	if err = f.d.RetireBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Group: resource.ID, Caller: ProvisioningGroupCaller(retire.Credential), ExpectedRevision: updated.Revision, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.GetManagedPublisherGroupForCaller(ctx, f.r.TeamID, f.r.ProjectKey, resource.ID, ProvisioningGroupCaller(read.Credential), f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("retired group disclosed", err)
	}
}

func TestIntegrationPublisherGroupProvisioningDoesNotRepairUnrelatedGrants(t *testing.T) {
	f, current := groupProvisioningFixture(t)
	ctx := t.Context()
	// make an unrelated existing assignment deliberately absent. a scoped
	// mutation must not recreate it using the machine's authority.
	e, err := f.d.IssuePublisherGroupEnrollment(ctx, f.r.TeamID, f.r.ProjectKey, f.group, f.r.ActorID, 1, time.Minute, f.now)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemPublisherGroupEnrollment(ctx, e.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.pool.Exec(ctx, `DELETE FROM control.publisher_group_service_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.pool.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE publisher_identity_id=$1`, member.PublisherIdentityID, f.now); err != nil {
		t.Fatal(err)
	}
	// explicit team grants are independent too. remove their apply references
	// without changing the saved declaration to exercise the repair boundary.
	if _, err = f.d.pool.Exec(ctx, `UPDATE control.applied_project_services SET visitor_grant_id=NULL WHERE group_id=$1`, f.group); err != nil {
		t.Fatal(err)
	}
	var beforeGrants, beforeVisitors int
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID).Scan(&beforeGrants); err != nil {
		t.Fatal(err)
	}
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id IN(SELECT service_id FROM control.applied_project_services WHERE group_id=$1)`, f.group).Scan(&beforeVisitors); err != nil {
		t.Fatal(err)
	}
	token := provisioningToken(t, f, ProvisioningCreate)
	resource, err := f.d.CreateBoundPublisherGroup(ctx, provisionedGroupRequest(f, current, token.Credential))
	if err != nil {
		t.Fatal(err)
	}
	update := provisioningToken(t, f, ProvisioningUpdate)
	_, err = f.d.UpdateBoundPublisherGroup(ctx, GroupBindingMutationRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Group: resource.ID, Caller: ProvisioningGroupCaller(update.Credential), ExpectedRevision: resource.Revision, Bindings: PublisherGroupBindings{"boundapi": {Target: "192.0.2.42:3001"}}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	var grants, visitors, assignments int
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id IN(SELECT service_id FROM control.applied_project_services WHERE group_id=$1)`, f.group).Scan(&visitors); err != nil {
		t.Fatal(err)
	}
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_group_service_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID).Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	if grants != beforeGrants || visitors != beforeVisitors || assignments != 0 {
		t.Fatal("scoped mutation repaired unrelated grants", grants, visitors, assignments)
	}
}

func TestIntegrationPublisherGroupEnrollmentIssuerIsHistoricalProvenance(t *testing.T) {
	f, current := groupProvisioningFixture(t)
	ctx := t.Context()
	create := provisioningToken(t, f, ProvisioningCreate)
	group, err := f.d.CreateBoundPublisherGroup(ctx, provisionedGroupRequest(f, current, create.Credential))
	if err != nil {
		t.Fatal(err)
	}
	enroll := provisioningToken(t, f, ProvisioningEnroll)
	e, err := f.d.IssuePublisherGroupEnrollmentForCaller(ctx, f.r.TeamID, f.r.ProjectKey, group.ID, ProvisioningGroupCaller(enroll.Credential), 1, time.Minute, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.d.RevokeMachineIdentity(ctx, f.r.TeamID, f.machine.ID, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.pool.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemPublisherGroupEnrollment(ctx, e.Key, public, f.now)
	if err != nil {
		t.Fatal("issued enrollment borrowed current manager or machine permissions", err)
	}
	var machine string
	var human *string
	if err = f.d.pool.QueryRow(ctx, `SELECT created_by_identity_id,created_by_machine_id FROM control.publisher_identities WHERE id=$1`, member.PublisherIdentityID).Scan(&human, &machine); err != nil {
		t.Fatal(err)
	}
	if human != nil || machine != f.machine.ID {
		t.Fatal("historical machine issuer changed")
	}
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, group.ID, machineTestServer+"/v1/publisher-groups/lease", key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.d.AcquirePublisherGroupLease(ctx, member.PublisherIdentityID, group.ID, assertion, machineTestServer+"/v1/publisher-groups/lease", f.now)
	if err != nil {
		t.Fatal("native publisher borrowed issuer permissions", err)
	}
	assignments, err := f.d.GetPublisherGroupAssignments(ctx, lease.AccessToken, f.now)
	if err != nil || len(assignments.Services) != 1 || assignments.Services[0].ServiceID != group.Services[0].ServiceID {
		t.Fatal("native publisher lost exact group scope", err)
	}
}

func TestIntegrationPublisherGroupProvisioningReauthorizesReplay(t *testing.T) {
	for _, change := range []string{"grant", "identity", "rotation", "expiry", "operation", "template", "current-template"} {
		t.Run(change, func(t *testing.T) {
			f, current := groupProvisioningFixture(t)
			token := provisioningToken(t, f, ProvisioningCreate)
			request := provisionedGroupRequest(f, current, token.Credential)
			if _, err := f.d.CreateBoundPublisherGroup(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			var err error
			switch change {
			case "grant":
				err = f.d.RevokeProvisioningGrant(t.Context(), f.r.TeamID, f.grant.ID, f.r.ActorID, f.now)
			case "identity":
				err = f.d.RevokeMachineIdentity(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, f.now)
			case "rotation":
				public, _, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				err = f.d.RotateMachineIdentityKey(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, "replacement", public, f.now)
			case "expiry":
				request.Now = token.ExpiresAt
			case "operation":
				read := provisioningToken(t, f, ProvisioningRead)
				request.Caller = ProvisioningGroupCaller(read.Credential)
			case "template":
				request.Creation.Template = "production"
			case "current-template":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_grants SET templates=ARRAY['production'] WHERE id=$1`, f.grant.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.d.CreateBoundPublisherGroup(t.Context(), request); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("replay bypassed current authorization", err)
			}
		})
	}
}

func TestIntegrationPublisherGroupProvisioningEnrollmentBudget(t *testing.T) {
	f, current := groupProvisioningFixture(t)
	create := provisioningToken(t, f, ProvisioningCreate)
	group, err := f.d.CreateBoundPublisherGroup(t.Context(), provisionedGroupRequest(f, current, create.Credential))
	if err != nil {
		t.Fatal(err)
	}
	enroll := provisioningToken(t, f, ProvisioningEnroll)
	caller := ProvisioningGroupCaller(enroll.Credential)
	_, err = f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_test_enrollment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test enrollment failure'; END $$; CREATE TRIGGER reject_test_enrollment BEFORE INSERT ON control.publisher_group_enrollments FOR EACH ROW EXECUTE FUNCTION control.reject_test_enrollment()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.IssuePublisherGroupEnrollmentForCaller(t.Context(), f.r.TeamID, f.r.ProjectKey, group.ID, caller, 2, time.Minute, f.now); err == nil {
		t.Fatal("expected insertion failure")
	}
	var used int
	if err = f.d.pool.QueryRow(t.Context(), `SELECT enrollment_used FROM control.machine_provisioning_grants WHERE id=$1`, f.grant.ID).Scan(&used); err != nil || used != 0 {
		t.Fatal("failed insertion spent budget", used, err)
	}
	if _, err = f.d.pool.Exec(t.Context(), `DROP TRIGGER reject_test_enrollment ON control.publisher_group_enrollments; DROP FUNCTION control.reject_test_enrollment()`); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, workers)
	for range workers {
		wg.Go(func() {
			<-start
			_, err := f.d.IssuePublisherGroupEnrollmentForCaller(t.Context(), f.r.TeamID, f.r.ProjectKey, group.ID, caller, 1, time.Minute, f.now)
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrMachineDenied) {
			t.Fatal(err)
		}
	}
	if success != f.grant.EnrollmentBudget {
		t.Fatal("concurrent issuance did not enforce budget", success)
	}
	if err = f.d.pool.QueryRow(t.Context(), `SELECT enrollment_used FROM control.machine_provisioning_grants WHERE id=$1`, f.grant.ID).Scan(&used); err != nil || used != success {
		t.Fatal("budget not atomic with issuance", used, err)
	}
}

func TestIntegrationPublisherGroupProvisioningMutationRetainsAuthority(t *testing.T) {
	f, current := groupProvisioningFixture(t)
	create := provisioningToken(t, f, ProvisioningCreate)
	group, err := f.d.CreateBoundPublisherGroup(t.Context(), provisionedGroupRequest(f, current, create.Credential))
	if err != nil {
		t.Fatal(err)
	}
	update := provisioningToken(t, f, ProvisioningUpdate)
	blocker, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, blocker)
	if _, err = blocker.Exec(t.Context(), `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, group.Services[0].ServiceID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	mutated := make(chan error, 1)
	request := GroupBindingMutationRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Group: group.ID, Caller: ProvisioningGroupCaller(update.Credential), ExpectedRevision: group.Revision, Bindings: PublisherGroupBindings{"boundapi": {Target: "192.0.2.42:3001"}}, Now: f.now}
	workers.Go(func() { _, e := f.d.UpdateBoundPublisherGroup(ctx, request); mutated <- e })
	mutationPID := waitForPostgresBlock(t, ctx, f.d, int32(blocker.Conn().PgConn().PID()), mutated)
	revoked := make(chan error, 1)
	workers.Go(func() { revoked <- f.d.RevokeProvisioningGrant(ctx, f.r.TeamID, f.grant.ID, f.r.ActorID, f.now) })
	waitForPostgresBlock(t, ctx, f.d, mutationPID, revoked)
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, mutated); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, revoked); err != nil {
		t.Fatal(err)
	}
	request.ExpectedRevision++
	if _, err = f.d.UpdateBoundPublisherGroup(ctx, request); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("revoked no-op update retained authority", err)
	}
}
