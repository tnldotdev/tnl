package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

// this fixture deliberately uses the canonical environment operations, not the
// retired project/template fixture shared by older machine identity tests.
type provisioningEnvironmentFixture struct {
	*environmentPublisherGrantFixture
	machine    MachineIdentity
	grant      ProvisioningGrant
	key        ed25519.PrivateKey
	collection Collection
}

func newProvisioningEnvironmentFixture(t *testing.T) provisioningEnvironmentFixture {
	t.Helper()
	base := newEnvironmentPublisherGrantFixture(t)
	collection, err := base.d.CreateCollection(t.Context(), CreateCollectionRequest{TeamID: base.r.TeamID, ProjectKey: base.r.ProjectKey, ActorID: base.r.ActorID, Name: "customers", DefaultDefinitionRevision: base.environment.AppliedDefinitionRevision, Now: base.now})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := base.d.RegisterMachineIdentity(t.Context(), RegisterMachineRequest{TeamID: base.r.TeamID, ActorID: base.r.ActorID, Name: "onboarding", ProofKind: "signing_key", KeyID: "first", PublicKey: public}, base.now)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := base.d.CreateProvisioningGrant(t.Context(), ProvisioningGrant{MachineID: machine.ID, TeamID: base.r.TeamID, ProjectKey: base.r.ProjectKey, Scope: EnvironmentPermissionScope{CollectionID: collection.ID, IncludeFutureEnvironments: new(true)}, Services: []string{"api"}, Operations: []ProvisioningOperation{ProvisioningCreate, ProvisioningRead, ProvisioningUpdate, ProvisioningEnroll, ProvisioningRevokeMember, ProvisioningRetire}, MaxEnrollmentMembers: 2, MaxEnrollmentSeconds: 600, EnrollmentBudget: 3, ExpiresAt: base.now.Add(time.Hour)}, base.r.ActorID, base.now)
	if err != nil {
		t.Fatal(err)
	}
	return provisioningEnvironmentFixture{environmentPublisherGrantFixture: base, machine: machine, grant: grant, key: key, collection: collection}
}

func (f provisioningEnvironmentFixture) authority(t *testing.T, operation ProvisioningOperation) (EnvironmentPublisherManager, ProvisioningSession) {
	t.Helper()
	const audience = "https://control.example/v1/provisioning-sessions/exchange"
	proof, err := publisherproof.Sign(f.machine.ID, "first", machineproof.Provisioning(f.grant.ID, string(operation)), audience, f.key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, operation, MachineProof{Assertion: proof}, audience, f.now)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	return manager, session
}

func (f provisioningEnvironmentFixture) request(t *testing.T) CreateEnvironmentRequest {
	t.Helper()
	manager, _ := f.authority(t, ProvisioningCreate)
	return CreateEnvironmentRequest{Manager: manager, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, SourceFingerprint: f.r.SourceFingerprint, Name: "customer-42", IdempotencyKey: "customer/42", CollectionID: f.collection.ID, ExpectedCollectionRevision: f.collection.MutationRevision, Targets: EnvironmentTargets{"api": {Address: "192.0.2.42:3000"}}, Now: f.now}
}

func (f provisioningEnvironmentFixture) create(t *testing.T) Environment {
	t.Helper()
	environment, err := f.d.CreateEnvironment(t.Context(), f.request(t))
	if err != nil {
		t.Fatal(err)
	}
	return environment
}

func (f provisioningEnvironmentFixture) enrollment(t *testing.T, environment Environment, key string, members int) IssueEnvironmentPublisherEnrollmentRequest {
	t.Helper()
	manager, _ := f.authority(t, ProvisioningEnroll)
	return IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: EnvironmentPublisherSelection{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentID: environment.ID, Manager: manager}, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: members, Lifetime: time.Minute, IdempotencyKey: key, Now: f.now}
}

func TestIntegrationPublisherGroupProvisioningScopeAndProvenance(t *testing.T) {
	f := newProvisioningEnvironmentFixture(t)
	ctx := t.Context()
	request := f.request(t)
	resource, err := f.d.CreateEnvironment(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.d.CreateEnvironment(ctx, request)
	if err != nil || replayed.ID != resource.ID || replayed.MutationRevision != resource.MutationRevision {
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
	var visitors int
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1`, service).Scan(&visitors); err != nil || visitors != 0 {
		t.Fatal("definition or provisioning minted visitor access", visitors, err)
	}
	read, session := f.authority(t, ProvisioningRead)
	environments, err := f.d.InspectEnvironments(ctx, f.r.TeamID, f.r.ProjectKey, read)
	if err != nil || len(environments) != 1 || environments[0].ID != resource.ID {
		t.Fatal("collection-filtered list", err, environments)
	}
	if _, err = f.d.InspectEnvironment(ctx, f.r.TeamID, f.r.ProjectKey, f.environment.ID, read); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("other collection read", err)
	}
	if _, err = f.d.InspectEnvironment(ctx, f.r.TeamID, "other", resource.ID, read); err == nil {
		t.Fatal("cross-project read accepted")
	}
	if _, err = f.d.AuthenticateAccessToken(ctx, credentials.AccessToken(session.Credential), f.now); err == nil {
		t.Fatal("provisioning became human authentication")
	}
	if _, err = f.d.ListWorkloadServices(ctx, session.Credential, f.now); err == nil {
		t.Fatal("provisioning became visitor access")
	}
	e, err := f.d.IssueEnvironmentPublisherEnrollment(ctx, f.enrollment(t, resource, "first", 1))
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemEnvironmentPublisherEnrollment(ctx, e.Key, public, f.now)
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
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1 AND service_id=$2 AND created_by_identity_id IS NULL AND created_by_machine_id=$3 AND provisioning_grant_id=$4 AND revoked_at IS NULL`, member.PublisherIdentityID, service, f.machine.ID, f.grant.ID).Scan(&exact); err != nil || exact != 1 {
		t.Fatal("enrollment lost exact scope or provenance", exact, err)
	}
	update, _ := f.authority(t, ProvisioningUpdate)
	wrong := ApplyEnvironmentRequest{Manager: update, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision}, Now: f.now}
	if _, err = f.d.ApplyEnvironment(ctx, wrong); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("updated outside collection", err)
	}
	wrong.EnvironmentID, wrong.ExpectedRevision, wrong.Manager = resource.ID, resource.MutationRevision, read
	if _, err = f.d.ApplyEnvironment(ctx, wrong); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("read token authorized update", err)
	}
	wrong.Manager, wrong.Targets = update, EnvironmentTargets{"api": {Address: "192.0.2.42:3001"}}
	updated, err := f.d.ApplyEnvironment(ctx, wrong)
	if err != nil || updated.Services[0].ServiceID != service {
		t.Fatal("update replaced service", err)
	}
	collection, err := f.d.GetCollection(ctx, f.r.TeamID, f.r.ProjectKey, f.collection.ID, f.r.ActorID)
	if err != nil || !reflect.DeepEqual(collection, f.collection) {
		t.Fatal("machine edited saved collection/default", err)
	}
	definition, err := loadServiceDefinitionForProvisioningTest(t, f, resource.AppliedDefinitionRevision)
	if err != nil || len(definition.Definition.Services) != 1 || definition.Definition.Services["api"].Protocol != "http" {
		t.Fatal("machine edited immutable definition", err)
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
	revoke, _ := f.authority(t, ProvisioningRevokeMember)
	if err = f.d.RevokeEnvironmentPublisher(ctx, EnvironmentPublisherSelection{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentID: resource.ID, Manager: revoke}, member.PublisherIdentityID, f.now); err != nil {
		t.Fatal(err)
	}
	retire, _ := f.authority(t, ProvisioningRetire)
	if err = f.d.RetireEnvironment(ctx, RetireEnvironmentRequest{Manager: retire, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentID: resource.ID, ExpectedRevision: updated.MutationRevision, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.InspectEnvironment(ctx, f.r.TeamID, f.r.ProjectKey, resource.ID, read); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("retired environment disclosed", err)
	}
}

func loadServiceDefinitionForProvisioningTest(t *testing.T, f provisioningEnvironmentFixture, revision int64) (ServiceDefinitionRevision, error) {
	t.Helper()
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		return ServiceDefinitionRevision{}, err
	}
	defer rollbackTestTransaction(t, tx)
	return loadServiceDefinition(t.Context(), tx, f.r.TeamID, f.r.ProjectKey, revision)
}

func TestIntegrationPublisherGroupProvisioningDoesNotRepairUnrelatedGrants(t *testing.T) {
	f := newProvisioningEnvironmentFixture(t)
	ctx := t.Context()
	member := f.publisher.member
	if _, err := f.d.pool.Exec(ctx, `DELETE FROM control.publisher_group_service_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.pool.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE publisher_identity_id=$1`, member.PublisherIdentityID, f.now); err != nil {
		t.Fatal(err)
	}
	var beforeGrants, beforeVisitors int
	if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID).Scan(&beforeGrants); err != nil {
		t.Fatal(err)
	}
	if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1`, f.environment.Services[0].ServiceID).Scan(&beforeVisitors); err != nil {
		t.Fatal(err)
	}
	resource := f.create(t)
	update, _ := f.authority(t, ProvisioningUpdate)
	_, err := f.d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{Manager: update, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentApplication: EnvironmentApplication{EnvironmentID: resource.ID, ExpectedRevision: resource.MutationRevision, DefinitionRevision: resource.AppliedDefinitionRevision, Targets: EnvironmentTargets{"api": {Address: "192.0.2.42:3001"}}}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	var grants, visitors, assignments int
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, member.PublisherIdentityID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err = f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1`, f.environment.Services[0].ServiceID).Scan(&visitors); err != nil {
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
	f := newProvisioningEnvironmentFixture(t)
	ctx := t.Context()
	environment := f.create(t)
	e, err := f.d.IssueEnvironmentPublisherEnrollment(ctx, f.enrollment(t, environment, "first", 2))
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.d.RedeemEnvironmentPublisherEnrollment(ctx, e.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.d.RevokeMachineIdentity(ctx, f.r.TeamID, f.machine.ID, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.pool.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	var machine string
	var human *string
	if err = f.d.pool.QueryRow(ctx, `SELECT created_by_identity_id,created_by_machine_id FROM control.publisher_identities WHERE id=$1`, member.PublisherIdentityID).Scan(&human, &machine); err != nil || human != nil || machine != f.machine.ID {
		t.Fatal("historical machine issuer changed", err)
	}
	const audience = "https://control.example/v1/environment-publishers/lease"
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, environment.ID, audience, key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.d.AcquireEnvironmentPublisherLease(ctx, member.PublisherIdentityID, environment.ID, assertion, audience, f.now)
	if err != nil {
		t.Fatal("installed publisher borrowed issuer permissions", err)
	}
	assignments, err := f.d.GetEnvironmentPublisherAssignments(ctx, lease.AccessToken, f.now)
	if err != nil || len(assignments.Services) != 1 || assignments.Services[0].ServiceID != environment.Services[0].ServiceID {
		t.Fatal("publisher lost exact environment scope", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.RedeemEnvironmentPublisherEnrollment(ctx, e.Key, other, f.now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("pending enrollment ignored revoked issuer", err)
	}
}

func TestIntegrationPublisherGroupProvisioningReauthorizesReplay(t *testing.T) {
	for _, change := range []string{"grant", "identity", "rotation", "expiry", "operation", "collection", "current-services"} {
		t.Run(change, func(t *testing.T) {
			f := newProvisioningEnvironmentFixture(t)
			request := f.request(t)
			if _, err := f.d.CreateEnvironment(t.Context(), request); err != nil {
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
				digest := sha256.Sum256([]byte(request.Manager.provisioningCredential))
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_sessions SET created_at=$2,expires_at=$3 WHERE credential_digest=$1`, digest[:], time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))
			case "operation":
				request.Manager, _ = f.authority(t, ProvisioningRead)
			case "collection":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_grants SET collection_id=NULL,include_future_environments=false,environment_ids=ARRAY[$2] WHERE id=$1`, f.grant.ID, f.environment.ID)
			case "current-services":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_grants SET services=ARRAY['other'] WHERE id=$1`, f.grant.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.d.CreateEnvironment(t.Context(), request); err == nil {
				t.Fatal("replay bypassed current authorization")
			}
		})
	}
}

func TestIntegrationPublisherGroupProvisioningEnrollmentBudget(t *testing.T) {
	f := newProvisioningEnvironmentFixture(t)
	environment := f.create(t)
	request := f.enrollment(t, environment, "failure", 2)
	_, err := f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_test_enrollment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test enrollment failure'; END $$; CREATE TRIGGER reject_test_enrollment BEFORE INSERT ON control.publisher_group_enrollments FOR EACH ROW EXECUTE FUNCTION control.reject_test_enrollment()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.IssueEnvironmentPublisherEnrollment(t.Context(), request); err == nil {
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
	for i := range workers {
		wg.Go(func() {
			<-start
			r := request
			r.IdempotencyKey, r.MaxMembers = fmt.Sprintf("concurrent/%d", i), 1
			_, err := f.d.IssueEnvironmentPublisherEnrollment(t.Context(), r)
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
	f := newProvisioningEnvironmentFixture(t)
	environment := f.create(t)
	manager, _ := f.authority(t, ProvisioningUpdate)
	blocker, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, blocker)
	if _, err = blocker.Exec(t.Context(), `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, environment.Services[0].ServiceID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	mutated := make(chan error, 1)
	request := ApplyEnvironmentRequest{Manager: manager, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: environment.MutationRevision, DefinitionRevision: environment.AppliedDefinitionRevision, Targets: EnvironmentTargets{"api": {Address: "192.0.2.42:3001"}}}, Now: f.now}
	workers.Go(func() { _, e := f.d.ApplyEnvironment(ctx, request); mutated <- e })
	pid := waitForPostgresBlock(t, ctx, f.d, int32(blocker.Conn().PgConn().PID()), mutated)
	revoked := make(chan error, 1)
	workers.Go(func() { revoked <- f.d.RevokeProvisioningGrant(ctx, f.r.TeamID, f.grant.ID, f.r.ActorID, f.now) })
	waitForPostgresBlock(t, ctx, f.d, pid, revoked)
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
	if _, err = f.d.ApplyEnvironment(ctx, request); err == nil {
		t.Fatal("revoked no-op update retained authority")
	}
}
