package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func managementRegistration(t *testing.T, scope DeploymentScope, now time.Time) (RegisterDeploymentCredentialRequest, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return RegisterDeploymentCredentialRequest{DeploymentScope: scope, Name: "customer-api", IdempotencyKey: "register", PublicKey: public, Permissions: map[string][]string{"manage": {"db"}}, AllDeployments: true, Lifetime: time.Hour, Now: now}, private
}

func managementAccess(t *testing.T, d *Database, credential DeploymentCredential, private ed25519.PrivateKey, now time.Time) PublisherAccess {
	t.Helper()
	assertion, err := publisherproof.Sign(credential.ClientID, credential.KeyID, credential.GrantID, publisherTestAudience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.ExchangePublisherAssertion(t.Context(), credential.ClientID, credential.GrantID, publisherTestAudience, assertion, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExchangePublisherAssertion(t.Context(), credential.ClientID, credential.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("management proof replay admitted", err)
	}
	if access.Until.After(credential.ExpiresAt) {
		t.Fatal("token outlived management approval")
	}
	return access
}

func TestIntegrationDeploymentManagementScopeAndRecovery(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "management_scope")
	_, setup := deploymentPublisherRequest(t, d, now)
	manager := setup.DeploymentScope
	production, err := d.GetDeployment(t.Context(), manager, "production")
	if err != nil {
		t.Fatal(err)
	}
	request, private := managementRegistration(t, manager, now)
	request.AllDeployments, request.DeploymentIDs = false, []string{production.ID}
	credential, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil || !reflect.DeepEqual(recovered, credential) {
		t.Fatal("registration changed identity, scope, or fixed deadline", recovered, err)
	}
	changed := request
	changed.Permissions = map[string][]string{"manage": {"web"}}
	if _, err = d.RegisterDeploymentCredential(t.Context(), changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("registration request key expanded intent", err)
	}
	access := managementAccess(t, d, credential, private, now)
	scope := DeploymentScope{TeamID: manager.TeamID, ProjectKey: manager.ProjectKey, AccessToken: access.Token, ActorID: "untrusted-actor"}
	selected, err := d.GetDeployment(t.Context(), scope, "production")
	if err != nil || len(selected.Services) != 1 || selected.Services["db"].ID != production.Services["db"].ID || len(selected.Targets) != 1 {
		t.Fatal("read exposed another service or trusted caller identity", selected, err)
	}
	page, err := d.ListDeployments(t.Context(), scope, "", 1)
	if err != nil || len(page) != 1 || page[0].ID != production.ID {
		t.Fatal("scoped pagination lost authorized deployment", page, err)
	}
	page, err = d.ListDeployments(t.Context(), scope, production.ID, 1)
	if err != nil || len(page) != 0 {
		t.Fatal("pagination included unapproved deployment", page, err)
	}
	if _, err = d.GetDeployment(t.Context(), scope, "staging"); !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatal("exact deployment scope followed another name", err)
	}
	foreign := scope
	foreign.ProjectKey = "another"
	if _, err = d.GetDeployment(t.Context(), foreign, production.ID); !errors.Is(err, ErrDeploymentNotFound) && !errors.Is(err, ErrDeploymentAccess) {
		t.Fatal("scope crossed projects", err)
	}
	if _, err = d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "create", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now}); !errors.Is(err, ErrDeploymentAccess) {
		t.Fatal("exact deployment grant covered future deployments", err)
	}
	if _, err = d.UpdateDeployment(t.Context(), UpdateDeploymentRequest{DeploymentScope: scope, Selector: production.ID, ExpectedRevision: production.Revision, Targets: map[string]DeploymentTarget{"web": {Address: "http://other.internal:3000"}}, Now: now}); !errors.Is(err, ErrDeploymentAccess) {
		t.Fatal("target update crossed fixed service allowlist", err)
	}
	if err = d.DeleteDeployment(t.Context(), scope, production.ID, production.Revision, now); !errors.Is(err, ErrDeploymentAccess) {
		t.Fatal("delete removed an unapproved service", err)
	}
	updated, err := d.UpdateDeployment(t.Context(), UpdateDeploymentRequest{DeploymentScope: scope, Selector: production.ID, ExpectedRevision: production.Revision, Targets: map[string]DeploymentTarget{"db": {Address: "updated.internal:5432"}}, Now: now})
	if err != nil || updated.Targets["db"].Address != "updated.internal:5432" || len(updated.Targets) != 1 {
		t.Fatal("approved target update failed", updated, err)
	}
	current, err := d.GetDeployment(t.Context(), manager, production.ID)
	if err != nil || !reflect.DeepEqual(current.Targets["web"], production.Targets["web"]) {
		t.Fatal("narrow mutation changed unrelated binding", current, err)
	}
	// management neither publishes a private service nor allocates public URLs.
	if _, err = d.GetServiceForPublisher(t.Context(), production.Services["db"].ID, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("management implied publish", err)
	}
	if _, err = d.AllocatePublisherPublicURL(t.Context(), access.PublisherIdentity, "allocation", "http://localhost:3000", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessRestricted}); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("management implied namespace allocation", err)
	}
	// explicit project-wide approval creates only the captured service names.
	request.AllDeployments, request.DeploymentIDs, request.IdempotencyKey = true, nil, "project-wide"
	broad, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	broadAccess := managementAccess(t, d, broad, private, now)
	scope.AccessToken = broadAccess.Token
	created, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "create", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "create", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now.Add(time.Second)})
	if err != nil || replayed.ID != created.ID {
		t.Fatal("lost creation reply allocated another deployment", replayed, err)
	}
	if err = d.DeleteDeployment(t.Context(), scope, created.ID, created.Revision, now); err != nil {
		t.Fatal("approved deployment deletion failed", err)
	}
}

func TestIntegrationDeploymentManagementPublisherIsolation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "management_publishers")
	r, setup := deploymentPublisherRequest(t, d, now)
	request, private := managementRegistration(t, setup.DeploymentScope, now)
	credential, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, d, credential, private, now)
	runtime := setup
	runtime.DeploymentScope = DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, AccessToken: access.Token}
	enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := d.CreateDeploymentPublisherEnrollment(t.Context(), runtime)
	if err != nil || !reflect.DeepEqual(enrollment, recovered) || enrollment.ExpiresAt.After(credential.ExpiresAt) {
		t.Fatal("setup recovery changed original authority or deadline", err)
	}
	// another credential issued by the same person has its own request-key space.
	request.IdempotencyKey = "second-credential"
	second, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	secondAccess := managementAccess(t, d, second, private, now)
	firstScope := runtime.DeploymentScope
	secondScope := firstScope
	secondScope.AccessToken = secondAccess.Token
	firstCreated, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: firstScope, Name: "first-customer", IdempotencyKey: "same-create-key", Targets: map[string]DeploymentTarget{"db": {Address: "first.internal:5432"}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	secondCreated, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: secondScope, Name: "second-customer", IdempotencyKey: "same-create-key", Targets: map[string]DeploymentTarget{"db": {Address: "second.internal:5432"}}, Now: now})
	if err != nil || firstCreated.ID == secondCreated.ID {
		t.Fatal("credentials from one issuer shared deployment recovery authority", err)
	}
	runtime.AccessToken = secondAccess.Token
	other, err := d.CreateDeploymentPublisherEnrollment(t.Context(), runtime)
	if err != nil || other.ID == enrollment.ID || other.Key == enrollment.Key {
		t.Fatal("another machine recovered the first machine's setup secret", err)
	}
	runtime.AccessToken = access.Token
	dbPublisher := enrollAppliedGroup(t, d, r, enrollment.PublisherGroupEnrollment, now)
	setup.IdempotencyKey, setup.Services = "broader", []string{"db", "web"}
	wideEnrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), setup)
	if err != nil {
		t.Fatal(err)
	}
	widePublisher := enrollAppliedGroup(t, d, r, wideEnrollment.PublisherGroupEnrollment, now)
	listed, err := d.ListDeploymentPublishers(t.Context(), runtime.DeploymentScope, "production", "", 1)
	if err != nil || len(listed) != 1 || listed[0].PublisherIdentityID != dbPublisher.member.PublisherIdentityID {
		t.Fatal("publisher page included broader approval", listed, err)
	}
	if _, err = d.GetDeploymentPublisher(t.Context(), runtime.DeploymentScope, "production", widePublisher.member.PublisherIdentityID); !errors.Is(err, ErrDeploymentPublisherNotFound) {
		t.Fatal("read exposed broader publisher", err)
	}
	if err = d.RevokeDeploymentPublisher(t.Context(), runtime.DeploymentScope, "production", widePublisher.member.PublisherIdentityID, now); !errors.Is(err, ErrDeploymentPublisherNotFound) {
		t.Fatal("revoked broader publisher", err)
	}
	if err = d.RevokeDeploymentPublisher(t.Context(), runtime.DeploymentScope, "production", dbPublisher.member.PublisherIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), widePublisher.lease.AccessToken, now); err != nil {
		t.Fatal("narrow revocation disturbed sibling", err)
	}
	// revoking the backend leaves separately enrolled publisher identities alone.
	if err = d.RevokePublisherIdentity(t.Context(), r.TeamID, credential.ClientID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetDeployment(t.Context(), runtime.DeploymentScope, "production"); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revoked backend retained management access", err)
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), widePublisher.lease.AccessToken, now); err != nil {
		t.Fatal("backend revocation retired an installed publisher", err)
	}
	if _, err = d.RegisterDeploymentCredential(t.Context(), request); err != nil {
		t.Fatal("independent credential lost registration", err)
	}
	request.IdempotencyKey = "register"
	if _, err = d.RegisterDeploymentCredential(t.Context(), request); !errors.Is(err, ErrDeploymentCredentialUnavailable) {
		t.Fatal("registration replay restored revoked authority", err)
	}
}

func TestIntegrationDeploymentManagementApprovalRetirement(t *testing.T) {
	for _, mutation := range []string{"protocol", "remove"} {
		t.Run(mutation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "management_retirement_"+mutation)
			r, setup := deploymentPublisherRequest(t, d, now)
			request, private := managementRegistration(t, setup.DeploymentScope, now)
			credential, err := d.RegisterDeploymentCredential(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			access := managementAccess(t, d, credential, private, now)
			saved := r.Configuration.Services["db"]
			r.ExpectedRevision = 1
			if mutation == "protocol" {
				next := saved
				next.Protocol = "mysql"
				r.Configuration.Services["db"] = next
			} else {
				delete(r.Configuration.Services, "db")
			}
			if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			r.ExpectedRevision, r.Configuration.Services["db"] = 2, saved
			if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("rollback restored retired service approval", err)
			}
			if _, err = d.RegisterDeploymentCredential(t.Context(), request); !errors.Is(err, ErrDeploymentCredentialUnavailable) {
				t.Fatal("registration replay restored retired scope", err)
			}
			request.IdempotencyKey = "explicit-new-approval"
			if _, err = d.RegisterDeploymentCredential(t.Context(), request); err != nil {
				t.Fatal("manager could not approve current declaration", err)
			}
		})
	}
}

func TestIntegrationDeploymentManagementSurvivesCreatorDeparture(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "management_departure")
	_, setup := deploymentPublisherRequest(t, d, now)
	request, private := managementRegistration(t, setup.DeploymentScope, now)
	credential, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, d, credential, private, now)
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at=$2,removed_by_identity_id=$3 WHERE team_id=$1 AND identity_id=$3`, request.TeamID, now, request.ActorID); err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, AccessToken: access.Token}
	created, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "create", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now})
	if err != nil {
		t.Fatal("team-owned authority depended on its departed issuer", err)
	}
	setup.DeploymentScope, setup.Selector, setup.IdempotencyKey = scope, created.ID, "setup-after-departure"
	if _, err = d.CreateDeploymentPublisherEnrollment(t.Context(), setup); err != nil {
		t.Fatal("team-owned setup depended on departed manager", err)
	}
	if err = d.DeleteDeployment(t.Context(), scope, created.ID, created.Revision, now); err != nil {
		t.Fatal("team-owned mutation depended on departed manager", err)
	}
}

func TestIntegrationDeploymentManagementRevocationDuringLockWait(t *testing.T) {
	for _, operation := range []string{"create", "recover", "get", "list", "update", "delete", "setup", "setup-recover", "publisher-list", "publisher-get", "publisher-revoke"} {
		t.Run(operation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "management_wait_"+operation)
			r, setup := deploymentPublisherRequest(t, d, now)
			request, private := managementRegistration(t, setup.DeploymentScope, now)
			credential, err := d.RegisterDeploymentCredential(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			access := managementAccess(t, d, credential, private, now)
			scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, AccessToken: access.Token}
			create := CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "create", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now}
			deployment, err := d.CreateDeployment(t.Context(), create)
			if err != nil {
				t.Fatal(err)
			}
			setup.DeploymentScope, setup.Selector = scope, deployment.ID
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), setup)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedGroup(t, d, r, enrollment.PublisherGroupEnrollment, now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockPublisherIdentity(ctx, credential.ClientID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch operation {
				case "create":
					create.Name, create.IdempotencyKey = "another", "another"
					_, err = d.CreateDeployment(ctx, create)
				case "recover":
					_, err = d.CreateDeployment(ctx, create)
				case "get":
					_, err = d.GetDeployment(ctx, scope, deployment.ID)
				case "list":
					_, err = d.ListDeployments(ctx, scope, "", 100)
				case "update":
					_, err = d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: deployment.ID, ExpectedRevision: deployment.Revision, Targets: map[string]DeploymentTarget{"db": {Address: "replacement.internal:5432"}}, Now: now})
				case "delete":
					err = d.DeleteDeployment(ctx, scope, deployment.ID, deployment.Revision, now)
				case "setup":
					setup.IdempotencyKey = "another"
					_, err = d.CreateDeploymentPublisherEnrollment(ctx, setup)
				case "setup-recover":
					_, err = d.CreateDeploymentPublisherEnrollment(ctx, setup)
				case "publisher-list":
					_, err = d.ListDeploymentPublishers(ctx, scope, deployment.ID, "", 100)
				case "publisher-get":
					_, err = d.GetDeploymentPublisher(ctx, scope, deployment.ID, replica.member.PublisherIdentityID)
				case "publisher-revoke":
					err = d.RevokeDeploymentPublisher(ctx, scope, deployment.ID, replica.member.PublisherIdentityID, now)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			if _, err = controlstatedb.New(gate).RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{ID: credential.ClientID, TeamID: r.TeamID, Now: timestamptz(now)}); err != nil {
				t.Fatal(err)
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("operation escaped revocation during its identity lock", err)
			}
			current, err := d.GetDeployment(ctx, request.DeploymentScope, deployment.ID)
			if err != nil || !reflect.DeepEqual(current, deployment) {
				t.Fatal("denied mutation changed deployment", current, err)
			}
			var count int
			if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_group_enrollments WHERE group_id=$1`, deployment.ID).Scan(&count); err != nil || count != 1 {
				t.Fatal("denied setup committed authority", count, err)
			}
			if _, err = d.GetPublisherGroupAssignments(ctx, replica.lease.AccessToken, now); err != nil {
				t.Fatal("denied revocation changed installed publisher", err)
			}
		})
	}
}

func TestIntegrationDeploymentManagementDeadlinesDuringLockWait(t *testing.T) {
	for _, boundary := range []string{"token", "grant", "assertion", "registration"} {
		t.Run(boundary, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "management_deadline_"+boundary)
			_, setup := deploymentPublisherRequest(t, d, now)
			request, private := managementRegistration(t, setup.DeploymentScope, now)
			credential, err := d.RegisterDeploymentCredential(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			at := now
			var access PublisherAccess
			if boundary == "token" {
				access = managementAccess(t, d, credential, private, now)
				at = access.Until.Add(-time.Second)
			}
			if boundary == "grant" {
				at = credential.ExpiresAt.Add(-time.Second)
				access = managementAccess(t, d, credential, private, at)
			}
			deployment, err := d.GetDeployment(t.Context(), request.DeploymentScope, "production")
			if err != nil {
				t.Fatal(err)
			}
			assertion, err := publisherproof.Sign(credential.ClientID, credential.KeyID, credential.GrantID, publisherTestAudience, private, now.Add(-59*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if boundary == "token" || boundary == "grant" {
				// audit work waits after resource and identity checks. the final
				// authorization check must still spend the same fixed deadline.
				_, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-audit:'||$1::text,0))`, request.TeamID)
			} else {
				_, err = controlstatedb.New(gate).LockPublisherIdentity(ctx, credential.ClientID)
			}
			if err != nil {
				t.Fatal(err)
			}
			done, entered := make(chan error, 1), make(chan time.Time, 1)
			workers.Go(func() {
				entered <- time.Now()
				var err error
				switch boundary {
				case "assertion":
					_, err = d.ExchangePublisherAssertion(ctx, credential.ClientID, credential.GrantID, publisherTestAudience, assertion, "", now)
				case "registration":
					request.Now = credential.ExpiresAt.Add(-time.Second)
					_, err = d.RegisterDeploymentCredential(ctx, request)
				default:
					_, err = d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, AccessToken: access.Token}, Selector: deployment.ID, ExpectedRevision: deployment.Revision, Targets: map[string]DeploymentTarget{"db": {Address: "late.internal:5432"}}, Now: at})
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			started := awaitIntegrationResult(t, ctx, entered)
			timer := time.NewTimer(time.Until(started.Add(time.Second + 50*time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			want := ErrPublisherIdentity
			if boundary == "registration" {
				want = ErrDeploymentCredentialUnavailable
			}
			if !errors.Is(err, want) {
				t.Fatal("database wait renewed expired authority", boundary, err)
			}
			current, err := d.GetDeployment(ctx, setup.DeploymentScope, deployment.ID)
			if err != nil || !reflect.DeepEqual(current, deployment) {
				t.Fatal("expired authority committed a target update", current, err)
			}
		})
	}
}

func TestIntegrationDeploymentManagementRegistrationRechecksManager(t *testing.T) {
	for _, operation := range []string{"register", "recover"} {
		t.Run(operation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "management_registration_"+operation)
			_, setup := deploymentPublisherRequest(t, d, now)
			request, _ := managementRegistration(t, setup.DeploymentScope, now)
			if operation == "recover" {
				if _, err := d.RegisterDeploymentCredential(t.Context(), request); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: request.TeamID, ProjectKey: request.ProjectKey}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			workers.Go(func() { _, err := d.RegisterDeploymentCredential(ctx, request); done <- err })
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			if _, err = gate.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, request.ActorID, now); err != nil {
				t.Fatal(err)
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("registration retained manager authority across wait", err)
			}
			var count int
			if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.deployment_management_grants WHERE team_id=$1`, request.TeamID).Scan(&count); err != nil || operation == "register" && count != 0 || operation == "recover" && count != 1 {
				t.Fatal("denied registration committed another credential", count, err)
			}
		})
	}
}

func TestIntegrationDeploymentManagementCombinedIdentityLockOrder(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "management_combined_lock_order")
	r, setup := deploymentPublisherRequest(t, d, now)
	request, private := managementRegistration(t, setup.DeploymentScope, now)
	credential, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, d, credential, private, now)
	production, err := d.GetDeployment(t.Context(), request.DeploymentScope, "production")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := d.IdentityContext(t.Context(), r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	var membership Membership
	for _, m := range identity.Memberships {
		if m.TeamID == r.TeamID {
			membership = m
		}
	}
	// an administrator, not the runtime token, independently approves publication
	// for the same signing identity. neither capability implies the other.
	_, err = d.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{PublisherIdentityID: credential.ClientID, Scope: PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: production.Services["web"].ID}, EditorID: r.ActorID, EditorMembershipID: membership.ID, PolicyRevision: uint64(membership.PolicyRevision), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, AccessToken: access.Token}
	customer, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "customer", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	q := controlstatedb.New(gate)
	if _, err = q.LockService(ctx, production.Services["web"].ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: customer.ID, ExpectedRevision: customer.Revision, Targets: map[string]DeploymentTarget{"db": {Address: "changed.internal:5432"}}, Now: now})
		done <- err
	})
	// model a publication worker that holds its parent, then needs its identity
	// and audit clock. management must not hold either while waiting for it.
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	if _, err = q.LockPublisherIdentity(ctx, credential.ClientID); err != nil {
		t.Fatal("management locked identity ahead of publication parents", err)
	}
	if _, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-audit:'||$1::text,0))`, r.TeamID); err != nil {
		t.Fatal("management locked audit ahead of publication parents", err)
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal("combined identity deadlocked management and publication", err)
	}
}
