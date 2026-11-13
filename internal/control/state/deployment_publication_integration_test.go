package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

type deploymentPublicationFixture struct {
	d                   *Database
	now                 time.Time
	project             ApplyProjectConfigurationRequest
	production, staging Deployment
}

func newDeploymentPublicationFixture(t *testing.T) deploymentPublicationFixture {
	t.Helper()
	d, now := newControlStateIntegrationDatabase(t, "deployment_publication")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"web": {PublisherGroup: "production", Target: "app", PublicURL: &ProjectServicePublicURL{Access: &ProjectPublicAccess{Mode: "anonymous"}}},
		"api": {PublisherGroup: "production", Target: "app", PublicURL: &ProjectServicePublicURL{}},
		"db":  {PublisherGroup: "production", Protocol: "postgres", Target: "database.internal:5432"},
	}}
	r = selectedProjectRequest(r, "production")
	first, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	production, err := d.GetDeployment(t.Context(), scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = first.Revision
	stage := deploymentProjectRequest(r, "staging")
	// deploymentProjectRequest filters groups; retain explicit staging bindings.
	stage.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"web": {PublisherGroup: "staging", Target: "app", PublicURL: &ProjectServicePublicURL{}},
	}}
	if _, err = d.ApplyProjectConfiguration(t.Context(), stage); err != nil {
		t.Fatal(err)
	}
	staging, err := d.GetDeployment(t.Context(), scope, "staging")
	if err != nil {
		t.Fatal(err)
	}
	return deploymentPublicationFixture{d, now, r, production, staging}
}

func (f deploymentPublicationFixture) approve(t *testing.T, names map[string][]string, temporary string) (RegisterDeploymentCredentialRequest, DeploymentCredential, PublisherAccess, ed25519.PrivateKey) {
	t.Helper()
	r, key := managementRegistration(t, DeploymentScope{TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, ActorID: f.project.ActorID}, f.now)
	r.IdempotencyKey, _ = opaqueid.New(opaqueid.RequestPrefix)
	r.Permissions, r.TemporaryPublication = names, temporary
	r.AllDeployments, r.DeploymentIDs = false, []string{f.production.ID}
	credential, err := f.d.RegisterDeploymentCredential(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, f.d, credential, key, f.now)
	return r, credential, access, key
}

func (f deploymentPublicationFixture) scope(access PublisherAccess) DeploymentScope {
	return DeploymentScope{TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, AccessToken: access.Token}
}

func (f deploymentPublicationFixture) allocation(t *testing.T, access PublisherAccess) AllocateDeploymentPublicationRequest {
	t.Helper()
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return AllocateDeploymentPublicationRequest{DeploymentScope: f.scope(access), Deployment: f.production.ID, Invocation: invocation, Target: "http://127.0.0.1:3000", Options: PublisherPublicURLOptions{AccessMode: VisitorAccessRestricted}, Now: f.now}
}

func TestIntegrationDeploymentPublicationIndependentApproval(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	for _, capability := range []string{"manage", "connect", "publish"} {
		t.Run(capability, func(t *testing.T) {
			r, credential, access, _ := f.approve(t, map[string][]string{capability: {"web"}}, "")
			recovered, err := f.d.RegisterDeploymentCredential(t.Context(), r)
			if err != nil || !reflect.DeepEqual(credential, recovered) {
				t.Fatal("registration recovery changed independent approval", err)
			}
			publication, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now)
			if capability != "publish" {
				if err == nil || publication.PublicURL.ID != "" {
					t.Fatal("another capability implied publishing")
				}
				return
			}
			if err != nil || publication.PublicURL.ID != f.production.Services["web"].ID || publication.PublicURL.AccessMode != VisitorAccessAnonymous {
				t.Fatal("named publication lost saved policy", err)
			}
			if _, err := f.d.GetDeployment(t.Context(), f.scope(access), "production"); !errors.Is(err, ErrDeploymentAccess) {
				t.Fatal("publish implied management", err)
			}
			if err := f.d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err := f.d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: f.production.Services["db"].ID}, RegisteredKeyTokenSource{Credential: access.Token}, f.now); err == nil {
				t.Fatal("publish implied connection")
			}
			for _, selection := range [][2]string{{"production", "api"}, {"staging", "web"}, {"production", "db"}} {
				if result, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), selection[0], selection[1], f.now); err == nil || result.PublicURL.ID != "" {
					t.Fatal("publication escaped service/deployment scope")
				}
			}
			if _, err := f.d.AllocateDeploymentPublication(t.Context(), f.allocation(t, access)); !errors.Is(err, ErrDeploymentAccess) {
				t.Fatal("named publication implied allocation", err)
			}
			changed := r
			changed.TemporaryPublication = "anonymous"
			if _, err := f.d.RegisterDeploymentCredential(t.Context(), changed); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("registration retry expanded allocation approval", err)
			}
		})
	}
	r, _ := managementRegistration(t, DeploymentScope{TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, ActorID: f.project.ActorID}, f.now)
	r.Permissions = map[string][]string{"publish": {"db"}}
	if _, err := f.d.RegisterDeploymentCredential(t.Context(), r); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("publication approved a database protocol", err)
	}
}

func TestIntegrationDeploymentPublicationTemporaryRecoveryAndCleanup(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	ctx := t.Context()
	r, credential, access, _ := f.approve(t, nil, "restricted")
	if credential.Permissions.Publish == nil || credential.Permissions.Publish.Temporary != "restricted" || len(credential.Permissions.Publish.Services) != 0 {
		t.Fatal("temporary-only approval invented a service")
	}
	request := f.allocation(t, access)
	first, err := f.d.AllocateDeploymentPublication(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	group, err := controlstatedb.New(f.d.pool).LockProjectPublisherGroup(ctx, f.production.ID)
	if err != nil {
		t.Fatal(err)
	}
	label, namespace, found := strings.Cut(first.CanonicalHostname, ".")
	if !found || len(label) != 26 || namespace != group.Namespace || !first.Ephemeral || first.MembershipID != "" || first.AccessMode != VisitorAccessRestricted || first.PublicURLScope != PublicURLScopeShared {
		t.Fatal("allocation borrowed a saved policy, developer namespace, or wrong lifetime")
	}
	recovered, err := f.d.AllocateDeploymentPublication(ctx, request)
	if err != nil || !reflect.DeepEqual(first, recovered) {
		t.Fatal("lost allocation reply changed original URL/deadline", err)
	}
	request.Target = "http://127.0.0.1:4000"
	if _, err = f.d.AllocateDeploymentPublication(ctx, request); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatal("retry changed its target", err)
	}
	request = f.allocation(t, access)
	request.Options.AccessMode = VisitorAccessAnonymous
	if _, err = f.d.AllocateDeploymentPublication(ctx, request); !errors.Is(err, ErrDeploymentAccess) {
		t.Fatal("restricted approval allowed anonymous allocation", err)
	}
	_, _, other, _ := f.approve(t, nil, "restricted")
	if owns, err := f.d.PublisherMayStartRun(ctx, other.PublisherIdentity, first.ID); err != nil || owns {
		t.Fatal("another credential adopted the allocation", err)
	}
	if err := f.d.DeleteAuthorizedPublicURL(ctx, AuthorizedPublicURLDeleteRequest{PublicURLID: first.ID, TeamID: r.TeamID, ActingIdentityID: r.ActorID, PublisherIdentityID: access.ID, PublisherGrantID: access.GrantID, ExpectedMutationRevision: first.MutationRevision}, f.now); err != nil {
		t.Fatal(err)
	}
	request = f.allocation(t, access)
	request.Invocation = controlAllocationInvocation(t, f.d, first.ID)
	if _, err = f.d.AllocateDeploymentPublication(ctx, request); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatal("retry resurrected a deleted allocation", err)
	}
	fresh, err := f.d.AllocateDeploymentPublication(ctx, f.allocation(t, access))
	if err != nil || fresh.ID == first.ID || fresh.CanonicalHostname == first.CanonicalHostname {
		t.Fatal("fresh invocation reused an allocation", err)
	}
	if err = f.d.DeleteDeployment(ctx, r.DeploymentScope, f.production.ID, f.production.Revision, f.now); err != nil {
		t.Fatal(err)
	}
	u, err := controlstatedb.New(f.d.pool).LockPublicURLForRun(ctx, fresh.ID)
	if err != nil || u.LifecycleState != "deleted" {
		t.Fatal("deployment deletion retained its temporary URL", err)
	}
	if _, err = f.d.AllocateDeploymentPublication(ctx, f.allocation(t, access)); err == nil {
		t.Fatal("deleted deployment retained allocation authority")
	}
}

func controlAllocationInvocation(t *testing.T, d *Database, id string) string {
	t.Helper()
	a, err := controlstatedb.New(d.pool).GetPublisherAllocation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a.InvocationID
}

func TestIntegrationDeploymentPublicationSignedRunAndRevocation(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	_, _, _, _ = publishRunPrerequisitesInDatabase(t, f.d, f.now, nil)
	_, credential, access, key := f.approve(t, map[string][]string{"publish": {"web"}}, "anonymous")
	until := f.now.Add(10 * time.Second)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, credential.GrantID, until); err != nil {
		t.Fatal(err)
	}
	for _, temporary := range []bool{false, true} {
		var u PublicURL
		if temporary {
			r := f.allocation(t, access)
			r.Options.AccessMode = VisitorAccessAnonymous
			var err error
			u, err = f.d.AllocateDeploymentPublication(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			result, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now)
			if err != nil {
				t.Fatal(err)
			}
			u = result.PublicURL
		}
		request := reviewRunRequest(t, f.d, access.PublisherIdentity, key, u, "signed-deployment-"+u.ID)
		run, err := f.d.CreatePublishRun(t.Context(), request, f.now, 30*time.Second, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := f.d.CreatePublishRun(t.Context(), request, f.now, 30*time.Second, time.Minute)
		if err != nil || recovered.PublishRunID != run.PublishRunID || recovered.PublishRunToken != run.PublishRunToken {
			t.Fatal("signed run recovery changed authority", err)
		}
		if !run.ExpiresAt.Equal(until) {
			t.Fatal("run outlived approval")
		}
		heartbeat, err := f.d.HeartbeatPublishRun(t.Context(), PublishRunAuthentication{PublishRunID: run.PublishRunID, PublicURLID: u.ID, PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken}, f.now.Add(time.Second), time.Minute, time.Minute)
		if err != nil || !heartbeat.ExpiresAt.Equal(until) {
			t.Fatal("renewal extended the fixed grant deadline", err)
		}
	}
	if err := f.d.RevokePublisherIdentity(t.Context(), f.project.TeamID, credential.ClientID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publish_runs WHERE publisher_identity_id=$1 AND closed_at IS NULL`, credential.ClientID).Scan(&open); err != nil || open != 0 {
		t.Fatal("revocation retained active publication", err)
	}
}

func TestIntegrationDeploymentPublicationRetirementAndCrashExpiry(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	r, _, access, _ := f.approve(t, map[string][]string{"publish": {"web"}}, "restricted")
	request := f.allocation(t, access)
	u, err := f.d.AllocateDeploymentPublication(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.pool.Exec(t.Context(), `UPDATE control.domains SET state='releasing' WHERE id=$1`, u.DomainID); err != nil {
		t.Fatal(err)
	}
	if result, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now); !errors.Is(err, ErrDeploymentAccess) || result.PublicURL.ID != "" {
		t.Fatal("publication retained a releasing domain", err)
	}
	if _, err = f.d.pool.Exec(t.Context(), `UPDATE control.domains SET state='ready' WHERE id=$1`, u.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.DeleteExpiredEphemeralPublicURLs(t.Context(), u.ExpiresAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.AllocateDeploymentPublication(t.Context(), request); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatal("crash expiry resurrected an allocation", err)
	}
	for _, protocol := range []string{"tcp", "http"} {
		if _, err = f.d.pool.Exec(t.Context(), `UPDATE control.project_services SET protocol=$3 WHERE team_id=$1 AND project_key=$2 AND name='web'`, r.TeamID, r.ProjectKey, protocol); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("protocol rollback restored publication approval", err)
	}
	if _, err = f.d.RegisterDeploymentCredential(t.Context(), r); !errors.Is(err, ErrDeploymentCredentialUnavailable) {
		t.Fatal("registration replay restored retired approval", err)
	}
}

func TestIntegrationDeploymentPublicationAuthorityAfterLockWait(t *testing.T) {
	for _, operation := range []string{"named", "allocate", "recover"} {
		for _, boundary := range []string{"identity", "grant", "key", "deadline"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				f := newDeploymentPublicationFixture(t)
				_, credential, access, _ := f.approve(t, map[string][]string{"publish": {"web"}}, "restricted")
				request := f.allocation(t, access)
				if operation == "recover" {
					if _, err := f.d.AllocateDeploymentPublication(t.Context(), request); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				gate, err := f.d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err = controlstatedb.New(gate).LockLocalTeamForMutation(ctx, f.project.TeamID); err != nil {
					t.Fatal(err)
				}
				if boundary == "deadline" {
					if _, err = gate.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, credential.GrantID, f.now.Add(150*time.Millisecond)); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				started := time.Now()
				workers.Go(func() {
					if operation == "named" {
						result, err := f.d.GetDeploymentPublication(ctx, f.scope(access), "production", "web", f.now)
						if err != nil && result.PublicURL.ID != "" {
							err = errors.Join(err, errors.New("denied read returned URL"))
						}
						done <- err
						return
					}
					result, err := f.d.AllocateDeploymentPublication(ctx, request)
					if err != nil && result.ID != "" {
						err = errors.Join(err, errors.New("denied allocation returned URL"))
					}
					done <- err
				})
				waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
				switch boundary {
				case "identity":
					_, err = gate.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, credential.ClientID, f.now)
				case "grant":
					_, err = gate.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, credential.GrantID, f.now)
				case "key":
					_, err = gate.Exec(ctx, `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, credential.KeyID, f.now)
				case "deadline":
					timer := time.NewTimer(max(0, time.Until(started.Add(250*time.Millisecond))))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal(context.Cause(ctx))
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrPublisherIdentity) {
					t.Fatal("waiting publication escaped current authority", err)
				}
			})
		}
	}
}
