package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
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
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "app", Public: new(true), HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}},
		"api": {Target: "app", Public: new(true)},
		"db":  {Protocol: "postgres", Target: "database.internal:5432"},
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
	stage := r
	stage.ExpectedRevision, stage.Deployment = first.Revision, "staging"
	stage.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "app", Public: new(true)},
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

func assertDeploymentServiceHTTPMode(t *testing.T, d *Database, id string, expected VisitorAccessMode) {
	t.Helper()
	settings, err := d.serviceHTTPSettings(t.Context(), controlstatedb.New(d.pool), id)
	if err != nil {
		t.Fatal(err)
	}
	mode := VisitorAccessRestricted
	if settings != nil && settings.Access != nil {
		mode = VisitorAccessMode(settings.Access.VisitorMode())
	}
	if mode != expected {
		t.Fatalf("service HTTP access: got %q, want %q", mode, expected)
	}
}

type deploymentServiceRunFixture struct {
	service  ServiceRecord
	prepared ServiceRunPreparation
	run      ServiceRunState
}

func startDeploymentServiceRun(t *testing.T, f deploymentPublicationFixture, access PublisherAccess, deployment, name, attempt string) deploymentServiceRunFixture {
	t.Helper()
	service, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), deployment, name, f.now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, attempt, f.now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := f.d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PublisherGrantID != access.GrantID || prepared.PublisherIdentityID != access.ID || prepared.PublisherKeyID != access.KeyID {
		t.Fatal("service run substituted the registered grant, identity, or signing key")
	}
	return deploymentServiceRunFixture{service, prepared, run}
}

func readyDeploymentServiceRun(t *testing.T, d *Database, fixture deploymentServiceRunFixture, leases map[string]RelayLease, now time.Time) {
	t.Helper()
	installPrivateTestCertificate(t, d, fixture.prepared, fixture.run, now)
	for _, slot := range fixture.run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, fixture.run.ServiceID, fixture.run.RunID, fixture.run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, fixture.run.RunID, fixture.run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), fixture.run.ServiceID, fixture.run.RunID, fixture.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("service run did not become ready with its certificate and relay connections", err)
	}
}

func (f deploymentPublicationFixture) approve(t *testing.T, names map[string][]string, temporary string) (RegisterDeploymentCredentialRequest, DeploymentCredential, PublisherAccess, ed25519.PrivateKey) {
	t.Helper()
	r, key := managementRegistration(t, DeploymentScope{TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, ActorID: f.project.ActorID}, f.now)
	var err error
	r.IdempotencyKey, err = opaqueid.New(opaqueid.RequestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	r.Permissions, r.TemporaryPublication = names, temporary
	r.AllDeployments, r.DeploymentIDs = false, []string{f.production.ID}
	credential, err := f.d.RegisterDeploymentCredential(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	return r, credential, managementAccess(t, f.d, credential, key, f.now), key
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
	return AllocateDeploymentPublicationRequest{DeploymentScope: f.scope(access), Deployment: f.production.ID, AllocateServiceRequest: AllocateServiceRequest{Invocation: invocation, Configuration: ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"}}, Now: f.now}
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
				if err == nil || publication.ID != "" {
					t.Fatal("another capability implied publishing")
				}
				return
			}
			if err != nil || publication.ID != f.production.Services["web"].ID {
				t.Fatal("named publication lost saved policy", err)
			}
			assertDeploymentServiceHTTPMode(t, f.d, publication.ID, VisitorAccessAnonymous)
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
				if result, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), selection[0], selection[1], f.now); err == nil || result.ID != "" {
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
	deployment, err := controlstatedb.New(f.d.pool).LockDeploymentByID(ctx, f.production.ID)
	if err != nil {
		t.Fatal(err)
	}
	label, namespace, found := strings.Cut(first.Endpoint.Hostname, ".")
	if !found || len(label) != 26 || namespace != deployment.Namespace || !first.Ephemeral || !first.Endpoint.Public || first.Endpoint.Port != 443 {
		t.Fatal("allocation borrowed a saved policy, developer namespace, or wrong lifetime")
	}
	assertDeploymentServiceHTTPMode(t, f.d, first.ID, VisitorAccessRestricted)
	var ports, grants int
	if err := f.d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.service_port_claims WHERE service_id=$1),(SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$2)`, first.ID, access.ID).Scan(&ports, &grants); err != nil || ports != 0 || grants != 1 {
		t.Fatal("temporary service reserved an HTTP port or created a child grant", ports, grants, err)
	}
	recovered, err := f.d.AllocateDeploymentPublication(ctx, request)
	if err != nil || !reflect.DeepEqual(first, recovered) {
		t.Fatal("lost allocation reply changed original URL/deadline", err)
	}
	changed := request
	changed.Configuration.Target = "http://127.0.0.1:4000"
	if _, err = f.d.AllocateDeploymentPublication(ctx, changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("retry changed its target", err)
	}
	anonymous := f.allocation(t, access)
	anonymous.Configuration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
	if _, err = f.d.AllocateDeploymentPublication(ctx, anonymous); !errors.Is(err, ErrDeploymentAccess) {
		t.Fatal("restricted approval allowed anonymous allocation", err)
	}
	_, _, other, _ := f.approve(t, nil, "restricted")
	if _, err := f.d.GetServiceForPublisher(ctx, first.ID, other.PublisherIdentity, f.now); err == nil {
		t.Fatal("another credential adopted the allocation", err)
	}
	if err := f.d.DeletePublisherService(ctx, other.PublisherIdentity, first.ID, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another credential deleted the allocated service", err)
	}
	if err := f.d.DeletePublisherService(ctx, access.PublisherIdentity, f.production.Services["web"].ID, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("temporary approval deleted a named service", err)
	}
	if err := f.d.DeletePublisherService(ctx, access.PublisherIdentity, first.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.AllocateDeploymentPublication(ctx, request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("retry resurrected a deleted allocation", err)
	}
	fresh, err := f.d.AllocateDeploymentPublication(ctx, f.allocation(t, access))
	if err != nil || fresh.ID == first.ID || fresh.Endpoint.Hostname == first.Endpoint.Hostname {
		t.Fatal("fresh invocation reused an allocation", err)
	}
	if err = f.d.DeleteDeployment(ctx, r.DeploymentScope, f.production.ID, f.production.Revision, f.now); err != nil {
		t.Fatal(err)
	}
	u, err := controlstatedb.New(f.d.pool).LockService(ctx, fresh.ID)
	if err != nil || !u.DeletedAt.Valid {
		t.Fatal("deployment deletion retained its temporary service", err)
	}
	if _, err := controlstatedb.New(f.d.pool).GetPublisherAllocation(ctx, fresh.ID); err != nil {
		t.Fatal("deployment deletion discarded the allocation tombstone", err)
	}
	if _, err = f.d.AllocateDeploymentPublication(ctx, f.allocation(t, access)); err == nil {
		t.Fatal("deleted deployment retained allocation authority")
	}
}

func TestIntegrationDeploymentPublicationSignedRunAndRevocation(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	_, _, _, _ = publishRunPrerequisitesInDatabase(t, f.d, f.now, nil)
	_, credential, access, _ := f.approve(t, map[string][]string{"publish": {"web"}}, "anonymous")
	until := f.now.Add(10 * time.Second)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, credential.GrantID, until); err != nil {
		t.Fatal(err)
	}
	t.Run("named-service", func(t *testing.T) {
		service, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now)
		if err != nil {
			t.Fatal(err)
		}
		request := ServiceRunRequest{Metadata: service.ServiceMetadata}
		prepared, err := f.d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "signed-deployment-service", f.now, request)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := f.d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "signed-deployment-service", f.now, request)
		if err != nil || !reflect.DeepEqual(prepared, recovered) || prepared.PublisherGrantID != credential.GrantID || prepared.PublisherKeyID != credential.KeyID {
			t.Fatal("signed service preparation recovery changed authority", err)
		}
		run, err := f.d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, f.now)
		if err != nil || !run.ExpiresAt.Equal(until) || !prepared.ExpiresAt.Equal(until) {
			t.Fatal("service run outlived approval", err)
		}
		heartbeat, err := f.d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, f.now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || !heartbeat.ExpiresAt.Equal(until) {
			t.Fatal("service renewal extended the fixed grant deadline", err)
		}
		var grants int
		if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, credential.ClientID).Scan(&grants); err != nil || grants != 1 {
			t.Fatal("named publication created a child grant", grants, err)
		}
	})
	t.Run("temporary-allocation", func(t *testing.T) {
		r := f.allocation(t, access)
		r.Configuration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
		service, err := f.d.AllocateDeploymentPublication(t.Context(), r)
		if err != nil {
			t.Fatal(err)
		}
		request := ServiceRunRequest{Metadata: service.ServiceMetadata}
		prepared, err := f.d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "signed-temporary-service", f.now, request)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := f.d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "signed-temporary-service", f.now, request)
		if err != nil || !reflect.DeepEqual(prepared, recovered) || prepared.PublisherGrantID != credential.GrantID || prepared.PublisherKeyID != credential.KeyID {
			t.Fatal("signed run recovery changed authority", err)
		}
		run, err := f.d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, f.now)
		if err != nil || !run.ExpiresAt.Equal(until) || service.ExpiresAt == nil || !service.ExpiresAt.Equal(until) {
			t.Fatal("run outlived approval")
		}
		heartbeat, err := f.d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, f.now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || !heartbeat.ExpiresAt.Equal(until) {
			t.Fatal("renewal extended the fixed grant deadline", err)
		}
	})
	if err := f.d.RevokePublisherIdentity(t.Context(), f.project.TeamID, credential.ClientID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.publish_runs WHERE publisher_identity_id=$1 AND closed_at IS NULL)+(SELECT count(*) FROM control.service_runs WHERE publisher_identity_id=$1 AND closed_at IS NULL)`, credential.ClientID).Scan(&open); err != nil || open != 0 {
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
	if result, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now); !errors.Is(err, ErrDeploymentAccess) || result.ID != "" {
		t.Fatal("publication retained a releasing domain", err)
	}
	if _, err = f.d.AllocateDeploymentPublication(t.Context(), request); err == nil {
		t.Fatal("allocation recovery retained a releasing domain")
	}
	if _, err = f.d.pool.Exec(t.Context(), `UPDATE control.domains SET state='ready' WHERE id=$1`, u.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.ExpireServiceRuns(t.Context(), f.now.Add(ephemeralServiceGracePeriod+time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.AllocateDeploymentPublication(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
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
						if err != nil && result.ID != "" {
							err = errors.Join(err, errors.New("denied read returned service"))
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
