package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationPostQuantumAppliedServicePolicy(t *testing.T) {
	database, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	request := oidcRouteRequest(t, database, now)
	service := ProjectServiceConfiguration{Target: "app", Public: new(true)}
	local := RealizeLocalProjectServiceRequest{TeamID: request.TeamID, ProjectKey: "post-quantum", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout", ActorID: request.ActingIdentityID, Configuration: service, Now: now}
	realized, err := database.RealizeLocalProjectService(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	siblingRequest := local
	siblingRequest.Service = "other"
	sibling, err := database.RealizeLocalProjectService(ctx, siblingRequest)
	if err != nil {
		t.Fatal(err)
	}
	apply := ApplyProjectConfigurationRequest{TeamID: request.TeamID, ProjectKey: local.ProjectKey, SourceFingerprint: local.SourceFingerprint, ActorID: request.ActingIdentityID,
		Deployment: "local", ServiceDeclarations: map[string]string{"web": "http", "other": "http"},
		Configuration: ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": service, "other": service}}, Now: now}
	applied, err := database.ApplyProjectConfiguration(ctx, apply)
	if err != nil {
		t.Fatal(err)
	}
	apply.ExpectedRevision = applied.Revision
	service.RequirePostQuantum = new(true)
	service.HTTP = &config.HTTPService{Access: &config.Access{Mode: string(VisitorAccessAnonymous)}}
	apply.Configuration.Services["web"] = service
	applied, err = database.ApplyProjectConfiguration(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	record, err := database.GetService(ctx, realized.ServiceID, request.ActingIdentityID)
	if err != nil || !record.RequirePostQuantum {
		t.Fatalf("apply lost visitor TLS policy: %+v, %v", record, err)
	}
	assertDeploymentServiceHTTPMode(t, database, record.ID, VisitorAccessAnonymous)
	trustRevision := record.TrustRevision
	enroll := func(id string) PublisherIdentity {
		t.Helper()
		enrollment := publisherEnrollment(t, database, request, PublisherScope{TeamID: request.TeamID, Kind: "service", ServiceID: id}, now)
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := database.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		return publisher
	}
	publisher, siblingPublisher := enroll(record.ID), enroll(sibling.ServiceID)
	start := func(id, attempt string, publisher PublisherIdentity) (ServiceRunPreparation, ServiceRunState) {
		t.Helper()
		approved, err := database.GetServiceForPublisher(ctx, id, publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := database.PrepareServiceRun(ctx, id, publisher, attempt, now, ServiceRunRequest{Metadata: approved.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		run, err := database.StartServiceRun(ctx, id, prepared.RunID, prepared.RunNumber, publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		return prepared, run
	}
	prepared, run := start(record.ID, "post-quantum", publisher)
	_, siblingRun := start(sibling.ServiceID, "sibling", siblingPublisher)
	if !prepared.RequirePostQuantum {
		t.Fatal("run did not capture the saved visitor TLS requirement")
	}
	apply.ExpectedRevision = applied.Revision
	service.RequirePostQuantum = nil
	apply.Configuration.Services["web"] = service
	applied, err = database.ApplyProjectConfiguration(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	record, err = database.GetService(ctx, realized.ServiceID, request.ActingIdentityID)
	if err != nil || !record.RequirePostQuantum || record.TrustRevision != trustRevision {
		t.Fatalf("apply omission cleared saved visitor TLS policy or changed target trust: %+v, %v", record, err)
	}
	if _, err := database.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("omitting visitor TLS policy closed its run", err)
	}
	apply.ExpectedRevision = applied.Revision
	service.RequirePostQuantum = new(true)
	apply.Configuration.Services["web"] = service
	applied, err = database.ApplyProjectConfiguration(ctx, apply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("unchanged visitor TLS policy closed its run", err)
	}
	apply.ExpectedRevision = applied.Revision
	service.RequirePostQuantum = new(false)
	apply.Configuration.Services["web"] = service
	if _, err := database.ApplyProjectConfiguration(ctx, apply); err != nil {
		t.Fatal("explicit visitor TLS change failed to retire the old run", err)
	}
	stored, err := controlstatedb.New(database.pool).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: run.RunID, ServiceID: run.ServiceID})
	if err != nil || !stored.ClosedAt.Valid || stored.State != "closed" || !stored.RequirePostQuantum {
		t.Fatal("visitor TLS change mutated the live run instead of closing its captured requirement", err)
	}
	if _, err := database.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old run renewed with a different visitor TLS requirement", err)
	}
	if _, err := database.HeartbeatServiceRun(ctx, siblingRun.ServiceID, siblingRun.RunID, siblingRun.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("visitor TLS change closed an unaffected local service", err)
	}
	record, err = database.GetService(ctx, realized.ServiceID, request.ActingIdentityID)
	if err != nil || record.RequirePostQuantum || record.TrustRevision != trustRevision {
		t.Fatalf("apply did not save explicit false independently of target trust: %+v, %v", record, err)
	}
	replacement, next := start(record.ID, "post-quantum-replacement", publisher)
	if replacement.RequirePostQuantum || next.RunID == run.RunID || next.RunNumber != run.RunNumber+1 || replacement.PublisherGrantID != publisher.GrantID {
		t.Fatal("replacement lost its exact grant, next run number, or changed visitor TLS requirement")
	}
}
