package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPooledRunStartWaitIsRunScoped(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	metadata := f.service.ServiceMetadata
	metadata.PublisherPool = true
	var err error
	f.service, err = d.ConfigureService(t.Context(), f.service.ID, f.actor(t), metadata, nil, ServiceUpdateConditions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.service.TeamID, ActingIdentityID: f.actor(t)},
		PublisherScope{TeamID: f.service.TeamID, Kind: "service", ServiceID: f.service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), f.service.ID, publisher, "parallel", now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: prepared.RunID, ServiceID: f.service.ID}); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := d.StartServiceRun(ctx, f.service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
		done <- err
	})
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	progress, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if _, err := d.StartServiceRun(progress, f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, now); err != nil {
		t.Fatal("a pooled run start blocked another publisher on the same service", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPublisherRuntimeWaitIsIdentityScoped(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_runtime_contention")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"api": {Target: "api.internal:3000"}}}
	r = selectedProjectRequest(r, "remote")
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	e, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "remote", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	first := enrollAppliedDeployment(t, d, r, e, now)
	second := enrollAppliedDeployment(t, d, r, e, now)
	request := func(member DeploymentPublisherIdentity, key ed25519.PrivateKey) PublisherRuntimeRequest {
		t.Helper()
		request := PublisherRuntimeRequest{PublisherIdentityID: member.PublisherIdentityID, ScopeID: member.DeploymentID,
			ProcessRunID: strings.Repeat("a", 32), Action: "start", Audience: "https://control.example/v1/publisher-runtime", Now: now}
		var err error
		request.Assertion, err = publisherproof.Sign(member.PublisherIdentityID, member.KeyID,
			publisherproof.RuntimeScope(member.DeploymentID, request.Action, request.ProcessRunID, 0, ""), request.Audience, key, now)
		if err != nil {
			t.Fatal(err)
		}
		return request
	}
	firstRequest, secondRequest := request(first.member, first.private), request(second.member, second.private)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockPublisherIdentity(ctx, first.member.PublisherIdentityID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := d.PublisherRuntime(ctx, firstRequest)
		done <- err
	})
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	progress, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	started, err := d.PublisherRuntime(progress, secondRequest)
	if err != nil || started.Epoch != 1 || started.DeploymentLease == nil {
		t.Fatal("one publisher blocked another publisher's runtime", err)
	}
	assignments, err := d.GetDeploymentPublisherAssignments(progress, started.DeploymentLease.AccessToken, now)
	if err != nil {
		t.Fatal("one publisher blocked another publisher's assignments", err)
	}
	if err := d.AcknowledgeDeploymentPublisherConfiguration(progress, started.DeploymentLease.AccessToken,
		assignments.Revision, assignments.ConfigurationHash, true, now); err != nil {
		t.Fatal("one publisher blocked another publisher's acknowledgement", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}
