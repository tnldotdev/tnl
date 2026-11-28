package state

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

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
