package state

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServicePoolConditionWithoutDeclaration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "pool_condition")
	actor := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "pool", "pool",
		ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	absent, digest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
	if err != nil || absent != nil {
		t.Fatal(err)
	}
	metadata := service.ServiceMetadata
	metadata.PublisherPool = true
	updated, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, metadata, nil,
		ServiceUpdateConditions{PublisherPool: new(false)}, now)
	if err != nil || !updated.PublisherPool || updated.TrustRevision != service.TrustRevision ||
		updated.EndpointRevision != service.EndpointRevision {
		t.Fatal("pool condition required a declaration or changed trust or endpoint", err)
	}
	if declaration, nextDigest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID); err != nil ||
		declaration != nil || nextDigest != digest {
		t.Fatal("pool-only condition created a declaration or changed its absence digest", err)
	}
}

func TestIntegrationServiceUpdateConditionsPreserveConcurrentPoolChange(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now := f.database, f.now
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	configuration := ProjectServiceConfiguration{Target: "localhost:3000", HTTP: &config.HTTPService{
		Access: &config.Access{Mode: "anonymous"},
		Limits: &config.WorkLimits{Total: new(100)},
	}}
	var err error
	f.service, err = d.CreateServiceAt(ctx, f.project.TeamID, f.project.ActorID, "conditional-pool", "conditional-pool",
		ServicePlacement{}, now, ServiceMetadata{}, &configuration)
	if err != nil {
		t.Fatal(err)
	}
	f.run = f.publish(t, f.service)
	declaration, digest, err := d.GetServiceConfiguration(ctx, f.service.ID, f.project.ActorID)
	if err != nil || declaration == nil {
		t.Fatal("read standalone declaration", err)
	}
	replacement, err := normalizeServiceConfiguration(f.service.Name, declaration)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Target = "localhost:4000"
	q := controlstatedb.New(d.pool)
	policyKey := f.service.ID
	revision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil {
		t.Fatal(err)
	}
	check := func(service ServiceRecord, updates int) {
		t.Helper()
		if service.ID != f.service.ID || service.TrustRevision != f.service.TrustRevision ||
			service.EndpointRevision != f.service.EndpointRevision || !reflect.DeepEqual(service.Endpoint, f.service.Endpoint) {
			t.Fatal("conditional edit changed service identity, trust, or endpoint")
		}
		if current, err := q.ReadVisitorPolicyRevision(ctx, policyKey); err != nil || current != revision {
			t.Fatal("pool or target-only edit invalidated visitor policy", err)
		}
		auth := f.auth()
		if _, err := d.ReadPublisherVisitorPolicy(ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now); err != nil {
			t.Fatal("conditional edit closed or fenced the valid run", err)
		}
		var actualUpdates, trust int
		if err := d.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE event_type='service.update'),
		    count(*) FILTER(WHERE event_type='trust.update') FROM control.service_audit_events WHERE service_id=$1`,
			f.service.ID).Scan(&actualUpdates, &trust); err != nil || actualUpdates != updates || trust != 0 {
			t.Fatal("conditional edit lost audit or emitted a trust update", actualUpdates, trust, err)
		}
	}

	// queue both writers on the actual service lock. the partial edit read
	// before the pool toggle but must compare against its committed pool bit.
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockService(ctx, f.service.ID); err != nil {
		t.Fatal(err)
	}
	poolMetadata := f.service.ServiceMetadata
	poolMetadata.PublisherPool = true
	var enabled ServiceRecord
	poolDone := make(chan error, 1)
	workers.Go(func() {
		var err error
		enabled, err = d.ConfigureService(ctx, f.service.ID, f.project.ActorID, poolMetadata, nil,
			ServiceUpdateConditions{PublisherPool: new(false)}, now)
		poolDone <- err
	})
	poolPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), poolDone)
	partialDone := make(chan error, 1)
	workers.Go(func() {
		_, err := d.ConfigureService(ctx, f.service.ID, f.project.ActorID, f.service.ServiceMetadata, replacement,
			ServiceUpdateConditions{ConfigurationDigest: digest, PublisherPool: new(false)}, now)
		partialDone <- err
	})
	waitForPostgresBlock(t, ctx, d, poolPID, partialDone)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, poolDone); err != nil || !enabled.PublisherPool {
		t.Fatal("explicit pool toggle rejected its matching observed bit", err)
	}
	if err := awaitIntegrationResult(t, ctx, partialDone); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale partial update overwrote the concurrent pool toggle", err)
	}
	current, err := d.GetService(ctx, f.service.ID, f.project.ActorID)
	if err != nil || !current.PublisherPool {
		t.Fatal("rejected partial edit changed publisher pool", err)
	}
	saved, currentDigest, err := d.GetServiceConfiguration(ctx, f.service.ID, f.project.ActorID)
	if err != nil || currentDigest != digest || !reflect.DeepEqual(saved, declaration) {
		t.Fatal("pool-only edit or rejected partial edit changed the declaration or digest", err)
	}
	check(current, 1)

	updated, err := d.ConfigureService(ctx, current.ID, f.project.ActorID, current.ServiceMetadata, replacement,
		ServiceUpdateConditions{ConfigurationDigest: currentDigest, PublisherPool: new(current.PublisherPool)}, now)
	if err != nil || !updated.PublisherPool {
		t.Fatal("reread/retry lost the concurrent publisher pool setting", err)
	}
	saved, nextDigest, err := d.GetServiceConfiguration(ctx, current.ID, f.project.ActorID)
	if err != nil || nextDigest == digest || !reflect.DeepEqual(saved, replacement) {
		t.Fatal("conditional retry lost the requested declaration", err)
	}
	check(updated, 2)
	if _, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, updated.ServiceMetadata, declaration,
		ServiceUpdateConditions{ConfigurationDigest: digest, PublisherPool: new(true)}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("matching pool condition bypassed a stale declaration digest", err)
	}
	if _, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, updated.ServiceMetadata, nil,
		ServiceUpdateConditions{PublisherPool: new(false)}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("identical desired pool bypassed a stale observed bit", err)
	}
	stored, err := q.GetServiceConfiguration(ctx, updated.ID)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, updated.ServiceMetadata, saved,
		ServiceUpdateConditions{ConfigurationDigest: nextDigest, PublisherPool: new(true)}, now)
	if err != nil || !retried.PublisherPool {
		t.Fatal("exact conditional retry failed", err)
	}
	after, err := q.GetServiceConfiguration(ctx, updated.ID)
	if err != nil || !reflect.DeepEqual(stored, after) {
		t.Fatal("no-op conditions rewrote the encrypted declaration", err)
	}
	check(retried, 2)

	metadata := retried.ServiceMetadata
	metadata.PublisherPool = false
	disabled, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, metadata, nil,
		ServiceUpdateConditions{PublisherPool: new(true)}, now)
	if err != nil || disabled.PublisherPool {
		t.Fatal("pool toggle treated its condition as desired intent", err)
	}
	if _, digest, err := d.GetServiceConfiguration(ctx, updated.ID, f.project.ActorID); err != nil || digest != nextDigest {
		t.Fatal("pool toggle without a replacement changed its declaration digest", err)
	}
	check(disabled, 3)
}
