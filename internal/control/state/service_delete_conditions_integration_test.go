package state

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// existing lifecycle tests observe current settings before ordinary management
// deletion. dedicated concurrency tests below retain their older observation.
func observedServiceDeletion(t *testing.T, d *Database, service string) ServiceDeleteConditions {
	t.Helper()
	var revision int64
	if err := d.pool.QueryRow(t.Context(), `SELECT service_revision FROM control.services WHERE id=$1`, service).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return ServiceDeleteConditions{Revision: revision}
}

func TestServiceDeleteConditionBounds(t *testing.T) {
	var d *Database
	for _, conditions := range []ServiceDeleteConditions{
		{}, {Revision: -1}, {Revision: 1, Unconditional: true}, {Revision: -1, Unconditional: true},
	} {
		if err := d.DeleteService(t.Context(), "service", "actor", conditions, time.Now()); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("invalid deletion condition reached storage", err)
		}
	}
}

func TestIntegrationServiceDeletionUnconditionalRetainsStoredScope(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	current, err := f.d.GetService(ctx, f.local.ID, f.member.IdentityID)
	if err != nil || current.ServiceRevision < 1 {
		t.Fatal("exact manager could not read current revision", err)
	}
	if denied, err := f.d.GetService(ctx, f.local.ID, f.unrelated.IdentityID); !errors.Is(err, ErrServiceAccess) || denied.ServiceRevision != 0 {
		t.Fatal("unrelated member read another service's revision", err)
	}
	metadata := current.ServiceMetadata
	metadata.PublisherPool = !metadata.PublisherPool
	updated, err := f.d.ConfigureService(ctx, f.local.ID, f.member.IdentityID, metadata, nil, ServiceUpdateConditions{}, f.now)
	if err != nil || updated.ServiceRevision <= current.ServiceRevision || updated.TrustRevision != current.TrustRevision {
		t.Fatal("compatible metadata edit did not advance independent service revision", err)
	}
	before := serviceSecuritySnapshot(t, f.d)
	for _, conditions := range []ServiceDeleteConditions{{Revision: current.ServiceRevision}, {Unconditional: true}} {
		if err := f.d.DeleteService(ctx, f.local.ID, f.unrelated.IdentityID, conditions, f.now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("condition bypassed current stored management scope", err)
		}
	}
	if after := serviceSecuritySnapshot(t, f.d); !reflect.DeepEqual(after, before) {
		t.Fatal("denied deletion changed state")
	}
	if err := f.d.DeleteService(ctx, f.local.ID, f.member.IdentityID, ServiceDeleteConditions{Revision: current.ServiceRevision}, f.now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale management revision did not conflict", err)
	}
	if err := f.d.DeleteService(ctx, f.local.ID, f.member.IdentityID, ServiceDeleteConditions{Unconditional: true}, f.now); err != nil {
		t.Fatal("explicit unconditional deletion failed", err)
	}
}

func TestIntegrationServiceRevisionExcludesNoopAndRunChurn(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, ctx := f.database, t.Context()
	current, err := d.GetService(ctx, f.service.ID, f.actor(t))
	if err != nil || current.ServiceRevision != f.service.ServiceRevision {
		t.Fatal("preparing and starting a run advanced saved-service revision", err)
	}
	declaration, digest, err := d.GetServiceConfiguration(ctx, current.ID, f.actor(t))
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := d.ConfigureService(ctx, current.ID, f.actor(t), current.ServiceMetadata, declaration,
		ServiceUpdateConditions{ConfigurationDigest: digest}, f.now)
	if err != nil || unchanged.ServiceRevision != current.ServiceRevision {
		t.Fatal("identical settings replacement changed saved-service revision", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	var revision int64
	if err := d.pool.QueryRow(ctx, `UPDATE control.services SET service_revision=service_revision+100,updated_at=updated_at
		WHERE id=$1 RETURNING service_revision`, f.service.ID).Scan(&revision); err != nil || revision != current.ServiceRevision {
		t.Fatal("runtime churn or caller-supplied revision replaced the row-owned counter", err)
	}
}

func TestIntegrationServiceDeletionRejectsQueuedSettingsChange(t *testing.T) {
	for _, change := range []struct {
		name, sql string
	}{
		{"metadata", `UPDATE control.services SET publisher_pool=NOT publisher_pool WHERE id=$1`},
		{"configuration", `UPDATE control.services SET configuration_ciphertext=NULL,storage_key_id=NULL WHERE id=$1`},
		{"exposure", `UPDATE control.services SET public=false WHERE id=$1`},
		{"enablement", `UPDATE control.services SET enabled=false WHERE id=$1`},
	} {
		t.Run(change.name, func(t *testing.T) {
			d, now, authority, _ := newPublishRunPrerequisites(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			service, err := d.CreateServiceAt(ctx, authority.TeamID, authority.ActingIdentityID, "delete-stale", "delete-stale",
				ServicePlacement{DNSAutomation: true}, now, ServiceMetadata{},
				&ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000", Public: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			_, prepared := adminPreparedRun(t, d, service, authority.ActingIdentityID, now)
			if current := observedServiceDeletion(t, d, service.ID); current.Revision != service.ServiceRevision {
				t.Fatal("run preparation changed saved-service settings revision")
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, change.sql, service.ID); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			workers.Go(func() {
				result <- d.DeleteService(ctx, service.ID, authority.ActingIdentityID, ServiceDeleteConditions{Revision: service.ServiceRevision}, now)
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), result)
			// snapshot the writer's transaction before exposing its committed
			// settings. the queued delete must leave every row byte-identical.
			before := serviceSecuritySnapshotQuery(t, gate)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, result); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("queued stale deletion did not conflict", err)
			}
			if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
				t.Fatal("stale deletion changed tombstone, runs, policy, DNS, ports, or audit")
			}
			var open bool
			if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NULL FROM control.service_runs WHERE id=$1`, prepared.RunID).Scan(&open); err != nil || !open {
				t.Fatal("stale delete closed prepared publication", err)
			}
			current, err := d.GetService(ctx, service.ID, authority.ActingIdentityID)
			if err != nil || current.ServiceRevision <= service.ServiceRevision {
				t.Fatal("saved settings did not advance the service revision", err)
			}
			if err := d.DeleteService(ctx, service.ID, authority.ActingIdentityID, ServiceDeleteConditions{Revision: current.ServiceRevision}, now); err != nil {
				t.Fatal("matching deletion failed", err)
			}
		})
	}
}
