package state

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationServiceGroupMove(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_group_move")
	r := retainedEnvironmentProject(t, d, now)
	ctx := t.Context()
	environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"database": {Protocol: "postgres"}})
	production, err := retainedNamespaceClaim(t, d, r, "production", "", now)
	if err != nil {
		t.Fatal(err)
	}
	staging, err := retainedNamespaceClaim(t, d, r, "staging", "", now)
	if err != nil {
		t.Fatal(err)
	}
	// these are namespace-owner fixtures, not environment-owned service IDs.
	// environments never adopt or transfer another environment's saved services.
	var records []ServiceRecord
	for i, group := range []string{production, staging} {
		name := "database"
		if i == 1 {
			name = "staging-database"
		}
		service, err := d.CreateServiceAt(ctx, r.TeamID, r.ActorID, name, group, ServicePlacement{}, now, ServiceMetadata{Protocol: "postgres"})
		if err != nil {
			t.Fatal(err)
		}
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `UPDATE control.services SET name='database',name_scope=$2 WHERE id=$1`, service.ID, group); err != nil {
			t.Fatal(err)
		}
		if err := ensurePublisherGroupIngressPool(ctx, tx, group, 1, nil, []string{PrimaryIngressPoolID}); err != nil {
			t.Fatal(err)
		}
		if err := d.ensureServiceEndpoint(ctx, tx, service.ID, group, false, now); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		record, err := d.GetService(ctx, service.ID, r.ActorID)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
		if i == 0 {
			if _, err := d.CreateServiceGrant(ctx, service.ID, r.ActorID, "endpoint-team", "team", "", nil, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := records[0]
	grants, _, err := d.ListServiceGrants(ctx, old.ID, r.ActorID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListServiceAudit(ctx, r.TeamID, r.ActorID, ServiceAuditFilter{Service: "database"}, now); !errors.Is(err, serviceaudit.ErrInvalid) {
		t.Fatal("ambiguous name chose an arbitrary service", err)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := d.ensureServiceEndpoint(ctx, tx, old.ID, staging, false, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("colliding namespace destination accepted", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetService(ctx, old.ID, r.ActorID)
	if err != nil || !reflect.DeepEqual(current, old) {
		t.Fatal("failed move changed endpoint", err)
	}
	if err := d.DeleteService(ctx, records[1].ID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	move := func(at time.Time) {
		t.Helper()
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := d.ensureServiceEndpoint(ctx, tx, old.ID, staging, false, at); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	move(now.Add(time.Second))
	endpoint, err := d.GetService(ctx, old.ID, r.ActorID)
	if err != nil || endpoint.ID != old.ID || endpoint.Endpoint.Port != old.Endpoint.Port || endpoint.Endpoint.Hostname == old.Endpoint.Hostname || !strings.HasPrefix(endpoint.Endpoint.Hostname, "database.staging.") {
		t.Fatal("namespace owner lost service identity/reservation", err)
	}
	after, _, err := d.ListServiceGrants(ctx, old.ID, r.ActorID, "")
	if err != nil || !reflect.DeepEqual(after, grants) {
		t.Fatal("endpoint mutation changed visitor grants", err)
	}
	move(now.Add(2 * time.Second))
	retry, err := d.GetService(ctx, old.ID, r.ActorID)
	if err != nil || !reflect.DeepEqual(retry, endpoint) {
		t.Fatal("endpoint retry changed saved identity", err)
	}
}
