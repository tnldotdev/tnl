package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceSourceOwnershipSurvivesDeletionWithoutReassignment(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	if err := f.d.DeleteService(ctx, f.local.ID, f.member.IdentityID, ServiceDeleteConditions{Unconditional: true}, f.now); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE control.service_source_owners SET membership_id=$2 WHERE service_id=$1`,
		`DELETE FROM control.service_source_owners WHERE service_id=$1 AND membership_id<>$2`,
	} {
		_, err := f.d.pool.Exec(ctx, query, f.local.ID, f.unrelated.ID)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "P0001" || databaseError.Message != "service source ownership is immutable" {
			t.Fatal("deleted service ownership could be reassigned or erased", err)
		}
	}
}

func TestIntegrationServiceSourceOwnershipSurvivesLocalBindingHandoff(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	fingerprint := strings.Repeat("a", 64)
	request := RealizeLocalProjectServiceRequest{TeamID: f.team, ActorID: f.member.IdentityID,
		ProjectKey: "local-" + fingerprint[:48], SourceFingerprint: fingerprint, Service: "api", WorktreeKey: "checkout",
		Configuration: ProjectServiceConfiguration{Target: "app", Ephemeral: true}, Now: f.now}
	first, err := f.d.RealizeLocalProjectService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Now = f.now.Add(ephemeralServiceGracePeriod)
	if _, err := f.d.expireServices(ctx, request.Now); err != nil {
		t.Fatal(err)
	}
	replacement, err := f.d.RealizeLocalProjectService(ctx, request)
	if err != nil || replacement.ServiceID == first.ServiceID || replacement.Hostname != first.Hostname {
		t.Fatal("local binding handoff failed", replacement, err)
	}
	var retainedBindings int
	if err := f.d.pool.QueryRow(ctx, `SELECT
	    (SELECT count(*) FROM control.local_project_services WHERE service_id=$1)
	    + (SELECT count(*) FROM control.service_endpoints WHERE service_id=$1)`, first.ServiceID).Scan(&retainedBindings); err != nil || retainedBindings != 0 {
		t.Fatal("local binding handoff retained mutable receipts", retainedBindings, err)
	}
	tx, err := f.d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	row, err := controlstatedb.New(tx).LockService(ctx, first.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	member, err := serviceMembershipForActor(ctx, tx, f.team, f.member.IdentityID, request.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireStoredServiceManagement(ctx, tx, row, member, true); err != nil {
		t.Fatal("binding replacement erased retained management authority", err)
	}
	if err := requireServiceManagement(ctx, tx, row, member); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retained receipt revived ordinary management of a tombstone", err)
	}
}
