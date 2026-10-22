package tnldruntime

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/internal/testutil"
)

type cancelingAuditDatabase struct {
	*controlstate.Database
	cancel context.CancelFunc
}

func (s cancelingAuditDatabase) CleanupServiceAudit(ctx context.Context, now time.Time, limit int) (int64, error) {
	defer s.cancel()
	return s.Database.CleanupServiceAudit(ctx, now, limit)
}

func TestIntegrationServiceAuditCleanupObservedOnce(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	url, inspect := standaloneTestDatabase(t)
	db, err := controlstate.Open(t.Context(), url, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := observability.New("control")
	defer m.Shutdown(context.Background())
	db.Instrument(m)
	old := time.Now().Add(-serviceaudit.Retention - time.Hour)
	for range 3 {
		if _, err := inspect.ExecContext(t.Context(), `INSERT INTO control.service_audit_events(id,team_id,service_id,service_kind,event_type,occurred_at,received_at) VALUES($1,'team_fixture','service_fixture','private_service','connection.close',$2,$2)`, serviceaudit.NewID(), old); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := runServiceAuditCleanup(ctx, cancelingAuditDatabase{db, cancel}, m); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.service_audit_events`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("worker did not remove real expired rows", remaining, err)
	}
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, family := range families {
		want := float64(0)
		switch family.GetName() {
		case "tnl_control_cleanup_runs_total":
			want = 1
		case "tnl_control_cleanup_items_total":
			want = 3
		default:
			continue
		}
		for _, point := range family.Metric {
			for _, label := range point.Label {
				if label.GetName() == "tnl_cleanup_kind" && label.GetValue() == "service_audit" {
					seen++
					if point.GetCounter().GetValue() != want {
						t.Errorf("%s = %v, want %v", family.GetName(), point.GetCounter().GetValue(), want)
					}
				}
			}
		}
	}
	if seen != 2 {
		t.Fatal("missing cleanup observations", seen)
	}
	t.Log("instrumented PostgreSQL worker: cleanup_runs=1 cleanup_items=3 remaining_rows=0")
}
