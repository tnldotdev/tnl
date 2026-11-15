package daemon

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/maintenance"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
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
	db, err := controlstate.Open(t.Context(), url, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	session, err := db.CreateOIDCControlSession(t.Context(), "audit.example.test", controlstate.OIDCIdentity{
		Issuer: "https://identity.example.test", Subject: "audit-cleanup", DisplayName: "audit cleanup",
		AssertionDigest: sha256.Sum256([]byte("audit-cleanup")), AssertionExpiry: now.Add(time.Hour),
	}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := db.CreateServiceAt(t.Context(), session.Identity.PersonalTeamID, session.Identity.Identity.ID,
		"cleanup", "cleanup", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.service_audit_events`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	m := observability.New("control")
	defer m.Shutdown(context.Background())
	db.Instrument(m)
	old := time.Now().Add(-serviceaudit.Retention - time.Hour)
	for range 3 {
		if _, err := inspect.ExecContext(t.Context(), `INSERT INTO control.service_audit_events(id,team_id,service_id,event_type,occurred_at,received_at) VALUES($1,$2,$3,'connection.close',$4,$4)`, serviceaudit.NewID(), service.TeamID, service.ID, old); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := maintenance.RunServiceAuditCleanup(ctx, cancelingAuditDatabase{db, cancel}, m); err != nil {
		t.Fatal(err)
	}
	var remaining, expired int
	if err := inspect.QueryRowContext(t.Context(), `SELECT count(*),count(*) FILTER (WHERE received_at<$1) FROM control.service_audit_events`, now.Add(-serviceaudit.Retention)).Scan(&remaining, &expired); err != nil || remaining != retained || expired != 0 {
		t.Fatal("worker did not remove exactly the expired rows while retaining current service history", remaining, expired, retained, err)
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
	t.Logf("instrumented PostgreSQL worker: cleanup_runs=1 cleanup_items=3 expired_rows=0 retained_rows=%d", retained)
}
