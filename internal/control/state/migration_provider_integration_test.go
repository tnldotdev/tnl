package state

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationMigrationWorkloadProviderConstraints(t *testing.T) {
	d, _, now := newControlStateIntegrationDatabaseWithURL(t, "provider_constraints")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	// probe the real provider constraint without changing the saved session.
	for _, provider := range []string{"vercel", "fly", "oidc", "google", "kubernetes", "gitlab", "unknown"} {
		t.Run(provider, func(t *testing.T) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			_, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET provider=$1,
				claims=jsonb_build_object('provider',$1::text),
				repository_id=NULL,run_id=NULL,run_attempt=NULL,check_run_id=NULL WHERE id=$2`, provider, session.ID)
			if provider != "unknown" {
				if err != nil {
					t.Fatalf("provider %q rejected: %v", provider, err)
				}
				return
			}
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "workload_sessions_provider_check" {
				t.Fatalf("provider %q error = %v; want workload_sessions_provider_check (23514)", provider, err)
			}
		})
	}
}
