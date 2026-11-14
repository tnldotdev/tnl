package state

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationMigrationRejectsPreGoogleProviderBaseline(t *testing.T) {
	testMigrationRejectsProviderBaseline(t,
		"tnl-control-fresh-v1-workload-optional-duration",
		[]string{"github", "vercel", "fly", "oidc"}, "google")
}

func testMigrationRejectsProviderBaseline(t *testing.T, previous string, providers []string, excluded string) {
	t.Helper()
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "provider_baseline_"+excluded)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	// probe the real constraint without applying a provider-specific policy or
	// leaving changes to the saved session. all added providers are non-github.
	assertProvider := func(t *testing.T, provider string, rejected bool) {
		t.Helper()
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, tx)
		_, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET provider=$1,
			claims=jsonb_build_object('provider',$1::text),
			repository_id=NULL,run_id=NULL,run_attempt=NULL,check_run_id=NULL WHERE id=$2`, provider, session.ID)
		if !rejected {
			if err != nil {
				t.Fatalf("provider %q rejected: %v", provider, err)
			}
			return
		}
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "workload_sessions_provider_check" {
			t.Fatalf("provider %q error = %v; want workload_sessions_provider_check (23514)", provider, err)
		}
	}
	assertProvider(t, excluded, false)
	// these are frozen test literals, not provider names from project input.
	for _, query := range []string{
		`DELETE FROM control.goose_db_version WHERE version_id > 1`,
		`ALTER TABLE control.workload_sessions DROP CONSTRAINT workload_sessions_provider_check`,
		fmt.Sprintf(`ALTER TABLE control.workload_sessions ADD CONSTRAINT workload_sessions_provider_check
			CHECK (provider IN ('%s'))`, strings.Join(providers, "','")),
	} {
		if _, err := d.pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	for _, provider := range providers {
		if provider != "github" {
			assertProvider(t, provider, false)
		}
	}
	assertProvider(t, excluded, true)
	if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != 1 {
		t.Fatalf("predecessor schema version = %d, %v; want 1", version, err)
	}
	snapshot := func(t *testing.T) string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
			(SELECT jsonb_agg(v ORDER BY id) FROM control.goose_db_version v),
			(SELECT to_jsonb(i) FROM control.schema_identity i WHERE id=1),
			(SELECT pg_get_constraintdef(oid) FROM pg_constraint
			 WHERE conrelid='control.schema_identity'::regclass AND conname='schema_identity_baseline_id_check'),
			(SELECT pg_get_constraintdef(oid) FROM pg_constraint
			 WHERE conrelid='control.workload_sessions'::regclass AND conname='workload_sessions_provider_check'),
			(SELECT to_jsonb(w) FROM control.workload_sessions w WHERE id=$1))::text`, session.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	// cover the ordered stack's predecessor and its originally reused identity.
	// using baselineID here would conceal a future incompatible baseline edit.
	for _, identity := range []string{previous, "tnl-control-fresh-v1-connector-rebinding"} {
		t.Run(identity, func(t *testing.T) {
			if _, err := d.pool.Exec(ctx, `ALTER TABLE control.schema_identity DROP CONSTRAINT schema_identity_baseline_id_check`); err != nil {
				t.Fatal(err)
			}
			if _, err := d.pool.Exec(ctx, `UPDATE control.schema_identity SET baseline_id=$1 WHERE id=1`, identity); err != nil {
				t.Fatal(err)
			}
			if _, err := d.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE control.schema_identity
				ADD CONSTRAINT schema_identity_baseline_id_check CHECK (baseline_id='%s')`, identity)); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t)
			for _, check := range []struct {
				name string
				run  func() error
			}{
				{"migrate", func() error { return Migrate(ctx, url) }},
				{"readiness", func() error { return d.Readiness(ctx) }},
				{"open", func() error {
					opened, err := Open(ctx, url, testStorageKey, "", naming.ManagedURLModeGenerated)
					if opened != nil {
						opened.Close()
					}
					return err
				}},
			} {
				t.Run(check.name, func(t *testing.T) {
					err := check.run()
					if err == nil || !strings.Contains(err.Error(), "incompatible database baseline") || !strings.Contains(err.Error(), "use a fresh PostgreSQL database") {
						t.Errorf("rejection = %v; want incompatible baseline with fresh-database diagnostic", err)
					}
					if snapshot(t) != before {
						t.Fatal("compatibility check changed predecessor version, identity, constraints, or session")
					}
					assertProvider(t, excluded, true)
				})
			}
		})
	}
}
