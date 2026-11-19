package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/control/storagekey"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationCertificateHistoryMigration(t *testing.T) {
	for _, version := range []int64{1, 3} {
		t.Run(fmt.Sprintf("schema-%d", version), func(t *testing.T) {
			ctx := t.Context()
			url := newDisposableControlStateDatabaseURL(t, "certificate_history")
			config, err := parseDirectConfig(url)
			if err != nil {
				t.Fatal(err)
			}
			sqlDB := stdlib.OpenDB(*config)
			t.Cleanup(func() { _ = sqlDB.Close() })
			if err := ensureMigrationLock(ctx, sqlDB); err != nil {
				t.Fatal(err)
			}
			source, err := fs.Sub(migrationFiles, "migrations")
			if err != nil {
				t.Fatal(err)
			}
			provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, source, goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.UpTo(ctx, version); err != nil {
				t.Fatal(err)
			}
			pool, err := pgxpool.New(ctx, url)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := storagekey.New(testStorageKey, "")
			if err != nil {
				pool.Close()
				t.Fatal(err)
			}
			d := &Database{pool: pool, storageKey: keys, managedURLMode: naming.ManagedURLModeGenerated,
				activity: new(queryActivity), connections: new(connectionActivity)}
			t.Cleanup(d.Close)
			now := time.Now().UTC().Truncate(time.Second)
			r := appliedProjectRequest(t, d, now)
			r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
				"app": {Target: "localhost:3000"},
			}}
			r = selectedProjectRequest(r, "production")
			if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
				t.Fatal(err)
			}
			enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedDeployment(t, d, r, enrollment, now)
			assignment := replica.assignments.Services[0]
			access := deploymentAssignmentAccess(t, d, replica, assignment, now)
			registerCertificatePlanRelays(t, d, now)
			prep, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "history", now,
				ServiceRunRequest{Metadata: ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}})
			if err != nil {
				t.Fatal(err)
			}
			run, err := d.StartServiceRun(ctx, assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO control.publisher_certificate_checkpoints
				SELECT $1, encode(sha256(convert_to(plan::text,'UTF8')),'hex'), plan
				FROM (SELECT jsonb_build_object('cache_key','old-'||n||'.example',
					'scope','old-'||n||'.example','identifiers',jsonb_build_array('old-'||n||'.example'),
					'challenge_method','dns-01') AS plan FROM generate_series(1,1024) n) plans`, replica.member.PublisherIdentityID); err != nil {
				t.Fatal(err)
			}
			const directory = "https://acme.example.test/directory"
			if _, err := d.EnsureACMEAccount(ctx, directory, "operator@example.test", now); err != nil {
				t.Fatal(err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: prep.CertificatePlan.Identifiers}, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.CreateServiceCertificateIssuance(ctx, run.ServiceID, run.RunID, run.Token, directory, "history", run.RunNumber, csr, now); err == nil {
				t.Fatal("old schema accepted a 1025th certificate plan")
			}
			snapshot := func() string {
				t.Helper()
				var value string
				if err := pool.QueryRow(ctx, `SELECT jsonb_build_array(
					(SELECT jsonb_agg(to_jsonb(c) ORDER BY plan_digest) FROM control.publisher_certificate_checkpoints c),
					(SELECT jsonb_agg(to_jsonb(k) ORDER BY id) FROM control.publisher_identity_keys k),
					(SELECT jsonb_agg(to_jsonb(a) ORDER BY access_token_digest) FROM control.publisher_access_tokens a))::text`).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			for range 2 {
				if err := Migrate(ctx, url); err != nil {
					t.Fatal(err)
				}
				if snapshot() != before {
					t.Fatal("migration changed saved plans or credentials")
				}
			}
			if _, err := d.CreateServiceCertificateIssuance(ctx, run.ServiceID, run.RunID, run.Token, directory, "history", run.RunNumber, csr, now); err != nil {
				t.Fatal("existing run could not issue after upgrade", err)
			}
			assignments, err := d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, now)
			if err != nil || len(assignments.CertificateStatePlans) != 1025 {
				t.Fatal("assignment response lost plan history", len(assignments.CertificateStatePlans), err)
			}
		})
	}
}
