package state

import (
	"reflect"
	"testing"
)

func TestIntegrationWorkloadKubernetesMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_kubernetes_migration")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	exchange, _ := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	var before string
	if err := d.pool.QueryRow(t.Context(), `SELECT to_jsonb(w)::text FROM control.workload_sessions w WHERE id=$1`, session.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	if err := d.Readiness(t.Context()); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := d.pool.QueryRow(t.Context(), `SELECT to_jsonb(w)::text FROM control.workload_sessions w WHERE id=$1`, session.ID).Scan(&after); err != nil || after != before {
		t.Fatal("Kubernetes migration changed an existing session row", err)
	}
	recovered, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil || !reflect.DeepEqual(recovered.Session, session) {
		t.Fatal("Kubernetes migration changed existing session authority", err)
	}
}
