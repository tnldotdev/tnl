package state

import (
	"reflect"
	"testing"
)

func TestIntegrationWorkloadGoogleMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_google_migration")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	exchange, _ := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil || !reflect.DeepEqual(recovered.Session, session) {
		t.Fatal("Google migration changed existing session authority", err)
	}
}
