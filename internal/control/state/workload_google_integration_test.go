package state

import (
	"reflect"
	"testing"
)

func TestIntegrationWorkloadGoogleMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_google_migration")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil || !reflect.DeepEqual(recovered, session) {
		t.Fatal("Google migration changed existing session authority", err)
	}
}
