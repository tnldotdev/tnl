package state

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationGuestRestoredExactCertificatePlanAndForeignServiceRunDenial(t *testing.T) {
	f, _ := guestAuthorityFixture(t, false)
	hostname := f.service.Endpoint.Hostname
	want := CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "dns-01"}
	if hostname == "" || !reflect.DeepEqual(f.prep.CertificatePlan, want) ||
		f.prep.GuestID != f.service.GuestID || f.prep.TeamID != "" ||
		f.prep.PublisherIdentityID != f.publisher.ID || f.prep.PublisherGrantID != f.publisher.GrantID {
		t.Fatal("guest preparation widened its exact service plan or changed publisher authority")
	}
	other := newGuestTrialForTest(t, f.database, f.now.Add(-time.Second))
	foreign, err := f.database.AllocateGuestDemoService(t.Context(), AllocateGuestDemoServiceRequest{
		Credential: guestCredentialForTest(other), IdempotencyKey: "foreign", Target: guestLoopbackTarget(t), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := f.stored(t)
	if _, err := f.database.PrepareServiceRun(f.ctx, foreign.ID, f.publisher, "foreign", f.now,
		ServiceRunRequest{Metadata: foreign.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("guest publisher prepared another trial's service", err)
	}
	if _, err := f.database.StartServiceRun(f.ctx, foreign.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("guest publisher started its run under another service", err)
	}
	if after := f.stored(t); !reflect.DeepEqual(after, before) {
		t.Fatal("foreign-service denial changed guest accounting or active authority")
	}
	var foreignRuns int
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_runs WHERE service_id=$1`,
		foreign.ID).Scan(&foreignRuns); err != nil || foreignRuns != 0 {
		t.Fatal("foreign-service denial created a durable guest run", err)
	}
}
