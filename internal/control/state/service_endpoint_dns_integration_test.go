package state

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationServiceEndpointDNSRevisions(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_endpoint_dns")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.DNSAutomation = true
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "production", Target: "localhost:3000"}}}
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(public bool, state PublicURLDNSState) ServiceEndpointDNSWork {
		t.Helper()
		work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "endpoint-worker", r.Now, time.Minute)
		if err != nil || !found || work.Hostname != applied.Services[0].Hostname || work.ServiceID != applied.Services[0].ServiceID || work.Public != public || work.State != state {
			t.Fatal("incorrect endpoint DNS work", work, found, err)
		}
		if err = d.ValidateServiceEndpointDNSWork(ctx, work, r.Now); err != nil {
			t.Fatal(err)
		}
		return work
	}
	private := claim(false, PublicURLDNSPending)
	r.ExpectedRevision = applied.Revision
	r.Now = now.Add(time.Second)
	r.Configuration.PublisherGroups["production"] = ProjectPublisherGroup{Public: true}
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ValidateServiceEndpointDNSWork(ctx, private, r.Now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatal("stale worker retained provider authority", err)
	}
	private.State, private.AvailableAt = PublicURLDNSPublished, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(ctx, private, r.Now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatal("old loopback publication completed a public revision", err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", r.Now, time.Minute); err != nil || found {
		t.Fatal("public DNS became claimable without a ready publisher and exposed port", found, err)
	}
	r.ExpectedRevision = applied.Revision
	r.Now = now.Add(2 * time.Second)
	r.Configuration.PublisherGroups["production"] = ProjectPublisherGroup{}
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	loopback := claim(false, PublicURLDNSPending)
	loopback.State, loopback.AvailableAt = PublicURLDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, loopback, r.Now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", r.Now, time.Minute); err != nil || found {
		t.Fatal("completed DNS work remained queued", found, err)
	}
	r.ExpectedRevision = applied.Revision
	r.Now = now.Add(3 * time.Second)
	delete(r.Configuration.Services, "api")
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	removed := claim(false, PublicURLDNSRemoving)
	removed.State, removed.AvailableAt = PublicURLDNSRemoved, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(ctx, removed, r.Now); err != nil {
		t.Fatal(err)
	}
	var retired bool
	if err = d.pool.QueryRow(ctx, `SELECT retired_at IS NOT NULL AND reusable_after>$2 FROM control.service_endpoints WHERE hostname=$1`, removed.Hostname, r.Now).Scan(&retired); err != nil || !retired {
		t.Fatal("DNS removal released certificate authority early", retired, err)
	}
	if count, err := d.ReleaseServicePorts(ctx, now.Add(8*24*time.Hour)); err != nil || count != 1 {
		t.Fatal("completed retirement permanently held the service port", count, err)
	}
}
