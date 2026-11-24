package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestIntegrationRunAliasDNSRetryResetsOnPendingRetirementAndRebind(t *testing.T) {
	f, _, declaration := newRunAliasServiceFixture(t)
	ctx := t.Context()
	d := f.database
	service, err := d.CreateServiceAt(ctx, f.project.TeamID, f.project.ActorID, "retry", "retry",
		ServicePlacement{DomainID: f.service.DomainID, DNSAutomation: true}, f.now, f.service.ServiceMetadata, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	registerServiceHTTPAdmissionIngress(t, ctx, f, "alias-dns-retry")
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID},
		PublisherScope{TeamID: f.project.TeamID, Kind: "service", ServiceID: service.ID}, f.now)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	access := publisherAccess(t, d, publisher, private, "192.0.2.10", f.now)
	run := readyAppliedServiceRun(t, d, access, private, service, netip.MustParseAddr("192.0.2.10"), f.leases, f.now)
	f.now = f.now.Add(time.Second)
	first, found, err := d.ClaimServiceEndpointDNSWork(ctx, "first", f.now, time.Minute)
	if err != nil || !found {
		t.Fatal("expected a DNS claim", found, err)
	}
	second, found, err := d.ClaimServiceEndpointDNSWork(ctx, "second", f.now, time.Minute)
	if err != nil || !found {
		t.Fatal("expected a second DNS claim", found, err)
	}
	canonical, alias := first, second
	if canonical.Hostname == run.RunHostname {
		canonical, alias = alias, canonical
	}
	if canonical.Hostname != service.Endpoint.Hostname || alias.Hostname != run.RunHostname {
		t.Fatal("claimed incorrect endpoints")
	}
	const dnsError = "server.dns_failed"
	save := func(work ServiceEndpointDNSWork, state ServiceEndpointDNSState, lastError string, streak int64) {
		t.Helper()
		work.State, work.LastError, work.AvailableAt = state, lastError, time.Time{}
		if state == ServiceEndpointDNSPending || state == ServiceEndpointDNSRemoving {
			work.AvailableAt = f.now.Add(time.Second)
		}
		saved, err := d.SaveServiceEndpointDNSWork(ctx, work, f.now)
		if err != nil || saved.ConsecutiveErrors != streak || saved.Attempts != work.Attempts || saved.LastError != lastError {
			t.Fatal("DNS outcome did not save the expected streak, total, and diagnostic", saved, err)
		}
	}
	claim := func(worker string, state ServiceEndpointDNSState, streak, attempts int64) ServiceEndpointDNSWork {
		t.Helper()
		f.now = f.now.Add(time.Second)
		work, found, err := d.ClaimServiceEndpointDNSWork(ctx, worker, f.now, time.Minute)
		if err != nil || !found || work.Hostname != alias.Hostname || work.State != state ||
			work.ConsecutiveErrors != streak || work.Attempts != attempts {
			t.Fatal("next claim did not see the expected DNS operation and counts", found, work, err)
		}
		return work
	}
	assertStale := func(work ServiceEndpointDNSWork) {
		t.Helper()
		work.AvailableAt, work.LastError = f.now.Add(time.Minute), dnsError
		if _, err := d.SaveServiceEndpointDNSWork(ctx, work, f.now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
			t.Fatal("stale DNS worker changed the backoff", err)
		}
	}
	save(canonical, ServiceEndpointDNSPublished, "", 0)
	save(alias, ServiceEndpointDNSPending, dnsError, 1)
	retry := claim("different-worker", ServiceEndpointDNSPending, 1, 2)
	assertStale(alias)
	wrongEpoch := retry
	wrongEpoch.Epoch--
	assertStale(wrongEpoch)
	wrongWorker := retry
	wrongWorker.Worker = "not-the-owner"
	assertStale(wrongWorker)
	save(retry, ServiceEndpointDNSPending, dnsError, 2)
	save(claim("pending", ServiceEndpointDNSPending, 2, 3), ServiceEndpointDNSPending, "", 0)
	save(claim("next-error", ServiceEndpointDNSPending, 0, 4), ServiceEndpointDNSPending, dnsError, 1)
	publishing := claim("old-publish", ServiceEndpointDNSPending, 1, 5)

	if err := d.CloseServiceRun(ctx, service.ID, run.RunID, run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	assertStale(publishing)
	save(claim("first-removal", ServiceEndpointDNSRemoving, 0, 6), ServiceEndpointDNSRemoving, dnsError, 1)
	removing := claim("old-removal", ServiceEndpointDNSRemoving, 1, 7)
	preparing := time.Now()
	replacement, err := d.PrepareServiceRun(ctx, service.ID, publisher, "replacement", f.now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	preparedBy := f.now.Add(time.Since(preparing))
	if err != nil || replacement.RunHostname != alias.Hostname || replacement.RunID == run.RunID {
		t.Fatal("replacement did not bind the same alias to a new run", err)
	}
	assertStale(removing)
	var fresh bool
	var availableAt time.Time
	if err := d.pool.QueryRow(ctx, `SELECT dns_state='pending' AND dns_consecutive_errors=0
	    AND dns_attempts=7 AND dns_last_error IS NULL AND dns_work_owner IS NULL,dns_available_at
	    FROM control.service_endpoints WHERE hostname=$1 AND service_run_id=$2`, alias.Hostname, replacement.RunID).
		Scan(&fresh, &availableAt); err != nil || !fresh || availableAt.Before(f.now) || availableAt.After(preparedBy) {
		t.Fatal("replacement inherited the old removal's DNS backoff", fresh, availableAt, err)
	}
}
