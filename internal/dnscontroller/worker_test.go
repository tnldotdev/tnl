package dnscontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestWorkerCreatesAndVerifiesClaimedZone(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsStoreStub{work: testDNSWork(now)}
	provider := &providerStub{zone: Zone{ID: "Z123", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
	verifier := &verifierStub{verified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)

	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("create iteration = found %v, error %v", found, err)
	}
	if provider.ensureCalls != 1 || store.saved.ProviderZoneID != "Z123" || store.saved.State != "pending" ||
		len(store.saved.Nameservers) != 2 || !store.saved.AvailableAt.Equal(now.Add(time.Second)) {
		t.Fatalf("created work = %#v, provider calls %d", store.saved, provider.ensureCalls)
	}

	store.work = store.saved
	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("verification iteration = found %v, error %v", found, err)
	}
	if verifier.calls != 1 || verifier.domain != "claimed.example.test" || store.saved.State != "ready" {
		t.Fatalf("verified work = %#v, verifier = %#v", store.saved, verifier)
	}
}

func TestWorkerWaitsForSafeRelease(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	work := testDNSWork(now)
	work.State, work.ProviderZoneID = "releasing", "Z123"
	store := &dnsStoreStub{work: work}
	provider := &providerStub{}
	worker := testDNSWorker(t, store, provider, &verifierStub{}, now)

	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("waiting release iteration = found %v, error %v", found, err)
	}
	if provider.releaseCalls != 0 || store.saved.State != "releasing" || !store.saved.AvailableAt.Equal(now.Add(time.Second)) {
		t.Fatalf("waiting release work = %#v, provider calls %d", store.saved, provider.releaseCalls)
	}

	store.work, store.releaseReady = store.saved, true
	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("completed release iteration = found %v, error %v", found, err)
	}
	if provider.releaseCalls != 1 || store.saved.State != "released" {
		t.Fatalf("released work = %#v, provider calls %d", store.saved, provider.releaseCalls)
	}
}

func TestWorkerPersistsProviderFailureForRetry(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsStoreStub{work: testDNSWork(now)}
	provider := &providerStub{err: errors.New("Route 53 unavailable")}
	worker := testDNSWorker(t, store, provider, &verifierStub{}, now)
	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("failed iteration = found %v, error %v", found, err)
	}
	if store.saved.State != "pending" || store.saved.LastError == "" || !store.saved.AvailableAt.Equal(now.Add(time.Second)) {
		t.Fatalf("retried work = %#v", store.saved)
	}
}

func TestWorkerPublishesManagedRouteRecords(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsStoreStub{routeWork: controlstate.DNSRouteWork{
		RouteID: "route_0123456789abcdef0123456789abcdef", DomainID: "domain_1",
		CanonicalHostname: "api.tunnels.example.test", State: controlstate.RouteDNSPending,
		DNSRevision: 1, Attempts: 1, AvailableAt: now,
		WorkerID: "dns_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute),
	}}
	provider := &providerStub{zone: Zone{ID: "ZMANAGED", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
	verifier := &verifierStub{routeVerified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	worker.config.IngressIPv6Addresses = []string{"2001:db8::10"}

	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("route iteration = found %v, error %v", found, err)
	}
	if provider.publishCalls != 1 || provider.record.ZoneID != "ZMANAGED" || provider.record.ClaimedZone ||
		store.routeSaved.State != controlstate.RouteDNSPublished || verifier.routeCalls != 1 {
		t.Fatalf("published route = %#v, provider = %#v, verifier = %#v", store.routeSaved, provider, verifier)
	}
}

func TestWorkerUnavailableDNSPreservesPendingAndReleasingState(t *testing.T) {
	for _, phase := range []string{"fresh", "persisted", "releasing"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
			work := testDNSWork(now)
			if phase != "fresh" {
				work.ProviderZoneID, work.Nameservers = "Z123", []string{"ns-1.example.test", "ns-2.example.test"}
			}
			if phase == "releasing" {
				work.State = "releasing"
			}
			store := &dnsStoreStub{work: work, releaseReady: true}
			failure := errors.New("DNS unavailable")
			provider, verifier := &providerStub{err: failure}, &verifierStub{err: failure}
			worker := testDNSWorker(t, store, provider, verifier, now)
			if found, err := worker.processOne(t.Context()); err != nil || !found {
				t.Fatalf("iteration: found %v, error %v", found, err)
			}
			if store.saved.State != work.State || store.saved.ProviderZoneID != work.ProviderZoneID || store.saved.LastError == "" || !store.saved.AvailableAt.After(now) {
				t.Fatalf("unavailable DNS changed lifecycle: %#v", store.saved)
			}
			if phase == "persisted" && (provider.ensureCalls != 0 || verifier.calls != 1) {
				t.Fatalf("persisted zone was recreated: provider %#v, verifier %#v", provider, verifier)
			}
			if phase == "releasing" && provider.releaseCalls != 1 {
				t.Fatalf("release calls %d", provider.releaseCalls)
			}
		})
	}
}

func testDNSWorker(
	t *testing.T,
	store *dnsStoreStub,
	provider *providerStub,
	verifier *verifierStub,
	now time.Time,
) *Worker {
	t.Helper()
	worker, err := New(store, provider, verifier, Config{
		WorkerID: "dns_worker_test", PollInterval: time.Second, RetryInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now }
	return worker
}

func testDNSWork(now time.Time) controlstate.DNSAuthorityWork {
	return controlstate.DNSAuthorityWork{
		DNSAuthority: controlstate.DNSAuthority{
			Reference: "dns_authority_0123456789abcdef0123456789abcdef",
			TeamID:    "team_1", DomainID: "domain_1", CanonicalDomain: "claimed.example.test", State: "pending",
		},
		Provider: "route53", WorkRevision: 1, Attempts: 1, AvailableAt: now,
		WorkerID: "dns_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute),
	}
}

type dnsStoreStub struct {
	work         controlstate.DNSAuthorityWork
	saved        controlstate.DNSAuthorityWork
	routeWork    controlstate.DNSRouteWork
	routeSaved   controlstate.DNSRouteWork
	releaseReady bool
}

func (s *dnsStoreStub) ClaimDNSAuthorityWork(
	context.Context,
	string,
	time.Time,
	time.Duration,
) (controlstate.DNSAuthorityWork, bool, error) {
	if s.work.Reference == "" {
		return controlstate.DNSAuthorityWork{}, false, nil
	}
	work := s.work
	s.work = controlstate.DNSAuthorityWork{}
	return work, true, nil
}

func (s *dnsStoreStub) SaveDNSAuthorityWork(
	_ context.Context,
	work controlstate.DNSAuthorityWork,
	_ time.Time,
) (controlstate.DNSAuthorityWork, error) {
	s.saved = work
	return work, nil
}

func (s *dnsStoreStub) DNSAuthorityReleaseReady(context.Context, string, time.Time) (bool, error) {
	return s.releaseReady, nil
}

func (s *dnsStoreStub) GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error) {
	return controlstate.DNSAuthority{}, controlstate.ErrDNSAuthorityNotFound
}

func (s *dnsStoreStub) ClaimDNSRouteWork(
	context.Context,
	string,
	time.Time,
	time.Duration,
) (controlstate.DNSRouteWork, bool, error) {
	if s.routeWork.RouteID == "" {
		return controlstate.DNSRouteWork{}, false, nil
	}
	work := s.routeWork
	s.routeWork = controlstate.DNSRouteWork{}
	return work, true, nil
}

func (s *dnsStoreStub) SaveDNSRouteWork(
	_ context.Context,
	work controlstate.DNSRouteWork,
	_ time.Time,
) (controlstate.DNSRouteWork, error) {
	s.routeSaved = work
	return work, nil
}

type providerStub struct {
	zone         Zone
	err          error
	ensureCalls  int
	releaseCalls int
	publishCalls int
	removeCalls  int
	record       RouteRecord
}

func (p *providerStub) EnsureClaimedZone(context.Context, controlstate.DNSAuthorityWork) (Zone, error) {
	p.ensureCalls++
	return p.zone, p.err
}

func (p *providerStub) ReleaseClaimedZone(context.Context, controlstate.DNSAuthorityWork) error {
	p.releaseCalls++
	return p.err
}

func (p *providerStub) PublishRoute(_ context.Context, record RouteRecord) (Zone, error) {
	p.publishCalls++
	p.record = record
	return p.zone, p.err
}

func (p *providerStub) RemoveRoute(_ context.Context, record RouteRecord) (Zone, error) {
	p.removeCalls++
	p.record = record
	return p.zone, p.err
}

type verifierStub struct {
	verified      bool
	err           error
	calls         int
	domain        string
	routeVerified bool
	routeCalls    int
}

func (v *verifierStub) VerifyRoute(
	context.Context,
	string,
	[]string,
	[]string,
	[]string,
) (bool, error) {
	v.routeCalls++
	return v.routeVerified, v.err
}

func (v *verifierStub) Verify(_ context.Context, domain string, _ []string) (bool, error) {
	v.calls++
	v.domain = domain
	return v.verified, v.err
}
