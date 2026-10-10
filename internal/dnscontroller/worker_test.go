package dnscontroller

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestWorkerCreatesAndVerifiesCustomZone(t *testing.T) {
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

func TestWorkerDoesNotStarvePublicURLWorkBehindAuthorityBacklog(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsStoreStub{work: testDNSWork(now), publicURLWork: claimedRouteWork(now)}
	worker := testDNSWorker(t, store, &providerStub{zone: Zone{ID: "ZMANAGED"}}, &verifierStub{publicURLVerified: true}, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "claimed.example.test", "ZMANAGED"
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("first authority iteration = %t, %v", found, err)
	}
	// control can always have another claimable authority. the other queue
	// must still make progress while authority work remains available.
	store.work = testDNSWork(now)
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("second iteration = %t, %v", found, err)
	}
	if store.publicURLSaves != 1 {
		t.Fatalf("public URL work was starved: %d saves", store.publicURLSaves)
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
	metrics := observability.New("control")
	worker.config.Observer = metrics
	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("failed iteration = found %v, error %v", found, err)
	}
	if store.saved.State != "pending" || store.saved.LastError == "" || !store.saved.AvailableAt.Equal(now.Add(time.Second)) {
		t.Fatalf("retried work = %#v", store.saved)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		`tnl_control_dns_work_duration_seconds_count{kind="authority",outcome="error",phase="provider"} 1`,
		`tnl_control_dns_work_duration_seconds_count{kind="authority",outcome="error",phase="advance"} 1`,
	} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("saved retry missing metric %q", want)
		}
	}
}

func TestWorkerSchedulesRetryFromFailureCompletion(t *testing.T) {
	started := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"authority", "route"} {
		t.Run(kind, func(t *testing.T) {
			now := started
			store := new(dnsStoreStub)
			if kind == "authority" {
				store.work = testDNSWork(started)
			} else {
				store.publicURLWork = claimedRouteWork(started)
			}
			provider := &providerStub{err: errors.New("provider unavailable"), beforeCall: func() {
				now = now.Add(5 * time.Second)
			}}
			worker := testDNSWorker(t, store, provider, &verifierStub{}, started)
			worker.now = func() time.Time { return now }
			worker.config.ManagedDomain, worker.config.ManagedZoneID = "claimed.example.test", "Z123"
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			availableAt := store.saved.AvailableAt
			delay := time.Second
			if kind == "route" {
				availableAt = store.publicURLSaved.AvailableAt
				delay = 4 * time.Second
			}
			if want := now.Add(delay); !availableAt.Equal(want) {
				t.Fatalf("available at = %s, want %s", availableAt, want)
			}
		})
	}
}

func TestWorkerPublishesManagedRouteRecords(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsStoreStub{publicURLWork: controlstate.DNSPublicURLWork{
		PublicURLID: "public_url_0123456789abcdef0123456789abcdef", IngressPoolID: "ingress-a", DomainID: "domain_1",
		CanonicalHostname: "api.tunnels.example.test", State: controlstate.PublicURLDNSPending,
		DNSRevision: 1, Attempts: 1, AvailableAt: now,
		WorkerID: "dns_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute),
	}}
	provider := &providerStub{zone: Zone{ID: "ZMANAGED", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
	verifier := &verifierStub{publicURLVerified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	worker.config.IngressIPv6Addresses = []string{"2001:db8::10"}

	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("route iteration = found %v, error %v", found, err)
	}
	if provider.publishCalls != 1 || provider.record.ZoneID != "ZMANAGED" || provider.record.CustomZone ||
		store.publicURLSaved.State != controlstate.PublicURLDNSPublished || verifier.publicURLCalls != 1 {
		t.Fatalf("published route = %#v, provider = %#v, verifier = %#v", store.publicURLSaved, provider, verifier)
	}
}

func TestNestedMemberURLUsesItsImmediateParentWildcard(t *testing.T) {
	now := time.Now()
	store := &dnsStoreStub{publicURLWork: controlstate.DNSPublicURLWork{
		PublicURLID: "url_nested", IngressPoolID: "ingress-a", DomainID: "domain_1", CanonicalHostname: "api.shop.member.tunnels.example.test",
		Namespace: "member.tunnels.example.test", PublicURLScope: controlstate.PublicURLScopeMember, State: controlstate.PublicURLDNSPending,
		DNSRevision: 1, AvailableAt: now, WorkerID: "dns_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute),
	}}
	provider := &providerStub{zone: Zone{ID: "ZMANAGED"}}
	worker := testDNSWorker(t, store, provider, &verifierStub{publicURLVerified: true}, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("nested URL DNS work = %t, %v", found, err)
	}
	if provider.publishCalls != 1 || provider.record.WildcardHostname != "*.shop.member.tunnels.example.test" ||
		provider.record.CanonicalHostname != "api.shop.member.tunnels.example.test" {
		t.Fatal("nested URL did not use its immediate parent wildcard")
	}
}

func TestWorkerUsesAuthorizedManagedWildcardRoots(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	worker := testDNSWorker(t, &dnsStoreStub{}, &providerStub{}, &verifierStub{}, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "routes.example.test", "ZMANAGED"
	for _, test := range []struct{ hostname, namespace, wildcard string }{
		{"app.routes.example.test", "routes.example.test", "*.routes.example.test"},
		{"app.alex.studio.routes.example.test", "alex.studio.routes.example.test", "*.alex.studio.routes.example.test"},
		{"api.preview.alex.studio.routes.example.test", "alex.studio.routes.example.test", "*.preview.alex.studio.routes.example.test"},
	} {
		record, _, ready, err := worker.publicURLRecord(t.Context(), controlstate.DNSPublicURLWork{
			PublicURLID: "url_test", IngressPoolID: "ingress-a", DomainID: "managed", CanonicalHostname: test.hostname, Namespace: test.namespace,
		})
		if err != nil || !ready || record.WildcardHostname != test.wildcard || record.Namespace != test.namespace {
			t.Errorf("record for %s = %#v, ready %t, error %v", test.hostname, record, ready, err)
		}
	}
}

func TestWorkerUsesPinnedIngressPoolForMemberWildcard(t *testing.T) {
	now := time.Now()
	store := &dnsStoreStub{pool: controlstate.IngressPool{
		ID: "ingress-b", State: "enabled",
		IPv4Address: netip.MustParseAddr("192.0.2.20"), IPv6Address: netip.MustParseAddr("2001:db8::20"),
	}}
	worker := testDNSWorker(t, store, &providerStub{}, &verifierStub{}, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	record, _, ready, err := worker.publicURLRecord(t.Context(), controlstate.DNSPublicURLWork{
		PublicURLID: "url_second_pool", IngressPoolID: "ingress-b", DomainID: "domain_1",
		CanonicalHostname: "api.member.tunnels.example.test", Namespace: "member.tunnels.example.test",
	})
	if err != nil || !ready || record.WildcardHostname != "*.member.tunnels.example.test" ||
		!reflect.DeepEqual(record.IngressIPv4Addresses, []string{"192.0.2.20"}) ||
		!reflect.DeepEqual(record.IngressIPv6Addresses, []string{"2001:db8::20"}) {
		t.Fatalf("member URL used another pool's ingress address: record=%#v ready=%t err=%v", record, ready, err)
	}
	store.pool.State = "disabled"
	if _, _, ready, err := worker.publicURLRecord(t.Context(), controlstate.DNSPublicURLWork{
		PublicURLID: "url_second_pool", IngressPoolID: "ingress-b", DomainID: "domain_1",
		CanonicalHostname: "api.member.tunnels.example.test", Namespace: "member.tunnels.example.test",
	}); err != nil || ready {
		t.Fatalf("disabled secondary pool issued public URL DNS: ready=%t err=%v", ready, err)
	}
}

func TestWorkerUsesOrganizationNamespaceOnCustomDomain(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	authority := testDNSWork(now).DNSAuthority
	authority.State, authority.ProviderZoneID = controlstate.DNSAuthorityReady, "ZCLAIMED"
	worker := testDNSWorker(t, &dnsStoreStub{authority: authority}, &providerStub{}, &verifierStub{}, now)
	work := claimedRouteWork(now)
	work.Namespace = "alex.studio.claimed.example.test"
	work.CanonicalHostname = "app." + work.Namespace
	record, _, ready, err := worker.publicURLRecord(t.Context(), work)
	if err != nil || !ready || record.WildcardHostname != "*."+work.Namespace || !record.CustomZone {
		t.Fatalf("custom organization wildcard = %#v, ready %t, error %v", record, ready, err)
	}
}

func TestWorkerManagedMemberWildcardPersistsAcrossPublicURLRemoval(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	work := controlstate.DNSPublicURLWork{
		PublicURLID: "public_url_0123456789abcdef0123456789abcdef", IngressPoolID: "ingress-a", DomainID: "domain_1",
		CanonicalHostname: "api.member.tunnels.example.test", Namespace: "member.tunnels.example.test", PublicURLScope: controlstate.PublicURLScopeMember,
		State: controlstate.PublicURLDNSPending, DNSRevision: 1, Attempts: 1, AvailableAt: now,
		WorkerID: "dns_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute),
	}
	store := &dnsStoreStub{publicURLWork: work}
	provider := &providerStub{zone: Zone{ID: "ZMANAGED", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
	verifier := &verifierStub{publicURLVerified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("publish wildcard = %t, %v", found, err)
	}
	if provider.publishCalls != 1 || provider.record.CanonicalHostname != work.CanonicalHostname ||
		provider.record.WildcardHostname != "*.member.tunnels.example.test" ||
		verifier.publicURLHostname != provider.record.WildcardHostname ||
		store.publicURLSaved.State != controlstate.PublicURLDNSPublished {
		t.Fatalf("wildcard publication = %#v, %#v, %#v", provider, verifier, store.publicURLSaved)
	}
	work.State = controlstate.PublicURLDNSRemoving
	store.publicURLWork = work
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("remove public URL = %t, %v", found, err)
	}
	if provider.removeCalls != 0 || provider.publishCalls != 1 || verifier.publicURLCalls != 1 ||
		store.publicURLSaved.State != controlstate.PublicURLDNSRemoved {
		t.Fatalf("namespace wildcard changed during public URL removal = %#v, %#v", provider, store.publicURLSaved)
	}
}

func TestWorkerCustomMemberWildcardUsesCustomZone(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	work := claimedRouteWork(now)
	work.CanonicalHostname = "api.member.claimed.example.test"
	work.Namespace = "member.claimed.example.test"
	work.PublicURLScope = controlstate.PublicURLScopeMember
	authority := testDNSWork(now).DNSAuthority
	authority.State, authority.ProviderZoneID = controlstate.DNSAuthorityReady, "ZCLAIMED"
	authority.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
	store := &dnsStoreStub{publicURLWork: work, authority: authority}
	provider := &providerStub{zone: Zone{ID: "ZCLAIMED"}}
	verifier := &verifierStub{publicURLVerified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("claimed member publish = %t, %v", found, err)
	}
	if !provider.record.CustomZone || provider.record.WildcardHostname != "*.member.claimed.example.test" ||
		verifier.publicURLHostname != provider.record.WildcardHostname ||
		store.publicURLSaved.State != controlstate.PublicURLDNSPublished {
		t.Fatalf("claimed wildcard publication = %#v, %#v", provider.record, store.publicURLSaved)
	}
	work.State = controlstate.PublicURLDNSRemoving
	store.publicURLWork = work
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("claimed member removal = %t, %v", found, err)
	}
	if provider.removeCalls != 0 || store.publicURLSaved.State != controlstate.PublicURLDNSRemoved {
		t.Fatalf("claimed wildcard was removed with URL: %#v, %#v", provider, store.publicURLSaved)
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
			TeamID:    "team_1", DomainID: "domain_1", CanonicalDomain: "claimed.example.test", State: controlstate.DNSAuthorityPending,
		},
		Provider: "route53", WorkRevision: 1, Attempts: 1, AvailableAt: now,
		WorkerID: "dns_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute),
	}
}

type dnsStoreStub struct {
	work                              controlstate.DNSAuthorityWork
	saved                             controlstate.DNSAuthorityWork
	publicURLWork                     controlstate.DNSPublicURLWork
	publicURLSaved                    controlstate.DNSPublicURLWork
	releaseReady                      bool
	authority                         controlstate.DNSAuthority
	pool                              controlstate.IngressPool
	authorityReferences               []string
	getErr, saveErr, publicURLSaveErr error
	saves, publicURLSaves             int
	savedAt, publicURLSavedAt         time.Time
}

func (s *dnsStoreStub) GetIngressPool(_ context.Context, id string) (controlstate.IngressPool, error) {
	if s.pool.ID != "" {
		return s.pool, nil
	}
	return controlstate.IngressPool{ID: id, State: "disabled"}, nil
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
	now time.Time,
) (controlstate.DNSAuthorityWork, error) {
	s.saves++
	s.saved = work
	s.savedAt = now
	return work, s.saveErr
}

func (s *dnsStoreStub) DNSAuthorityReleaseReady(context.Context, string, time.Time) (bool, error) {
	return s.releaseReady, nil
}

func (s *dnsStoreStub) GetDNSAuthority(_ context.Context, reference string) (controlstate.DNSAuthority, error) {
	s.authorityReferences = append(s.authorityReferences, reference)
	return s.authority, s.getErr
}

func (s *dnsStoreStub) ClaimDNSPublicURLWork(
	context.Context,
	string,
	time.Time,
	time.Duration,
) (controlstate.DNSPublicURLWork, bool, error) {
	if s.publicURLWork.PublicURLID == "" {
		return controlstate.DNSPublicURLWork{}, false, nil
	}
	work := s.publicURLWork
	s.publicURLWork = controlstate.DNSPublicURLWork{}
	return work, true, nil
}

func (s *dnsStoreStub) SaveDNSPublicURLWork(
	_ context.Context,
	work controlstate.DNSPublicURLWork,
	now time.Time,
) (controlstate.DNSPublicURLWork, error) {
	s.publicURLSaves++
	s.publicURLSaved = work
	s.publicURLSavedAt = now
	return work, s.publicURLSaveErr
}

type providerStub struct {
	zone                    Zone
	err                     error
	ensureCalls             int
	releaseCalls            int
	publishCalls            int
	removeCalls             int
	record                  PublicURLRecord
	ensureWork, releaseWork controlstate.DNSAuthorityWork
	beforeCall              func()
}

func (p *providerStub) EnsureCustomZone(_ context.Context, work controlstate.DNSAuthorityWork) (Zone, error) {
	p.ensureCalls++
	p.ensureWork = work
	if p.beforeCall != nil {
		p.beforeCall()
	}
	return p.zone, p.err
}

func (p *providerStub) ReleaseCustomZone(_ context.Context, work controlstate.DNSAuthorityWork) error {
	p.releaseCalls++
	p.releaseWork = work
	if p.beforeCall != nil {
		p.beforeCall()
	}
	return p.err
}

func (p *providerStub) PublishPublicURL(_ context.Context, record PublicURLRecord) (Zone, error) {
	p.publishCalls++
	p.record = record
	if p.beforeCall != nil {
		p.beforeCall()
	}
	return p.zone, p.err
}

func (p *providerStub) RemovePublicURL(_ context.Context, record PublicURLRecord) (Zone, error) {
	p.removeCalls++
	p.record = record
	if p.beforeCall != nil {
		p.beforeCall()
	}
	return p.zone, p.err
}

type verifierStub struct {
	verified                                   bool
	err                                        error
	calls                                      int
	domain                                     string
	publicURLVerified                          bool
	publicURLCalls                             int
	publicURLHostname                          string
	routeIPv4, routeIPv6, publicURLNameservers []string
}

func (v *verifierStub) VerifyPublicURL(
	_ context.Context,
	hostname string,
	ipv4 []string,
	ipv6 []string,
	nameservers []string,
) (bool, error) {
	v.publicURLCalls++
	v.publicURLHostname = hostname
	v.routeIPv4, v.routeIPv6, v.publicURLNameservers = ipv4, ipv6, nameservers
	return v.publicURLVerified, v.err
}

func claimedRouteWork(now time.Time) controlstate.DNSPublicURLWork {
	return controlstate.DNSPublicURLWork{
		PublicURLID: "public_url_claimed", IngressPoolID: "ingress-a", DomainID: "domain_1", DNSAuthorityReference: "dns_authority_0123456789abcdef0123456789abcdef",
		CanonicalHostname: "api.claimed.example.test", State: controlstate.PublicURLDNSPending,
		DNSRevision: 7, Attempts: 3, WorkerID: "dns_worker_test", WorkEpoch: 9, WorkExpiresAt: now.Add(time.Minute),
	}
}

func TestWorkerReconcilesClaimedRoutePublicationAndRemoval(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                                      string
		removing, propagated, providerNameservers bool
	}{
		{"publish propagated", false, true, false},
		{"publish waiting", false, false, true},
		{"remove propagated", true, true, true},
		{"remove waiting", true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := claimedRouteWork(now)
			authority := testDNSWork(now).DNSAuthority
			authority.State, authority.ProviderZoneID = "ready", "ZCLAIMED"
			authority.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
			if test.removing {
				work.State, authority.State = controlstate.PublicURLDNSRemoving, "releasing"
			}
			store := &dnsStoreStub{publicURLWork: work, authority: authority}
			provider := &providerStub{zone: Zone{ID: "ZCLAIMED"}}
			wantNameservers := authority.Nameservers
			if test.providerNameservers {
				provider.zone.Nameservers = []string{"ns-3.example.test", "ns-4.example.test"}
				wantNameservers = provider.zone.Nameservers
			}
			verifier := &verifierStub{publicURLVerified: test.propagated}
			worker := testDNSWorker(t, store, provider, verifier, now)
			worker.config.IngressIPv4Addresses, worker.config.IngressIPv6Addresses = []string{"192.0.2.10"}, []string{"2001:db8::10"}
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			wantRecord := PublicURLRecord{
				ZoneID: "ZCLAIMED", ZoneDomain: "claimed.example.test", CustomZone: true,
				AuthorityReference: authority.Reference, TeamID: "team_1", DomainID: "domain_1", PublicURLID: "public_url_claimed",
				CanonicalHostname: "api.claimed.example.test", IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"},
			}
			if !reflect.DeepEqual(provider.record, wantRecord) || !reflect.DeepEqual(store.authorityReferences, []string{authority.Reference}) {
				t.Fatalf("provider record = %#v, authority lookups = %v", provider.record, store.authorityReferences)
			}
			wantIPv4, wantIPv6 := wantRecord.IngressIPv4Addresses, wantRecord.IngressIPv6Addresses
			if test.removing {
				wantIPv4, wantIPv6 = nil, nil
			}
			if verifier.publicURLCalls != 1 || verifier.publicURLHostname != "api.claimed.example.test" ||
				!reflect.DeepEqual(verifier.routeIPv4, wantIPv4) || !reflect.DeepEqual(verifier.routeIPv6, wantIPv6) || !reflect.DeepEqual(verifier.publicURLNameservers, wantNameservers) {
				t.Fatalf("verification = %#v", verifier)
			}
			if test.removing && (provider.removeCalls != 1 || provider.publishCalls != 0) || !test.removing && (provider.publishCalls != 1 || provider.removeCalls != 0) {
				t.Fatalf("provider calls = %#v", provider)
			}
			want := work
			want.AvailableAt = now.Add(time.Second)
			if test.propagated {
				want.AvailableAt = time.Time{}
				want.State = controlstate.PublicURLDNSPublished
				if test.removing {
					want.State = controlstate.PublicURLDNSRemoved
				}
			}
			if !reflect.DeepEqual(store.publicURLSaved, want) || store.publicURLSaves != 1 || !store.publicURLSavedAt.Equal(now) {
				t.Fatalf("saved = %#v, want %#v", store.publicURLSaved, want)
			}
		})
	}
}

func TestWorkerClaimedRouteAuthorityBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, domain string
		state        controlstate.DNSAuthorityState
		zone         string
		lookupErr    error
		wantState    controlstate.PublicURLDNSState
		wantDelay    time.Duration
	}{
		{"pending authority", "claimed.example.test", controlstate.DNSAuthorityPending, "", nil, controlstate.PublicURLDNSPending, time.Second},
		{"wrong domain", "other.example.test", controlstate.DNSAuthorityReady, "Z123", nil, controlstate.PublicURLDNSFailed, 0},
		{"released authority", "claimed.example.test", controlstate.DNSAuthorityReleased, "Z123", nil, controlstate.PublicURLDNSFailed, 0},
		{"missing zone", "claimed.example.test", controlstate.DNSAuthorityReady, "", nil, controlstate.PublicURLDNSFailed, 0},
		{"lookup failure", "claimed.example.test", controlstate.DNSAuthorityReady, "Z123", errors.New("lookup unavailable"), controlstate.PublicURLDNSPending, 4 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := claimedRouteWork(now)
			authority := testDNSWork(now).DNSAuthority
			authority.CanonicalDomain, authority.State, authority.ProviderZoneID = test.domain, test.state, test.zone
			store := &dnsStoreStub{publicURLWork: work, authority: authority, getErr: test.lookupErr}
			provider, verifier := &providerStub{}, &verifierStub{}
			worker := testDNSWorker(t, store, provider, verifier, now)
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			wantAvailable := time.Time{}
			if test.wantDelay != 0 {
				wantAvailable = now.Add(test.wantDelay)
			}
			if store.publicURLSaved.State != test.wantState || !store.publicURLSaved.AvailableAt.Equal(wantAvailable) ||
				provider.publishCalls != 0 || provider.removeCalls != 0 || verifier.publicURLCalls != 0 {
				t.Fatalf("authority boundary: saved %#v, provider %#v, verifier %#v", store.publicURLSaved, provider, verifier)
			}
			if (store.publicURLSaved.LastError != "") != (test.state != controlstate.DNSAuthorityPending) {
				t.Fatalf("last error = %q", store.publicURLSaved.LastError)
			}
		})
	}
}

func TestWorkerPersistenceFailureAfterExternalSuccess(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	failure := errors.New("database connection lost")
	for _, kind := range []string{"authority", "route"} {
		t.Run(kind, func(t *testing.T) {
			store := &dnsStoreStub{saveErr: failure, publicURLSaveErr: failure}
			provider := &providerStub{zone: Zone{ID: "Z123", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
			verifier := &verifierStub{publicURLVerified: true}
			worker := testDNSWorker(t, store, provider, verifier, now)
			if kind == "authority" {
				store.work = testDNSWork(now)
			} else {
				store.publicURLWork = claimedRouteWork(now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "claimed.example.test", "Z123"
			}
			if found, err := worker.processOne(t.Context()); !found || !errors.Is(err, failure) {
				t.Fatalf("process = %v, %v", found, err)
			}
			if kind == "authority" {
				if provider.ensureCalls != 1 || store.saves != 1 || store.saved.ProviderZoneID != "Z123" || store.saved.LastError != "" {
					t.Fatalf("authority save = %#v", store)
				}
			} else if provider.publishCalls != 1 || verifier.publicURLCalls != 1 || store.publicURLSaves != 1 || store.publicURLSaved.State != controlstate.PublicURLDNSPublished || store.publicURLSaved.LastError != "" {
				t.Fatalf("route save = %#v", store)
			}
			// a failed save leaves the original durable work available for a later claim.
			store.saveErr, store.publicURLSaveErr = nil, nil
			if kind == "authority" {
				store.work = testDNSWork(now)
			} else {
				store.publicURLWork = claimedRouteWork(now)
			}
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("retry = %v, %v", found, err)
			}
			if kind == "authority" {
				if provider.ensureCalls != 2 || !reflect.DeepEqual(provider.ensureWork, testDNSWork(now)) || store.saves != 2 {
					t.Fatalf("authority retry = %#v, %#v", provider, store)
				}
			} else if provider.publishCalls != 2 || provider.record.PublicURLID != "public_url_claimed" || store.publicURLSaves != 2 {
				t.Fatalf("route retry = %#v, %#v", provider, store)
			}
		})
	}
}

func TestWorkerRouteFailuresPreserveLifecycleOrFailTerminally(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, state := range []controlstate.PublicURLDNSState{controlstate.PublicURLDNSPending, controlstate.PublicURLDNSRemoving} {
		for _, test := range []struct {
			name                     string
			providerErr, verifierErr error
			terminal                 bool
		}{
			{"provider unavailable", errors.New("provider unavailable"), nil, false},
			{"ownership conflict", terminalf("foreign ownership"), nil, true},
			{"verification unavailable", nil, errors.New("DNS unavailable"), false},
		} {
			t.Run(string(state)+"/"+test.name, func(t *testing.T) {
				work := claimedRouteWork(now)
				work.State, work.Attempts = state, 20
				store := &dnsStoreStub{publicURLWork: work}
				provider, verifier := &providerStub{err: test.providerErr}, &verifierStub{err: test.verifierErr}
				worker := testDNSWorker(t, store, provider, verifier, now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "claimed.example.test", "Z123"
				if found, err := worker.processOne(t.Context()); !found || err != nil {
					t.Fatalf("process = %v, %v", found, err)
				}
				wantState, wantAt := state, now.Add(time.Minute)
				if test.terminal {
					wantState, wantAt = controlstate.PublicURLDNSFailed, time.Time{}
				}
				wantReason := "server.dns_failed"
				if test.terminal {
					wantReason = "server.dns_conflict"
				}
				if store.publicURLSaved.State != wantState || !store.publicURLSaved.AvailableAt.Equal(wantAt) || store.publicURLSaved.LastError != wantReason ||
					store.publicURLSaved.DNSRevision != 7 || store.publicURLSaved.WorkEpoch != 9 || store.publicURLSaves != 1 {
					t.Fatalf("saved failure = %#v", store.publicURLSaved)
				}
				wantVerifications := 0
				if test.providerErr == nil {
					wantVerifications = 1
				}
				if verifier.publicURLCalls != wantVerifications {
					t.Fatalf("verification calls = %d", verifier.publicURLCalls)
				}
			})
		}
	}
}

func TestWorkerCancellationDoesNotPersistRetry(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"authority", "route"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &dnsStoreStub{}
			provider := &providerStub{err: context.Canceled, beforeCall: cancel}
			worker := testDNSWorker(t, store, provider, &verifierStub{}, now)
			if kind == "authority" {
				store.work = testDNSWork(now)
			} else {
				store.publicURLWork = claimedRouteWork(now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "claimed.example.test", "Z123"
			}
			if found, err := worker.processOne(ctx); !found || !errors.Is(err, context.Canceled) {
				t.Fatalf("process = %v, %v", found, err)
			}
			if store.saves != 0 || store.publicURLSaves != 0 {
				t.Fatalf("canceled operation persisted: %#v", store)
			}
		})
	}
}

func (v *verifierStub) Verify(_ context.Context, domain string, _ []string) (bool, error) {
	v.calls++
	v.domain = domain
	return v.verified, v.err
}
