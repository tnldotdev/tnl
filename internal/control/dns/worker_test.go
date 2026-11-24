package dns

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
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

func TestWorkerDoesNotStarveServiceEndpointWorkBehindAuthorityBacklog(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsStoreStub{work: testDNSWork(now), serviceEndpointWork: testServiceDNSWork(now)}
	worker := testDNSWorker(t, store, &providerStub{zone: Zone{ID: "ZMANAGED"}}, &verifierStub{addressVerified: true}, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("first authority iteration = %t, %v", found, err)
	}
	// control can always have another claimable authority. the other queue
	// must still make progress while authority work remains available.
	store.work = testDNSWork(now)
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("second iteration = %t, %v", found, err)
	}
	if store.serviceEndpointSaves != 1 {
		t.Fatalf("service endpoint work was starved: %d saves", store.serviceEndpointSaves)
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
		`tnl_control_dns_work_duration_seconds_count{tnl_dns_kind="authority",tnl_operation="provider",tnl_outcome="error"} 1`,
		`tnl_control_dns_work_duration_seconds_count{tnl_dns_kind="authority",tnl_operation="advance",tnl_outcome="error"} 1`,
	} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("saved retry missing metric %q", want)
		}
	}
}

func TestWorkerSchedulesRetryFromFailureCompletion(t *testing.T) {
	started := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"authority", "service"} {
		t.Run(kind, func(t *testing.T) {
			now := started
			store := new(dnsStoreStub)
			if kind == "authority" {
				store.work = testDNSWork(started)
			} else {
				store.serviceEndpointWork = testServiceDNSWork(started)
				store.serviceEndpointWork.Attempts, store.serviceEndpointWork.ConsecutiveErrors = 30, 2
			}
			provider := &providerStub{err: errors.New("provider unavailable"), beforeCall: func() {
				now = now.Add(5 * time.Second)
			}}
			worker := testDNSWorker(t, store, provider, &verifierStub{}, started)
			worker.now = func() time.Time { return now }
			worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "Z123"
			worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			availableAt := store.saved.AvailableAt
			delay := time.Second
			if kind == "service" {
				availableAt = store.serviceEndpointSaved.AvailableAt
				delay = 4 * time.Second
			}
			if want := now.Add(delay); !availableAt.Equal(want) {
				t.Fatalf("available at = %s, want %s", availableAt, want)
			}
		})
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
	serviceEndpointWork    controlstate.ServiceEndpointDNSWork
	serviceEndpointSaved   controlstate.ServiceEndpointDNSWork
	serviceEndpointClaims  int
	serviceEndpointSaves   int
	serviceEndpointSavedAt time.Time
	serviceEndpointLocked  bool
	work                   controlstate.DNSAuthorityWork
	saved                  controlstate.DNSAuthorityWork
	releaseReady           bool
	authority              controlstate.DNSAuthority
	pool                   controlstate.IngressPool
	authorityReferences    []string
	getErr, saveErr        error
	saves                  int
	savedAt                time.Time
}

func (s *dnsStoreStub) ClaimServiceEndpointDNSWork(context.Context, string, time.Time, time.Duration) (controlstate.ServiceEndpointDNSWork, bool, error) {
	s.serviceEndpointClaims++
	work := s.serviceEndpointWork
	s.serviceEndpointWork = controlstate.ServiceEndpointDNSWork{}
	return work, work.Hostname != "", nil
}

func (s *dnsStoreStub) SaveServiceEndpointDNSWork(_ context.Context, work controlstate.ServiceEndpointDNSWork, now time.Time) (controlstate.ServiceEndpointDNSWork, error) {
	s.serviceEndpointSaves++
	s.serviceEndpointSaved = work
	s.serviceEndpointSavedAt = now
	return work, s.saveErr
}

func (s *dnsStoreStub) ValidateServiceEndpointDNSWork(context.Context, controlstate.ServiceEndpointDNSWork, time.Time) error {
	if !s.serviceEndpointLocked {
		return controlstate.ErrServiceEndpointDNSWorkStale
	}
	return nil
}

func (s *dnsStoreStub) WithDNSRecordLock(_ context.Context, _ string, run func() error) error {
	s.serviceEndpointLocked = true
	defer func() { s.serviceEndpointLocked = false }()
	return run()
}

func (s *dnsStoreStub) GetIngressPool(_ context.Context, id string) (controlstate.IngressPool, error) {
	if s.pool.ID != "" {
		return s.pool, nil
	}
	return controlstate.IngressPool{ID: id, State: controlstate.IngressPoolDisabled}, nil
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

type providerStub struct {
	zone                    Zone
	err                     error
	ensureCalls             int
	releaseCalls            int
	publishCalls            int
	removeCalls             int
	exactRecordsRemain      bool
	record                  AddressRecord
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

func (p *providerStub) PublishAddress(_ context.Context, record AddressRecord) (Zone, error) {
	p.publishCalls++
	p.record = record
	if p.beforeCall != nil {
		p.beforeCall()
	}
	return p.zone, p.err
}

func (p *providerStub) RemoveAddress(_ context.Context, record AddressRecord) (AddressRemoval, error) {
	p.removeCalls++
	p.record = record
	if p.beforeCall != nil {
		p.beforeCall()
	}
	return AddressRemoval{Zone: p.zone, ExactRecordsAbsent: !p.exactRecordsRemain}, p.err
}

type verifierStub struct {
	verified                                 bool
	err                                      error
	calls                                    int
	domain                                   string
	addressVerified                          bool
	addressCalls                             int
	removalCalls                             int
	addressHostname                          string
	routeIPv4, routeIPv6, addressNameservers []string
}

func (v *verifierStub) VerifyAddressRemoval(_ context.Context, record AddressRecord, nameservers []string) (bool, error) {
	v.removalCalls++
	v.addressHostname, v.addressNameservers = record.CanonicalHostname, nameservers
	v.routeIPv4, v.routeIPv6 = nil, nil
	return v.addressVerified, v.err
}

func (v *verifierStub) VerifyAddress(
	_ context.Context,
	hostname string,
	ipv4 []string,
	ipv6 []string,
	nameservers []string,
) (bool, error) {
	v.addressCalls++
	v.addressHostname = hostname
	v.routeIPv4, v.routeIPv6, v.addressNameservers = ipv4, ipv6, nameservers
	return v.addressVerified, v.err
}

func testServiceDNSWork(now time.Time) controlstate.ServiceEndpointDNSWork {
	return controlstate.ServiceEndpointDNSWork{
		Hostname: "api.tunnels.example.test", ServiceID: "svc_1", OwnerID: "dpl_1",
		DomainID: "domain_1", PoolID: controlstate.PrimaryIngressPoolID, Public: true, State: controlstate.ServiceEndpointDNSPending,
		Revision: 7, Attempts: 1, Worker: "dns_worker_test", Epoch: 9, ExpiresAt: now.Add(time.Minute),
	}
}

func TestWorkerReconcilesCustomServiceEndpointPublicationAndRemoval(t *testing.T) {
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
			work := testServiceDNSWork(now)
			work.Hostname = "api.claimed.example.test"
			work.AuthorityReference = testDNSWork(now).Reference
			authority := testDNSWork(now).DNSAuthority
			authority.State, authority.ProviderZoneID = "ready", "ZCLAIMED"
			authority.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
			if test.removing {
				work.State, authority.State = controlstate.ServiceEndpointDNSRemoving, "releasing"
			}
			store := &dnsStoreStub{serviceEndpointWork: work, authority: authority}
			provider := &providerStub{zone: Zone{ID: "ZCLAIMED"}}
			wantNameservers := authority.Nameservers
			if test.providerNameservers {
				provider.zone.Nameservers = []string{"ns-3.example.test", "ns-4.example.test"}
				wantNameservers = provider.zone.Nameservers
			}
			verifier := &verifierStub{addressVerified: test.propagated}
			worker := testDNSWorker(t, store, provider, verifier, now)
			worker.config.IngressIPv4Addresses, worker.config.IngressIPv6Addresses = []string{"192.0.2.10"}, []string{"2001:db8::10"}
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			wantRecord := AddressRecord{
				ZoneID: "ZCLAIMED", ZoneDomain: "claimed.example.test", CustomZone: true,
				AuthorityReference: authority.Reference, TeamID: "team_1", DomainID: "domain_1", Owner: ServiceOwner(work.OwnerID),
				CanonicalHostname: "api.claimed.example.test", IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"},
			}
			if test.removing {
				wantRecord.IngressIPv4Addresses, wantRecord.IngressIPv6Addresses = nil, nil
			}
			if !reflect.DeepEqual(provider.record, wantRecord) || !reflect.DeepEqual(store.authorityReferences, []string{authority.Reference}) {
				t.Fatalf("provider record = %#v, authority lookups = %v", provider.record, store.authorityReferences)
			}
			wantIPv4, wantIPv6 := wantRecord.IngressIPv4Addresses, wantRecord.IngressIPv6Addresses
			if test.removing {
				wantIPv4, wantIPv6 = nil, nil
			}
			if verifier.addressCalls+verifier.removalCalls != 1 || (verifier.removalCalls == 1) != test.removing || verifier.addressHostname != "api.claimed.example.test" ||
				!reflect.DeepEqual(verifier.routeIPv4, wantIPv4) || !reflect.DeepEqual(verifier.routeIPv6, wantIPv6) || !reflect.DeepEqual(verifier.addressNameservers, wantNameservers) {
				t.Fatalf("verification = %#v", verifier)
			}
			if test.removing && (provider.removeCalls != 1 || provider.publishCalls != 0) || !test.removing && (provider.publishCalls != 1 || provider.removeCalls != 0) {
				t.Fatalf("provider calls = %#v", provider)
			}
			want := work
			want.AvailableAt = now.Add(time.Second)
			if test.propagated {
				want.AvailableAt = time.Time{}
				want.State = controlstate.ServiceEndpointDNSPublished
				if test.removing {
					want.State = controlstate.ServiceEndpointDNSRemoved
				}
			}
			if !reflect.DeepEqual(store.serviceEndpointSaved, want) || store.serviceEndpointSaves != 1 || !store.serviceEndpointSavedAt.Equal(now) {
				t.Fatalf("saved = %#v at %s, want %#v at %s", store.serviceEndpointSaved, store.serviceEndpointSavedAt, want, now)
			}
		})
	}
}

func TestWorkerServiceEndpointAuthorityBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, domain string
		state        controlstate.DNSAuthorityState
		zone         string
		lookupErr    error
		wantState    controlstate.ServiceEndpointDNSState
		wantDelay    time.Duration
	}{
		{"pending authority", "claimed.example.test", controlstate.DNSAuthorityPending, "", nil, controlstate.ServiceEndpointDNSPending, time.Second},
		{"wrong domain", "other.example.test", controlstate.DNSAuthorityReady, "Z123", nil, controlstate.ServiceEndpointDNSFailed, 0},
		{"wrong authority reference", "claimed.example.test", controlstate.DNSAuthorityReady, "Z123", nil, controlstate.ServiceEndpointDNSFailed, 0},
		{"released authority", "claimed.example.test", controlstate.DNSAuthorityReleased, "Z123", nil, controlstate.ServiceEndpointDNSFailed, 0},
		{"missing zone", "claimed.example.test", controlstate.DNSAuthorityReady, "", nil, controlstate.ServiceEndpointDNSFailed, 0},
		{"lookup failure", "claimed.example.test", controlstate.DNSAuthorityReady, "Z123", errors.New("lookup unavailable"), controlstate.ServiceEndpointDNSPending, time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := testServiceDNSWork(now)
			work.Hostname, work.AuthorityReference = "api.claimed.example.test", testDNSWork(now).Reference
			authority := testDNSWork(now).DNSAuthority
			authority.CanonicalDomain, authority.State, authority.ProviderZoneID = test.domain, test.state, test.zone
			if test.name == "wrong authority reference" {
				authority.Reference = "dns_authority_wrong"
			}
			store := &dnsStoreStub{serviceEndpointWork: work, authority: authority, getErr: test.lookupErr}
			provider, verifier := &providerStub{}, &verifierStub{}
			worker := testDNSWorker(t, store, provider, verifier, now)
			worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			wantAvailable := time.Time{}
			if test.wantDelay != 0 {
				wantAvailable = now.Add(test.wantDelay)
			}
			if store.serviceEndpointSaved.State != test.wantState || !store.serviceEndpointSaved.AvailableAt.Equal(wantAvailable) ||
				provider.publishCalls != 0 || provider.removeCalls != 0 || verifier.addressCalls != 0 {
				t.Fatalf("authority boundary: saved %#v, provider %#v, verifier %#v", store.serviceEndpointSaved, provider, verifier)
			}
			if (store.serviceEndpointSaved.LastError != "") != (test.state != controlstate.DNSAuthorityPending) {
				t.Fatalf("last error = %q", store.serviceEndpointSaved.LastError)
			}
		})
	}
}

func TestWorkerServiceEndpointAuthorityLookupRetryBackoff(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		streak int64
		delay  time.Duration
	}{
		{"first error", 0, time.Second},
		{"third consecutive error", 2, 4 * time.Second},
		{"capped retry", 19, time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := testServiceDNSWork(now)
			work.Hostname, work.AuthorityReference = "api.claimed.example.test", testDNSWork(now).Reference
			work.Attempts, work.ConsecutiveErrors = 100, test.streak
			authority := testDNSWork(now).DNSAuthority
			authority.State, authority.ProviderZoneID = controlstate.DNSAuthorityReady, "ZCLAIMED"
			store := &dnsStoreStub{
				serviceEndpointWork: work, authority: authority,
				getErr: errors.New("lookup unavailable"),
			}
			provider, verifier := &providerStub{}, &verifierStub{}
			worker := testDNSWorker(t, store, provider, verifier, now)
			worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
			if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
				t.Fatalf("process = %v, %v", found, err)
			}
			want := work
			want.LastError, want.AvailableAt = "server.dns_failed", now.Add(test.delay)
			if !reflect.DeepEqual(store.serviceEndpointSaved, want) || store.serviceEndpointSaves != 1 ||
				!store.serviceEndpointSavedAt.Equal(now) {
				t.Fatalf("lookup retry = %#v at %s, want %#v at %s", store.serviceEndpointSaved, store.serviceEndpointSavedAt, want, now)
			}
			if !reflect.DeepEqual(store.authorityReferences, []string{work.AuthorityReference}) ||
				provider.publishCalls != 0 || provider.removeCalls != 0 || verifier.addressCalls != 0 {
				t.Fatalf("lookup failure reached DNS: references %v, provider %#v, verifier %#v", store.authorityReferences, provider, verifier)
			}
		})
	}
}

func TestWorkerPersistenceFailureAfterExternalSuccess(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	failure := errors.New("database connection lost")
	for _, kind := range []string{"authority", "service"} {
		t.Run(kind, func(t *testing.T) {
			store := &dnsStoreStub{saveErr: failure}
			provider := &providerStub{zone: Zone{ID: "Z123", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
			verifier := &verifierStub{addressVerified: true}
			worker := testDNSWorker(t, store, provider, verifier, now)
			if kind == "authority" {
				store.work = testDNSWork(now)
			} else {
				store.serviceEndpointWork = testServiceDNSWork(now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "Z123"
				worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
			}
			if found, err := worker.processOne(t.Context()); !found || !errors.Is(err, failure) {
				t.Fatalf("process = %v, %v", found, err)
			}
			if kind == "authority" {
				if provider.ensureCalls != 1 || store.saves != 1 || store.saved.ProviderZoneID != "Z123" || store.saved.LastError != "" {
					t.Fatalf("authority save = %#v", store)
				}
			} else if provider.publishCalls != 1 || verifier.addressCalls != 1 || store.serviceEndpointSaves != 1 || store.serviceEndpointSaved.State != controlstate.ServiceEndpointDNSPublished || store.serviceEndpointSaved.LastError != "" {
				t.Fatalf("service save = %#v", store)
			}
			// a failed save leaves the original durable work available for a later claim.
			store.saveErr = nil
			if kind == "authority" {
				store.work = testDNSWork(now)
			} else {
				store.serviceEndpointWork = testServiceDNSWork(now)
			}
			if found, err := worker.processOne(t.Context()); !found || err != nil {
				t.Fatalf("retry = %v, %v", found, err)
			}
			if kind == "authority" {
				if provider.ensureCalls != 2 || !reflect.DeepEqual(provider.ensureWork, testDNSWork(now)) || store.saves != 2 {
					t.Fatalf("authority retry = %#v, %#v", provider, store)
				}
			} else if provider.publishCalls != 2 || provider.record.Owner != ServiceOwner("dpl_1") || store.serviceEndpointSaves != 2 {
				t.Fatalf("service retry = %#v, %#v", provider, store)
			}
		})
	}
}

func TestWorkerServiceFailuresPreserveLifecycleOrFailTerminally(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, state := range []controlstate.ServiceEndpointDNSState{controlstate.ServiceEndpointDNSPending, controlstate.ServiceEndpointDNSRemoving} {
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
				work := testServiceDNSWork(now)
				work.State, work.Attempts, work.ConsecutiveErrors = state, 100, 19
				store := &dnsStoreStub{serviceEndpointWork: work}
				provider, verifier := &providerStub{err: test.providerErr}, &verifierStub{err: test.verifierErr}
				worker := testDNSWorker(t, store, provider, verifier, now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "Z123"
				worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
				if found, err := worker.processOne(t.Context()); !found || err != nil {
					t.Fatalf("process = %v, %v", found, err)
				}
				wantState, wantAt := state, now.Add(time.Minute)
				if test.terminal {
					wantState, wantAt = controlstate.ServiceEndpointDNSFailed, time.Time{}
				}
				wantReason := "server.dns_failed"
				if test.terminal {
					wantReason = "server.dns_conflict"
				}
				if store.serviceEndpointSaved.State != wantState || !store.serviceEndpointSaved.AvailableAt.Equal(wantAt) || store.serviceEndpointSaved.LastError != wantReason ||
					store.serviceEndpointSaved.Revision != 7 || store.serviceEndpointSaved.Epoch != 9 || store.serviceEndpointSaves != 1 {
					t.Fatalf("saved failure = %#v", store.serviceEndpointSaved)
				}
				wantVerifications := 0
				if test.providerErr == nil {
					wantVerifications = 1
				}
				if verifier.addressCalls+verifier.removalCalls != wantVerifications {
					t.Fatalf("verification calls = %d address, %d removal", verifier.addressCalls, verifier.removalCalls)
				}
			})
		}
	}
}

func TestWorkerCancellationDoesNotPersistRetry(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"authority", "service"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &dnsStoreStub{}
			provider := &providerStub{err: context.Canceled, beforeCall: cancel}
			worker := testDNSWorker(t, store, provider, &verifierStub{}, now)
			if kind == "authority" {
				store.work = testDNSWork(now)
			} else {
				store.serviceEndpointWork = testServiceDNSWork(now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "Z123"
				worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
			}
			if found, err := worker.processOne(ctx); !found || !errors.Is(err, context.Canceled) {
				t.Fatalf("process = %v, %v", found, err)
			}
			if store.saves != 0 || store.serviceEndpointSaves != 0 {
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
