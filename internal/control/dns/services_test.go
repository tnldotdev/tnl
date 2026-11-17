package dns

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
)

type managedDNSStoreStub struct {
	dnsStoreStub
	work, saved controlstate.ServiceEndpointDNSWork
	stale       bool
	locked      bool
	saves       int
}

func (s *managedDNSStoreStub) ClaimServiceEndpointDNSWork(context.Context, string, time.Time, time.Duration) (controlstate.ServiceEndpointDNSWork, bool, error) {
	return s.work, true, nil
}

func (s *managedDNSStoreStub) WithDNSRecordLock(_ context.Context, _ string, run func() error) error {
	s.locked = true
	defer func() { s.locked = false }()
	return run()
}

func (s *managedDNSStoreStub) ValidateServiceEndpointDNSWork(context.Context, controlstate.ServiceEndpointDNSWork, time.Time) error {
	if !s.locked || s.stale {
		return controlstate.ErrServiceEndpointDNSWorkStale
	}
	return nil
}

func (s *managedDNSStoreStub) SaveServiceEndpointDNSWork(_ context.Context, work controlstate.ServiceEndpointDNSWork, _ time.Time) (controlstate.ServiceEndpointDNSWork, error) {
	s.saves++
	s.saved = work
	return work, s.saveErr
}

func TestServiceEndpointDNSUsesOwnedExactRecords(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name       string
		public     bool
		state      controlstate.ServiceEndpointDNSState
		propagated bool
	}{
		{"public", true, controlstate.ServiceEndpointDNSPending, true},
		{"waiting", true, controlstate.ServiceEndpointDNSPending, false},
		{"remove-private", false, controlstate.ServiceEndpointDNSRemoving, true},
		{"remove-public", true, controlstate.ServiceEndpointDNSRemoving, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &managedDNSStoreStub{work: controlstate.ServiceEndpointDNSWork{Hostname: "api.production.storefront.tunnels.example.test", ServiceID: "svc_0123456789ABCDEFGHIJKL", OwnerID: "dpl_0123456789ABCDEFGHIJKL", DomainID: "domain", PoolID: controlstate.PrimaryIngressPoolID, Public: test.public, State: test.state, Revision: 1, Epoch: 1, Attempts: 1, Worker: "dns-worker", ExpiresAt: now.Add(time.Minute), AvailableAt: now}}
			provider := &providerStub{}
			verifier := &verifierStub{addressVerified: test.propagated}
			worker, err := New(store, provider, verifier, Config{WorkerID: "dns-worker", ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123", IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"}})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			metrics := observability.New("control")
			worker.config.Observer = metrics
			if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
				t.Fatal(found, err)
			}
			if provider.record.Owner != ServiceOwner(store.work.OwnerID) || provider.record.CanonicalHostname != store.work.Hostname || store.saves != 1 {
				t.Fatal("managed endpoint used another DNS owner or a broad wildcard", provider.record, store.saved)
			}
			if provider.record.ZoneID != "Z123" || provider.record.ZoneDomain != "tunnels.example.test" || provider.record.CustomZone ||
				verifier.addressCalls != 1 || verifier.addressHostname != store.work.Hostname {
				t.Fatal("managed endpoint changed its zone or verification count", provider.record, verifier)
			}
			removing := test.state == controlstate.ServiceEndpointDNSRemoving
			response := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			for _, phase := range []string{"claim", "provider", "verify", "advance", "save"} {
				reason := ""
				if !test.propagated && (phase == "verify" || phase == "advance") {
					reason = `,tnl_reason="pending"`
				}
				want := fmt.Sprintf(`tnl_control_dns_work_duration_seconds_count{tnl_dns_kind="service",tnl_operation=%q,tnl_outcome="success"%s} 1`, phase, reason)
				if !strings.Contains(response.Body.String(), want) {
					t.Errorf("missing managed DNS stage %s", want)
				}
			}
			if removing {
				if provider.removeCalls != 1 || provider.publishCalls != 0 || store.saved.State != controlstate.ServiceEndpointDNSRemoved {
					t.Fatal("removal did not reconcile", provider, store.saved)
				}
			} else {
				if provider.publishCalls != 1 || provider.removeCalls != 0 {
					t.Fatal("managed endpoint publication was not exactly once", provider)
				}
				want4, want6 := []string{"192.0.2.10"}, []string{"2001:db8::10"}
				if !reflect.DeepEqual(provider.record.IngressIPv4Addresses, want4) || !reflect.DeepEqual(provider.record.IngressIPv6Addresses, want6) {
					t.Fatal("incorrect DNS-selected access path", provider.record)
				}
				if (store.saved.State == controlstate.ServiceEndpointDNSPublished) != test.propagated {
					t.Fatal("DNS readiness did not wait for authoritative propagation", store.saved)
				}
			}
		})
	}
}

func TestConnectorOnlyServiceCannotPublishDNS(t *testing.T) {
	now := time.Now().UTC()
	store := &managedDNSStoreStub{work: controlstate.ServiceEndpointDNSWork{
		Hostname:  "api.production.storefront.tunnels.example.test",
		ServiceID: "svc_0123456789ABCDEFGHIJKL", OwnerID: "dpl_0123456789ABCDEFGHIJKL",
		DomainID: "domain", PoolID: controlstate.PrimaryIngressPoolID,
		Public: false, State: controlstate.ServiceEndpointDNSPending,
		Revision: 1, Epoch: 1, Attempts: 1, Worker: "dns-worker",
		ExpiresAt: now.Add(time.Minute), AvailableAt: now,
	}}
	provider := &providerStub{}
	worker, err := New(store, provider, &verifierStub{}, Config{
		WorkerID: "dns-worker", ManagedDomain: "tunnels.example.test",
		ManagedZoneID: "Z123", IngressIPv4Addresses: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now }
	if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
		t.Fatal(found, err)
	}
	if provider.publishCalls != 0 || provider.removeCalls != 0 ||
		store.saved.State != controlstate.ServiceEndpointDNSFailed || store.saved.LastError == "" {
		t.Fatalf("connector-only DNS work reached provider: calls=%d, saved=%+v", provider.publishCalls, store.saved)
	}
}

func TestServiceEndpointDNSUsesPinnedIngressPool(t *testing.T) {
	now := time.Now().UTC()
	work := testServiceDNSWork(now)
	work.PoolID = "ingress-b"
	store := &dnsStoreStub{serviceEndpointWork: work, pool: controlstate.IngressPool{
		ID: "ingress-b", State: controlstate.IngressPoolEnabled,
		IPv4Address: netip.MustParseAddr("192.0.2.20"), IPv6Address: netip.MustParseAddr("2001:db8::20"),
	}}
	provider := &providerStub{}
	verifier := &verifierStub{addressVerified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
		t.Fatal(found, err)
	}
	if !reflect.DeepEqual(provider.record.IngressIPv4Addresses, []string{"192.0.2.20"}) ||
		!reflect.DeepEqual(provider.record.IngressIPv6Addresses, []string{"2001:db8::20"}) ||
		verifier.addressHostname != work.Hostname {
		t.Fatal("service endpoint used another pool or verified another hostname", provider.record, verifier)
	}
	store.pool.State = controlstate.IngressPoolDisabled
	store.serviceEndpointWork = work
	if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
		t.Fatal(found, err)
	}
	if provider.publishCalls != 1 || store.serviceEndpointSaved.State != controlstate.ServiceEndpointDNSPending {
		t.Fatal("disabled secondary pool issued service DNS", provider, store.serviceEndpointSaved)
	}
}

func TestServiceEndpointDNSUsesExactNestedHostname(t *testing.T) {
	now := time.Now().UTC()
	work := testServiceDNSWork(now)
	work.Hostname = "api.preview.member.tunnels.example.test"
	store := &dnsStoreStub{serviceEndpointWork: work}
	provider, verifier := &providerStub{}, &verifierStub{addressVerified: true}
	worker := testDNSWorker(t, store, provider, verifier, now)
	worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
	worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
	if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
		t.Fatal(found, err)
	}
	if provider.record.CanonicalHostname != work.Hostname || verifier.addressHostname != work.Hostname ||
		provider.record.ZoneID != "ZMANAGED" || provider.record.CustomZone ||
		provider.publishCalls != 1 || provider.removeCalls != 0 || verifier.addressCalls != 1 {
		t.Fatal("nested service endpoint did not use its exact hostname", provider.record, verifier)
	}
}

func TestServiceEndpointDNSExactHostnameAuthority(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, hostname string
		custom         bool
	}{
		{"managed root", "app.routes.example.test", false},
		{"managed member", "api.member.routes.example.test", false},
		{"managed organization", "app.chase.studio.routes.example.test", false},
		{"managed nested organization", "api.preview.chase.studio.routes.example.test", false},
		{"custom root", "api.claimed.example.test", true},
		{"custom member", "api.member.claimed.example.test", true},
		{"custom organization", "app.chase.studio.claimed.example.test", true},
		{"custom nested organization", "api.preview.chase.studio.claimed.example.test", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := testServiceDNSWork(now)
			work.Hostname = test.hostname
			authority := testDNSWork(now).DNSAuthority
			authority.State, authority.ProviderZoneID = controlstate.DNSAuthorityReady, "ZCLAIMED"
			authority.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
			if test.custom {
				work.AuthorityReference = authority.Reference
			}
			store := &dnsStoreStub{serviceEndpointWork: work, authority: authority}
			provider, verifier := &providerStub{}, &verifierStub{addressVerified: true}
			worker := testDNSWorker(t, store, provider, verifier, now)
			worker.config.ManagedDomain, worker.config.ManagedZoneID = "routes.example.test", "ZMANAGED"
			worker.config.IngressIPv4Addresses, worker.config.IngressIPv6Addresses = []string{"192.0.2.10"}, []string{"2001:db8::10"}
			wantRecord := AddressRecord{
				ZoneID: "ZMANAGED", ZoneDomain: "routes.example.test",
				Owner: ServiceOwner(work.OwnerID), DomainID: work.DomainID, CanonicalHostname: work.Hostname,
				IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"},
			}
			var wantReferences []string
			var wantNameservers []string
			if test.custom {
				wantRecord.ZoneID, wantRecord.ZoneDomain, wantRecord.CustomZone = "ZCLAIMED", authority.CanonicalDomain, true
				wantRecord.AuthorityReference, wantRecord.TeamID = authority.Reference, authority.TeamID
				wantNameservers = authority.Nameservers
			}
			for _, removing := range []bool{false, true} {
				if removing {
					work.State = controlstate.ServiceEndpointDNSRemoving
					store.serviceEndpointWork = work
					store.authority.State = controlstate.DNSAuthorityReleasing
					wantRecord.IngressIPv4Addresses, wantRecord.IngressIPv6Addresses = nil, nil
				}
				if test.custom {
					wantReferences = append(wantReferences, authority.Reference)
				}
				if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
					t.Fatalf("removing=%t: process = %v, %v", removing, found, err)
				}
				calls, removes, state := 1, 0, controlstate.ServiceEndpointDNSPublished
				if removing {
					calls, removes, state = 2, 1, controlstate.ServiceEndpointDNSRemoved
				}
				wantSaved := work
				wantSaved.State = state
				if !reflect.DeepEqual(provider.record, wantRecord) || !reflect.DeepEqual(store.authorityReferences, wantReferences) ||
					provider.publishCalls != 1 || provider.removeCalls != removes || verifier.addressCalls != calls ||
					verifier.addressHostname != work.Hostname || !reflect.DeepEqual(verifier.addressNameservers, wantNameservers) ||
					!reflect.DeepEqual(verifier.routeIPv4, wantRecord.IngressIPv4Addresses) ||
					!reflect.DeepEqual(verifier.routeIPv6, wantRecord.IngressIPv6Addresses) ||
					!reflect.DeepEqual(store.serviceEndpointSaved, wantSaved) || store.serviceEndpointSaves != calls ||
					!store.serviceEndpointSavedAt.Equal(now) {
					t.Fatalf("removing=%t: exact hostname/authority changed: record %#v, store %#v, verifier %#v", removing, provider.record, store, verifier)
				}
			}
		})
	}
}

func TestServiceEndpointDNSRejectsHostnameAuthorityMismatch(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, hostname, reference, domainID string
		authorityReference                  string
	}{
		{"missing authority", "app.chase.studio.claimed.example.test", "", "domain_1", ""},
		{"wrong authority reference", "app.chase.studio.claimed.example.test", "dns_other", "domain_1", "dns_wrong"},
		{"wrong domain ID", "app.chase.studio.claimed.example.test", "dns_other", "domain_other", "dns_other"},
		{"outside authority domain", "api.preview.chase.studio.other.example.test", "dns_other", "domain_1", "dns_other"},
		{"authority suffix lookalike", "api.preview.chase.studio.notclaimed.example.test", "dns_other", "domain_1", "dns_other"},
		{"managed suffix lookalike", "api.preview.chase.studio.notroutes.example.test", "", "domain_1", ""},
	} {
		for _, state := range []controlstate.ServiceEndpointDNSState{controlstate.ServiceEndpointDNSPending, controlstate.ServiceEndpointDNSRemoving} {
			t.Run(test.name+"/"+string(state), func(t *testing.T) {
				work := testServiceDNSWork(now)
				work.Hostname, work.AuthorityReference, work.DomainID, work.State = test.hostname, test.reference, test.domainID, state
				authority := testDNSWork(now).DNSAuthority
				authority.Reference, authority.State, authority.ProviderZoneID = test.authorityReference, controlstate.DNSAuthorityReady, "ZCLAIMED"
				store := &dnsStoreStub{serviceEndpointWork: work, authority: authority}
				provider, verifier := &providerStub{}, &verifierStub{addressVerified: true}
				worker := testDNSWorker(t, store, provider, verifier, now)
				worker.config.ManagedDomain, worker.config.ManagedZoneID = "routes.example.test", "ZMANAGED"
				worker.config.IngressIPv4Addresses = []string{"192.0.2.10"}
				if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil {
					t.Fatalf("process = %v, %v", found, err)
				}
				var wantReferences []string
				if work.AuthorityReference != "" {
					wantReferences = []string{work.AuthorityReference}
				}
				want := work
				want.State, want.LastError, want.AvailableAt = controlstate.ServiceEndpointDNSFailed, "server.dns_conflict", time.Time{}
				if provider.publishCalls != 0 || provider.removeCalls != 0 || verifier.addressCalls != 0 ||
					!reflect.DeepEqual(store.authorityReferences, wantReferences) ||
					!reflect.DeepEqual(store.serviceEndpointSaved, want) || store.serviceEndpointSaves != 1 ||
					!store.serviceEndpointSavedAt.Equal(now) {
					t.Fatalf("hostname crossed domain authority: provider %#v, verifier %#v, store %#v", provider, verifier, store)
				}
			})
		}
	}
}

func TestServiceEndpointDNSFencesStaleWork(t *testing.T) {
	now := time.Now().UTC()
	store := &managedDNSStoreStub{stale: true, work: controlstate.ServiceEndpointDNSWork{Hostname: "api.example.test"}}
	provider := &providerStub{}
	worker, err := New(store, provider, &verifierStub{}, Config{WorkerID: "dns-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if found, err := worker.processServiceEndpoint(t.Context(), now); !found || err != nil || provider.publishCalls != 0 || provider.removeCalls != 0 || store.saves != 0 {
		t.Fatal("stale DNS work reached the provider", found, err, provider, store.saves)
	}
	if err = store.ValidateServiceEndpointDNSWork(t.Context(), store.work, now); !errors.Is(err, controlstate.ErrServiceEndpointDNSWorkStale) {
		t.Fatal(err)
	}
}

func TestWorkerClaimsServiceEndpointWhenOtherQueuesAreEmpty(t *testing.T) {
	now := time.Now().UTC()
	store := &dnsStoreStub{}
	provider := &providerStub{}
	worker := testDNSWorker(t, store, provider, &verifierStub{}, now)
	if found, err := worker.processOne(t.Context()); found || err != nil || store.serviceEndpointClaims != 1 || provider.publishCalls != 0 {
		t.Fatalf("empty service queue = %t, %v; claims = %d, publishes = %d", found, err, store.serviceEndpointClaims, provider.publishCalls)
	}
}
