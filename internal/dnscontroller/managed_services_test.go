package dnscontroller

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

type managedDNSStoreStub struct {
	dnsStoreStub
	work, saved controlstate.ManagedEndpointDNSWork
	stale       bool
	locked      bool
	saves       int
}

func (s *managedDNSStoreStub) ClaimManagedEndpointDNSWork(context.Context, string, time.Time, time.Duration) (controlstate.ManagedEndpointDNSWork, bool, error) {
	return s.work, true, nil
}

func (s *managedDNSStoreStub) WithDNSRecordLock(_ context.Context, _ string, run func() error) error {
	s.locked = true
	defer func() { s.locked = false }()
	return run()
}

func (s *managedDNSStoreStub) ValidateManagedEndpointDNSWork(context.Context, controlstate.ManagedEndpointDNSWork, time.Time) error {
	if !s.locked || s.stale {
		return controlstate.ErrDNSPublicURLWorkStale
	}
	return nil
}

func (s *managedDNSStoreStub) SaveManagedEndpointDNSWork(_ context.Context, work controlstate.ManagedEndpointDNSWork, _ time.Time) (controlstate.ManagedEndpointDNSWork, error) {
	s.saves++
	s.saved = work
	return work, nil
}

func TestManagedEndpointDNSUsesOwnedExactRecords(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name       string
		public     bool
		state      controlstate.PublicURLDNSState
		propagated bool
	}{
		{"loopback", false, controlstate.PublicURLDNSPending, true},
		{"public", true, controlstate.PublicURLDNSPending, true},
		{"waiting", true, controlstate.PublicURLDNSPending, false},
		{"remove-private", false, controlstate.PublicURLDNSRemoving, true},
		{"remove-public", true, controlstate.PublicURLDNSRemoving, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &managedDNSStoreStub{work: controlstate.ManagedEndpointDNSWork{Hostname: "api.production.storefront.tunnels.example.test", ServiceID: "psvc_0123456789ABCDEFGHIJKL", OwnerID: "pgrp_0123456789ABCDEFGHIJKL", DomainID: "domain", PoolID: controlstate.PrimaryIngressPoolID, Public: test.public, State: test.state, Revision: 1, Epoch: 1, Attempts: 1, Worker: "dns-worker", ExpiresAt: now.Add(time.Minute), AvailableAt: now}}
			provider := &providerStub{}
			verifier := &verifierStub{publicURLVerified: test.propagated}
			worker, err := New(store, provider, verifier, Config{WorkerID: "dns-worker", ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123", IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"}})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			metrics := observability.New("control")
			worker.config.Observer = metrics
			if found, err := worker.processManagedEndpoint(t.Context(), now); !found || err != nil {
				t.Fatal(found, err)
			}
			if provider.record.Owner != ManagedServiceOwner(store.work.OwnerID) || provider.record.WildcardHostname != "" || provider.record.CanonicalHostname != store.work.Hostname || store.saves != 1 {
				t.Fatal("managed endpoint used another DNS owner or a broad wildcard", provider.record, store.saved)
			}
			removing := test.state == controlstate.PublicURLDNSRemoving
			response := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			for _, phase := range []string{"claim", "provider", "verify", "advance", "save"} {
				reason := ""
				if !test.propagated && (phase == "verify" || phase == "advance") {
					reason = `,tnl_reason="pending"`
				}
				want := fmt.Sprintf(`tnl_control_dns_work_duration_seconds_count{tnl_dns_kind="managed_service",tnl_operation=%q,tnl_outcome="success"%s} 1`, phase, reason)
				if !strings.Contains(response.Body.String(), want) {
					t.Errorf("missing managed DNS stage %s", want)
				}
			}
			if removing {
				if provider.removeCalls != 1 || provider.publishCalls != 0 || store.saved.State != controlstate.PublicURLDNSRemoved {
					t.Fatal("removal did not reconcile", provider, store.saved)
				}
			} else {
				want4, want6 := []string{"127.0.0.1"}, []string(nil)
				if test.public {
					want4, want6 = []string{"192.0.2.10"}, []string{"2001:db8::10"}
				}
				if !reflect.DeepEqual(provider.record.IngressIPv4Addresses, want4) || !reflect.DeepEqual(provider.record.IngressIPv6Addresses, want6) {
					t.Fatal("incorrect DNS-selected access path", provider.record)
				}
				if (store.saved.State == controlstate.PublicURLDNSPublished) != test.propagated {
					t.Fatal("DNS readiness did not wait for authoritative propagation", store.saved)
				}
			}
		})
	}
}

func TestManagedEndpointDNSFencesStaleWork(t *testing.T) {
	now := time.Now().UTC()
	store := &managedDNSStoreStub{stale: true, work: controlstate.ManagedEndpointDNSWork{Hostname: "api.example.test"}}
	provider := &providerStub{}
	worker, err := New(store, provider, &verifierStub{}, Config{WorkerID: "dns-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if found, err := worker.processManagedEndpoint(t.Context(), now); !found || err != nil || provider.publishCalls != 0 || provider.removeCalls != 0 || store.saves != 0 {
		t.Fatal("stale DNS work reached the provider", found, err, provider, store.saves)
	}
	if err = store.ValidateManagedEndpointDNSWork(t.Context(), store.work, now); !errors.Is(err, controlstate.ErrDNSPublicURLWorkStale) {
		t.Fatal(err)
	}
}
