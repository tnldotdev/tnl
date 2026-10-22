package dnscontroller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/testutil/workerobservation"
)

type blockingDNSProvider struct {
	providerStub
	calls   int
	started func()
	retry   bool
}

func (p *blockingDNSProvider) EnsureCustomZone(ctx context.Context, _ controlstate.DNSAuthorityWork) (Zone, error) {
	p.calls++
	if p.retry && p.calls > 1 {
		return Zone{ID: "zone", Nameservers: []string{"ns1.example.test", "ns2.example.test"}}, nil
	}
	if p.started != nil {
		p.started()
	}
	<-ctx.Done()
	return Zone{}, ctx.Err()
}

type retryDNSStore struct {
	dnsStoreStub
	claims int
	stop   context.CancelFunc
}

func (s *retryDNSStore) ClaimDNSAuthorityWork(context.Context, string, time.Time, time.Duration) (controlstate.DNSAuthorityWork, bool, error) {
	s.claims++
	if s.claims > 2 {
		s.stop()
		return controlstate.DNSAuthorityWork{}, false, nil
	}
	return s.work, true, nil
}

func (s *retryDNSStore) SaveDNSAuthorityWork(ctx context.Context, work controlstate.DNSAuthorityWork, now time.Time) (controlstate.DNSAuthorityWork, error) {
	saved, err := s.dnsStoreStub.SaveDNSAuthorityWork(ctx, work, now)
	s.stop()
	return saved, err
}

func TestDNSAttemptDeadlineReportsAndRetriesWithLiveParent(t *testing.T) {
	ctx, record := workerobservation.Start(t)
	ctx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	store := &retryDNSStore{dnsStoreStub: dnsStoreStub{work: testDNSWork(time.Now())}, stop: stop}
	provider := &blockingDNSProvider{retry: true}
	worker, err := New(store, provider, &verifierStub{}, Config{WorkerID: "review", OperationTimeout: 20 * time.Millisecond, PollInterval: time.Millisecond, Observer: record.Owner})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if store.claims != 2 || provider.calls != 2 || store.saves != 1 || store.saved.ProviderZoneID != "zone" {
		t.Fatal("deadline did not retry and advance recoverable work", store.claims, provider.calls, store.saves)
	}
	record.AssertFailure(t, "dns.authority.attempt", "timeout", string(failure.ServerDNSFailed))
	if !strings.Contains(record.Logs(), "timeout=true") {
		t.Fatal("timeout diagnostic lost classification")
	}
}

func TestDNSLifetimeShutdownDoesNotReportAttemptFailure(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, record := workerobservation.Start(t)
			var stop context.CancelFunc
			if mode == "deadline" {
				ctx, stop = context.WithTimeout(ctx, 20*time.Millisecond)
			} else {
				ctx, stop = context.WithCancel(ctx)
			}
			defer stop()
			provider := &blockingDNSProvider{}
			if mode == "cancel" {
				provider.started = stop
			}
			worker, err := New(&dnsStoreStub{work: testDNSWork(time.Now())}, provider, &verifierStub{}, Config{WorkerID: "review", OperationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if provider.calls != 1 || record.Logs() != "" {
				t.Fatal("shutdown reported operational failure", record.Logs())
			}
		})
	}
}

func TestManagedDNSOwnerAttemptPreservesPersistedProviderFailure(t *testing.T) {
	for _, saveFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "save-failed"}[saveFails], func(t *testing.T) {
			ctx, record := workerobservation.Start(t)
			now := time.Now().UTC()
			store := &managedDNSStoreStub{work: controlstate.ManagedEndpointDNSWork{Hostname: "api.example.test", OwnerID: "group", State: controlstate.PublicURLDNSPending, Attempts: 1, LastError: "old"}}
			if saveFails {
				store.saveErr = errors.New("private-provider-cause save")
			}
			provider := &providerStub{err: errors.New("private-provider-cause DNS")}
			worker, err := New(store, provider, &verifierStub{publicURLVerified: true}, Config{WorkerID: "review", ManagedDomain: "example.test", ManagedZoneID: "zone", Observer: record.Owner})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			found, err := worker.processManagedEndpoint(ctx, now)
			if !found || (err != nil) != saveFails || store.saves != 1 || store.saved.LastError != string(failure.ServerDNSFailed) || !store.saved.AvailableAt.After(now) || store.saved.State != controlstate.PublicURLDNSPending {
				t.Fatal("provider retry state lost", found, err, store.saved)
			}
			record.AssertFailure(t, "dns.managed_service.attempt", "error", string(failure.ServerDNSFailed))
			if !saveFails {
				store.work = store.saved
				provider.err = nil
				if _, err := worker.processManagedEndpoint(ctx, now); err != nil || store.saved.LastError != "" || store.saved.State != controlstate.PublicURLDNSPublished {
					t.Fatal("retry did not recover", err, store.saved)
				}
			}
		})
	}
}
