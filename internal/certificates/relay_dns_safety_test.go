package certificates

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRelayWorkerRejectsUnavailableDNSManager(t *testing.T) {
	worker, err := NewRelayWorker(&relayStoreStub{}, RelayConfig{
		WorkerID: "worker_test", AccountID: "account_1", Profile: "tlsserver", HTTPClient: &http.Client{},
	})
	if err == nil || worker != nil {
		t.Fatalf("unavailable DNS manager accepted: worker %v, error %v", worker != nil, err)
	}
}

func TestRelayWorkerDNSFailureDoesNotAdvance(t *testing.T) {
	for _, phase := range []string{"presenting", "presented"} {
		for _, unavailable := range []bool{false, true} {
			name := phase + "/not_propagated"
			if unavailable {
				name = phase + "/unavailable"
			}
			if phase == "presenting" && !unavailable {
				continue
			}
			t.Run(name, func(t *testing.T) {
				now := time.Now().UTC()
				dns := &relayDNSChallengesStub{}
				if unavailable {
					dns.err = errors.New("DNS unavailable")
				}
				worker := &RelayWorker{config: RelayConfig{DNSChallenges: dns, PollInterval: time.Second}}
				api := &acmeStub{}
				work := controlstate.RelayCertificateOrderWork{ID: "relay_order_1", State: phase, TLSServerName: "relay-a.example.test", ChallengeURL: "https://acme.example.test/challenge/1"}
				err := worker.advance(t.Context(), api, &work, now)
				if (err != nil) != unavailable || work.State != phase || api.acceptedChallenge != "" {
					t.Fatalf("DNS failure: error %v, state %q, accepted %q", err, work.State, api.acceptedChallenge)
				}
				if !unavailable && !work.AvailableAt.Equal(now.Add(time.Second)) {
					t.Fatalf("propagation retry = %v", work.AvailableAt)
				}
			})
		}
	}
}

func TestRelayWorkerCleanupFailurePreservesCertificateAndRetry(t *testing.T) {
	for _, phase := range []string{"cleaning", "failed_cleaning"} {
		for _, canceled := range []bool{false, true} {
			name := phase + "/provider_failure"
			if canceled {
				name = phase + "/context_canceled"
			}
			t.Run(name, func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				csr, certificate := testCertificate(t, "relay-a.example.test", now)
				renewAt := now.Add(30 * time.Minute)
				work := controlstate.RelayCertificateOrderWork{ID: "relay_order_1", State: phase, TLSServerName: "relay-a.example.test", CSRDER: csr, ChallengeURL: "https://acme.example.test/challenge/1", Account: controlstate.ACMEAccount{AccountURL: "https://acme.example.test/account/1"}}
				if phase == "cleaning" {
					notBefore, notAfter := now.Add(-time.Minute), now.Add(time.Hour)
					work.CertificatePEM, work.RenewAt = certificate, &renewAt
					work.NotBefore, work.NotAfter = &notBefore, &notAfter
				}
				store := &relayStoreStub{work: work}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				dns := &relayDNSChallengesStub{cleanup: func(ctx context.Context) error {
					if canceled {
						cancel()
						return ctx.Err()
					}
					return errors.New("DNS cleanup unavailable")
				}}
				worker := &RelayWorker{store: store, config: RelayConfig{DNSChallenges: dns, FailedRetryInterval: time.Hour}, now: func() time.Time { return now }, client: func(controlstate.ACMEAccount) (acmeAPI, error) { return &acmeStub{}, nil }}
				found, err := worker.processOne(ctx)
				if !found {
					t.Fatal("cleanup was not claimed")
				}
				if canceled {
					if !errors.Is(err, context.Canceled) || store.saves != 0 {
						t.Fatalf("canceled cleanup: error %v, saves %d", err, store.saves)
					}
					return
				}
				if err != nil || store.saves != 1 || store.saved.State != phase || store.saved.LastError == "" || !store.saved.AvailableAt.After(now) || !bytes.Equal(store.saved.CertificatePEM, work.CertificatePEM) {
					t.Fatalf("cleanup failure: error %v, work %#v", err, store.saved)
				}
				if phase == "cleaning" && (store.saved.RenewAt == nil || !store.saved.RenewAt.Equal(renewAt)) {
					t.Fatal("cleanup failure discarded renewal schedule")
				}
				store.work, dns.cleanup = store.saved, nil
				if _, err := worker.processOne(t.Context()); err != nil {
					t.Fatal(err)
				}
				wantState, wantAvailable := "failed", now.Add(time.Hour)
				if phase == "cleaning" {
					wantState, wantAvailable = "complete", renewAt
				}
				if store.saved.State != wantState || !store.saved.AvailableAt.Equal(wantAvailable) {
					t.Fatalf("cleanup retry %#v", store.saved)
				}
			})
		}
	}
}

func TestRelayWorkerIssuanceRejectsInvalidRenewalCertificate(t *testing.T) {
	for _, failure := range []string{"wrong_key", "wrong_hostname", "expired", "future"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			const hostname = "relay-a.example.test"
			csr, certificate := testCertificate(t, hostname, now)
			switch failure {
			case "wrong_key":
				_, certificate = testCertificate(t, hostname, now)
			case "wrong_hostname":
				csr, certificate = testCertificate(t, "relay-b.example.test", now)
			case "expired":
				csr, certificate = testCertificate(t, hostname, now.Add(-2*time.Hour))
			case "future":
				csr, certificate = testCertificate(t, hostname, now.Add(2*time.Hour))
			}
			api := &acmeStub{order: acmeclient.Order{URL: "https://acme.example.test/order/1", Finalize: "https://acme.example.test/finalize/1", Certificate: "https://acme.example.test/certificate/1", Status: "valid", Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}}}, certificatePEM: certificate}
			dns := &relayDNSChallengesStub{}
			worker := &RelayWorker{config: RelayConfig{DNSChallenges: dns}}
			work := controlstate.RelayCertificateOrderWork{ID: "relay_order_1", State: "finalizing", TLSServerName: hostname, CSRDER: csr, OrderURL: api.order.URL, ChallengeURL: "https://acme.example.test/challenge/1"}
			var terminal *terminalError
			if err := worker.advance(t.Context(), api, &work, now); !errors.As(err, &terminal) {
				t.Fatalf("invalid issued certificate accepted: %v", err)
			}
			if work.State != "finalizing" || len(work.CertificatePEM) != 0 || work.RenewAt != nil || dns.cleaned != "" {
				t.Fatalf("invalid certificate advanced issuance: %#v, DNS %#v", work, dns)
			}
		})
	}
}

type relayStoreStub struct {
	work  controlstate.RelayCertificateOrderWork
	saved controlstate.RelayCertificateOrderWork
	saves int
}

func (*relayStoreStub) PrepareRelayCertificateOrder(context.Context, string, time.Time, time.Duration) (bool, error) {
	return false, nil
}
func (s *relayStoreStub) ClaimRelayCertificateOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.RelayCertificateOrderWork, bool, error) {
	return s.work, true, nil
}
func (s *relayStoreStub) SaveRelayCertificateOrderWork(_ context.Context, work controlstate.RelayCertificateOrderWork, _ time.Time) (controlstate.RelayCertificateOrderWork, error) {
	s.saves++
	s.saved = work
	return work, nil
}
