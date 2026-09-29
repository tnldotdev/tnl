package certificates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/dnscontroller"
)

func TestPublicURLWorkerDNSUnavailableFailsSafely(t *testing.T) {
	for _, phase := range []string{"pending", "presenting", "presented", "finalizing", "failed", "canceled"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			api, work := dnsSafetyOrder(t, phase, now)
			worker, err := NewPublicURLWorker(&certificateStoreStub{}, PublicURLConfig{WorkerID: "worker_test", Profile: "tlsserver", HTTPClient: &http.Client{}})
			if err != nil {
				t.Fatal(err)
			}
			state := work.State
			authorizationState := ""
			if len(work.Authorizations) != 0 {
				authorizationState = work.Authorizations[0].State
			}
			if err := worker.advance(t.Context(), api, &work, now); !errors.Is(err, dnscontroller.ErrChallengesNotConfigured) {
				t.Fatalf("DNS-unavailable work error = %v", err)
			}
			if api.newOrderCalls != 0 || api.acceptedChallenge != "" || work.State != state {
				t.Fatalf("unsafe progress: order calls %d, accepted %q, state %q", api.newOrderCalls, api.acceptedChallenge, work.State)
			}
			if len(work.Authorizations) != 0 && (work.Authorizations[0].State != authorizationState || work.Authorizations[0].CleanupCompletedAt != nil) {
				t.Fatalf("unsafe authorization progress: %#v", work.Authorizations[0])
			}
		})
	}
}

func TestPublicURLWorkerUnconfiguredDNSDefersDurableCleanupIntent(t *testing.T) {
	for _, phase := range []string{"pending", "presenting", "presented", "finalizing", "failed", "canceled"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			api, work := dnsSafetyOrder(t, phase, now)
			store := &certificateStoreStub{work: work}
			worker, err := NewPublicURLWorker(store, PublicURLConfig{WorkerID: "worker_test", Profile: "tlsserver", HTTPClient: &http.Client{}})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }
			if found, err := worker.processOne(t.Context()); !found || !errors.Is(err, dnscontroller.ErrChallengesNotConfigured) {
				t.Fatalf("missing DNS configuration: found %v, error %v", found, err)
			}
			wantState := "failed"
			if phase == "canceled" {
				wantState = "canceled"
			}
			if store.saves != 1 || store.saved.State != wantState || store.saved.LastError == "" || api.newOrderCalls != 0 {
				t.Fatalf("configuration failure: saves %d, work %#v, order calls %d", store.saves, store.saved, api.newOrderCalls)
			}
			if !store.saved.AvailableAt.Equal(now.Add(time.Minute)) {
				t.Fatalf("unconfigured order retry = %v, want %v", store.saved.AvailableAt, now.Add(time.Minute))
			}
			if phase == "pending" {
				return
			}
			if store.saved.Authorizations[0].State != "cleaning" || store.saved.Authorizations[0].CleanupCompletedAt != nil || !store.saved.Authorizations[0].AvailableAt.Equal(store.saved.AvailableAt) {
				t.Fatalf("cleanup intent lost: %#v", store.saved.Authorizations[0])
			}
			if !bytes.Equal(store.saved.CertificatePEM, work.CertificatePEM) {
				t.Fatal("issued certificate was discarded")
			}
			store.work = store.saved
			worker.now = func() time.Time { return now.Add(time.Minute) }
			if _, err := worker.processOne(t.Context()); !errors.Is(err, dnscontroller.ErrChallengesNotConfigured) {
				t.Fatal(err)
			}
			if store.saved.Authorizations[0].State != "cleaning" || store.saved.Authorizations[0].CleanupCompletedAt != nil || !store.saved.AvailableAt.Equal(now.Add(2*time.Minute)) {
				t.Fatalf("unconfigured cleanup retry lost intent or delay: %#v", store.saved)
			}
			store.work = store.saved
			worker.config.DNSChallenges = &dnsChallengesStub{}
			if _, err := worker.processOne(t.Context()); err != nil {
				t.Fatal(err)
			}
			if store.saved.Authorizations[0].State != "complete" {
				t.Fatalf("restart did not finish cleanup: %#v", store.saved.Authorizations[0])
			}
		})
	}
}

func TestPublicURLWorkerUnconfiguredDNSContinuesWithTLSALPNOrder(t *testing.T) {
	for _, phase := range []string{"pending", "canceled"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			_, dnsWork := dnsSafetyOrder(t, phase, now)
			api, tlsWork := dnsSafetyOrder(t, "pending", now)
			dnsWork.ID, tlsWork.ID = "order_dns", "order_tls"
			tlsWork.ChallengeMethod = "tls-alpn-01"
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			claims := 0
			store := &certificateStoreStub{}
			store.claim = func(context.Context) (controlstate.ACMEOrderWork, bool, error) {
				claims++
				switch claims {
				case 1:
					return dnsWork, true, nil
				case 2:
					if store.saved.ID != dnsWork.ID || !store.saved.AvailableAt.After(now) {
						t.Errorf("DNS order was not deferred: %#v", store.saved)
					}
					return tlsWork, true, nil
				default:
					return controlstate.ACMEOrderWork{}, false, nil
				}
			}
			store.save = func(work controlstate.ACMEOrderWork) {
				if work.ID == tlsWork.ID {
					cancel()
				}
			}
			var logs bytes.Buffer
			worker, err := NewPublicURLWorker(store, PublicURLConfig{WorkerID: "worker_test", Profile: "tlsserver", HTTPClient: &http.Client{}, IdleInterval: time.Millisecond, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }
			if err := worker.Run(ctx); err != nil {
				t.Fatalf("DNS failure stopped the worker: %v", err)
			}
			if ctx.Err() != context.Canceled || store.saves != 2 || store.saved.ID != tlsWork.ID || store.saved.State != "authorizing" || api.newOrderCalls != 1 {
				t.Fatalf("TLS-ALPN work did not advance before cancellation: context %v, saves %d, work %#v, ACME calls %d", ctx.Err(), store.saves, store.saved, api.newOrderCalls)
			}
			if count := strings.Count(logs.String(), dnscontroller.ErrChallengesNotConfigured.Error()); count != 1 {
				t.Fatalf("configuration error logged %d times: %s", count, &logs)
			}
		})
	}
}

func TestPublicURLWorkerDNSFailureDoesNotPresentOrAcceptChallenge(t *testing.T) {
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
				api, work := dnsSafetyOrder(t, phase, now)
				dns := &dnsChallengesStub{}
				if unavailable {
					dns.err = errors.New("DNS unavailable")
				}
				worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: dns, PollInterval: time.Second}}
				err := worker.advance(t.Context(), api, &work, now)
				if (err != nil) != unavailable || api.acceptedChallenge != "" || work.Authorizations[0].State != phase || work.Authorizations[0].Attempts != 0 {
					t.Fatalf("DNS failure: error %v, accepted %q, authorization %#v", err, api.acceptedChallenge, work.Authorizations[0])
				}
				if !unavailable && !work.AvailableAt.Equal(now.Add(time.Second)) {
					t.Fatalf("propagation retry = %v", work.AvailableAt)
				}
			})
		}
	}
}

func TestPublicURLWorkerDNSCleanupFailurePreservesRetryAndRenewal(t *testing.T) {
	for _, phase := range []string{"failed", "canceled", "finalizing", "waiting_for_install", "installed"} {
		for _, canceled := range []bool{false, true} {
			name := phase + "/provider_failure"
			if canceled {
				name = phase + "/context_canceled"
			}
			t.Run(name, func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				api, work := dnsSafetyOrder(t, phase, now)
				store := &certificateStoreStub{work: work}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				failure := errors.New("DNS cleanup response lost")
				dns := &dnsChallengesStub{cleanup: func(ctx context.Context) error {
					if canceled {
						cancel()
						return ctx.Err()
					}
					return failure
				}}
				worker := &PublicURLWorker{store: store, config: PublicURLConfig{DNSChallenges: dns, PollInterval: time.Second}, now: func() time.Time { return now }, client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }}
				wantState, initialSaves := phase, 0
				if phase == "finalizing" {
					if found, err := worker.processOne(ctx); err != nil || !found || store.saves != 1 || store.saved.State != "waiting_for_install" ||
						!bytes.Equal(store.saved.CertificatePEM, work.CertificatePEM) || len(dns.cleanupCalls) != 0 {
						t.Fatalf("issued certificate blocked on cleanup: found=%t error=%v state=%q saves=%d cleanups=%d", found, err, store.saved.State, store.saves, len(dns.cleanupCalls))
					}
					store.work = store.saved
					wantState, initialSaves = "waiting_for_install", 1
				}
				found, err := worker.processOne(ctx)
				if !found {
					t.Fatal("cleanup work was not claimed")
				}
				if canceled {
					if !errors.Is(err, context.Canceled) || store.saves != initialSaves {
						t.Fatalf("canceled cleanup: error %v, saves %d", err, store.saves)
					}
					return
				}
				if err != nil || store.saves != initialSaves+1 || store.saved.State != wantState || store.saved.Authorizations[0].State != "cleaning" || store.saved.Authorizations[0].CleanupCompletedAt != nil || store.saved.LastError == "" || !store.saved.AvailableAt.After(now) {
					t.Fatalf("failed cleanup: error=%v saves=%d state=%q authorization=%q retry=%v", err, store.saves, store.saved.State, store.saved.Authorizations[0].State, store.saved.AvailableAt)
				}
				if !bytes.Equal(store.saved.CertificatePEM, work.CertificatePEM) ||
					(phase == "finalizing" || phase == "waiting_for_install" || phase == "installed") &&
						(store.saved.RenewAt == nil || !store.saved.RenewAt.Equal(*work.RenewAt)) {
					t.Fatal("DNS cleanup failure discarded the issued certificate or renewal schedule")
				}
				store.work = store.saved
				dns.cleanup = nil
				if _, err := worker.processOne(t.Context()); err != nil {
					t.Fatal(err)
				}
				if store.saved.Authorizations[0].State != "complete" || store.saved.Authorizations[0].CleanupCompletedAt == nil {
					t.Fatalf("cleanup retry %#v", store.saved.Authorizations[0])
				}
			})
		}
	}
}

func TestPublicURLWorkerTerminalDNSCleanupErrorDoesNotRevokeIssuedCertificate(t *testing.T) {
	for _, phase := range []string{"waiting_for_install", "installed"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			api, work := dnsSafetyOrder(t, phase, now)
			store := &certificateStoreStub{work: work}
			worker := &PublicURLWorker{
				store:  store,
				config: PublicURLConfig{DNSChallenges: &dnsChallengesStub{err: terminalf("conflicting DNS record")}},
				now:    func() time.Time { return now },
				client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil },
			}
			if found, err := worker.processOne(t.Context()); err != nil || !found || store.saves != 1 ||
				store.saved.State != phase || store.saved.Authorizations[0].State != "cleaning" ||
				!bytes.Equal(store.saved.CertificatePEM, work.CertificatePEM) ||
				store.saved.LastError == "" || !store.saved.AvailableAt.After(now) {
				t.Fatalf("issued certificate was revoked on cleanup error: found=%t error=%v state=%q saves=%d", found, err, store.saved.State, store.saves)
			}
		})
	}
}

func dnsSafetyOrder(t *testing.T, phase string, now time.Time) (*acmeStub, controlstate.ACMEOrderWork) {
	t.Helper()
	const hostname = "api.example.test"
	csr, certificate := testCertificate(t, hostname, now)
	expires, renewAt := now.Add(time.Hour), now.Add(30*time.Minute)
	api := &acmeStub{order: acmeclient.Order{
		URL: "https://acme.example.test/order/1", Finalize: "https://acme.example.test/finalize/1", Status: "pending", Expires: &expires,
		Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}}, Authorizations: []string{"https://acme.example.test/authorization/1"},
	}}
	work := controlstate.ACMEOrderWork{
		PublicURLID: "public_url_1", State: phase, ChallengeMethod: "dns-01", CSRDER: csr, CertificateIdentifiers: []string{hostname},
		Account: controlstate.ACMEAccount{AccountURL: "https://acme.example.test/account/1"}, OrderURL: api.order.URL,
		Authorizations: []controlstate.ACMEAuthorizationWork{{ID: "authorization_1", Identifier: hostname, AuthorizationURL: api.order.Authorizations[0], ChallengeURL: "https://acme.example.test/challenge/1", ChallengeType: "dns-01", ChallengeDigest: sha256.Sum256([]byte("challenge")), PresentationReference: "presentation_1", State: phase, ExpiresAt: &expires}},
	}
	if phase == "presenting" || phase == "presented" {
		work.State = "authorizing"
	}
	if phase == "presented" {
		work.Authorizations[0].PresentedAt = &now
	}
	if phase == "pending" {
		work.OrderURL = ""
		work.Authorizations = nil
	}
	if phase == "failed" || phase == "canceled" || phase == "finalizing" || phase == "waiting_for_install" || phase == "installed" {
		work.Authorizations[0].State, work.Authorizations[0].PresentedAt = "cleaning", &now
	}
	if phase == "finalizing" || phase == "waiting_for_install" || phase == "installed" {
		work.RenewAt = &renewAt
		work.CertificatePEM = certificate
		notBefore := now.Add(-time.Minute)
		work.NotBefore = &notBefore
		work.NotAfter = &expires
	}
	return api, work
}

type certificateStoreStub struct {
	work           controlstate.ACMEOrderWork
	saved          controlstate.ACMEOrderWork
	saves          int
	claim          func(context.Context) (controlstate.ACMEOrderWork, bool, error)
	challengeReady func(context.Context) (bool, error)
	save           func(controlstate.ACMEOrderWork)
}

func (s *certificateStoreStub) ClaimACMEOrderWork(ctx context.Context, _ string, _ time.Time, _ time.Duration) (controlstate.ACMEOrderWork, bool, error) {
	if s.claim != nil {
		return s.claim(ctx)
	}
	work := s.work
	work.Authorizations = append([]controlstate.ACMEAuthorizationWork(nil), work.Authorizations...)
	return work, true, nil
}
func (s *certificateStoreStub) ACMEChallengeRoutingReady(ctx context.Context, _ string, _ time.Time) (bool, error) {
	if s.challengeReady != nil {
		return s.challengeReady(ctx)
	}
	return true, nil
}
func (s *certificateStoreStub) SaveACMEOrderWork(_ context.Context, work controlstate.ACMEOrderWork, _ time.Time) (controlstate.ACMEOrderWork, error) {
	s.saves++
	s.saved = work
	if s.save != nil {
		s.save(work)
	}
	return work, nil
}
