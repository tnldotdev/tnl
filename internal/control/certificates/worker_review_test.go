package certificates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	acmeclient "github.com/tnldotdev/tnl/internal/control/certificates/acme"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/testutil/workerobservation"
)

type blockingACME struct {
	acmeStub
	calls   int
	started func()
	retry   bool
}

func (a *blockingACME) NewOrder(ctx context.Context, _ []string, _ string) (acmeclient.Order, error) {
	a.calls++
	if a.retry && a.calls > 1 {
		return a.order, nil
	}
	if a.started != nil {
		a.started()
	}
	<-ctx.Done()
	return acmeclient.Order{}, ctx.Err()
}

type retryRelayStore struct {
	relayStoreStub
	claims int
	stop   context.CancelFunc
}

func (s *retryRelayStore) ClaimRelayCertificateOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.RelayCertificateOrderWork, bool, error) {
	s.claims++
	if s.claims > 2 {
		s.stop()
		return controlstate.RelayCertificateOrderWork{}, false, nil
	}
	return s.work, true, nil
}

func (s *retryRelayStore) SaveRelayCertificateOrderWork(ctx context.Context, work controlstate.RelayCertificateOrderWork, now time.Time) (controlstate.RelayCertificateOrderWork, error) {
	saved, err := s.relayStoreStub.SaveRelayCertificateOrderWork(ctx, work, now)
	s.stop()
	return saved, err
}

func TestCertificateAttemptDeadlineReportsAndRetriesWithLiveParent(t *testing.T) {
	for _, kind := range []string{"service", "relay"} {
		t.Run(kind, func(t *testing.T) {
			ctx, record := workerobservation.Start(t)
			ctx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			api := &blockingACME{retry: true, acmeStub: acmeStub{order: acmeclient.Order{URL: "https://acme.example/order", Status: "pending", Finalize: "https://acme.example/finalize", Identifiers: []acmeclient.Identifier{{Type: "dns", Value: "app.example.test"}}, Authorizations: []string{"https://acme.example/authorization"}}}}
			factory := func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }
			account := controlstate.ACMEAccount{AccountURL: "https://acme.example/account"}
			if kind == "service" {
				store := &certificateStoreStub{}
				claims := 0
				store.claim = func(context.Context) (controlstate.ACMEOrderWork, bool, error) {
					claims++
					if claims > 2 {
						stop()
						return controlstate.ACMEOrderWork{}, false, nil
					}
					return controlstate.ACMEOrderWork{Account: account, State: "pending", ChallengeMethod: "dns-01", CertificateIdentifiers: []string{"app.example.test"}}, true, nil
				}
				store.save = func(controlstate.ACMEOrderWork) { stop() }
				worker, err := NewPublicURLWorker(store, PublicURLConfig{WorkerID: "review", Profile: "tlsserver", HTTPClient: &http.Client{}, DNSChallenges: &dnsChallengesStub{}, OperationTimeout: 20 * time.Millisecond, IdleInterval: time.Millisecond, Observer: record.Owner})
				if err != nil {
					t.Fatal(err)
				}
				worker.client = factory
				if err := worker.Run(ctx); err != nil {
					t.Fatal(err)
				}
				if claims != 2 || store.saves != 1 || store.saved.State != "authorizing" {
					t.Fatal("deadline did not retry and advance recoverable work", claims, store.saved)
				}
			} else {
				api.order.Identifiers[0].Value = "relay.example.test"
				store := &retryRelayStore{relayStoreStub: relayStoreStub{work: controlstate.RelayCertificateOrderWork{Account: account, State: "pending", TLSServerName: "relay.example.test"}}, stop: stop}
				worker, err := NewRelayWorker(store, RelayConfig{WorkerID: "review", AccountID: "account", Profile: "tlsserver", HTTPClient: &http.Client{}, DNSChallenges: &relayDNSChallengesStub{}, OperationTimeout: 20 * time.Millisecond, IdleInterval: time.Millisecond, Observer: record.Owner})
				if err != nil {
					t.Fatal(err)
				}
				worker.client = factory
				if err := worker.Run(ctx); err != nil {
					t.Fatal(err)
				}
				if store.claims != 2 || store.saves != 1 || store.saved.State != "authorizing" {
					t.Fatal("deadline did not retry and advance recoverable work", store.claims, store.saved)
				}
			}
			if api.calls != 2 {
				t.Fatal("provider did not retry", api.calls)
			}
			record.AssertFailure(t, "certificate."+kind+".attempt", "timeout", string(failure.ServerCertificateFailed))
			if !strings.Contains(record.Logs(), "timeout=true") {
				t.Fatal("missing timeout diagnostic")
			}
		})
	}
}

func TestCertificateLifetimeShutdownDoesNotReportAttemptFailure(t *testing.T) {
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
			api := &blockingACME{}
			if mode == "cancel" {
				api.started = stop
			}
			store := &certificateStoreStub{work: controlstate.ACMEOrderWork{Account: controlstate.ACMEAccount{AccountURL: "https://acme.example/account"}, State: "pending", ChallengeMethod: "dns-01", CertificateIdentifiers: []string{"app.example.test"}}}
			worker, err := NewPublicURLWorker(store, PublicURLConfig{WorkerID: "review", Profile: "tlsserver", HTTPClient: &http.Client{}, DNSChallenges: &dnsChallengesStub{}, OperationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }
			if err := worker.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if api.calls != 1 || record.Logs() != "" {
				t.Fatal("shutdown reported operational failure", record.Logs())
			}
		})
	}
}

func TestServiceCertificateQueueCountsUnclassifiedClaims(t *testing.T) {
	for _, phase := range []string{"begin", "query", "commit", "empty", "public_url", "managed_service"} {
		t.Run(phase, func(t *testing.T) {
			ctx, record := workerobservation.Start(t)
			cause := &pgconn.PgError{Code: "XX000", Message: "private-provider-cause"}
			var wantErr error
			kind, outcome := "service_queue", "error"
			store := &certificateStoreStub{claim: func(context.Context) (controlstate.ACMEOrderWork, bool, error) {
				if phase == "empty" {
					return controlstate.ACMEOrderWork{}, false, nil
				}
				if phase == "public_url" || phase == "managed_service" {
					work := controlstate.ACMEOrderWork{Account: controlstate.ACMEAccount{AccountURL: "https://acme.example/account"}, State: "canceled", ChallengeMethod: "dns-01"}
					if phase == "managed_service" {
						work.PrivateRunID = "private-run"
					}
					return work, true, nil
				}
				wantErr = fmt.Errorf("claim ACME order work: %s: %w", phase, cause)
				return controlstate.ACMEOrderWork{}, false, wantErr
			}}
			if phase == "empty" {
				outcome = "empty"
			} else if phase == "public_url" || phase == "managed_service" {
				kind, outcome = phase, "claimed"
			}
			worker, err := NewPublicURLWorker(store, PublicURLConfig{WorkerID: "review", Profile: "tlsserver", HTTPClient: &http.Client{}, DNSChallenges: &dnsChallengesStub{}, Observer: record.Owner})
			if err != nil {
				t.Fatal(err)
			}
			worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return &acmeStub{}, nil }
			found, err := worker.processOne(ctx)
			if (wantErr != nil && !errors.Is(err, cause)) || (wantErr == nil && err != nil) || found != (outcome == "claimed") {
				t.Fatal("claim result changed", found, err)
			}
			response := httptest.NewRecorder()
			record.Owner.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			reason := ""
			if outcome != "error" {
				reason = fmt.Sprintf(`,tnl_reason=%q`, outcome)
			}
			want := fmt.Sprintf(`tnl_control_certificate_claims_total{tnl_certificate_kind=%q,tnl_outcome=%q%s} 1`, kind, map[string]string{"error": "error", "empty": "success", "claimed": "success"}[outcome], reason)
			if !strings.Contains(response.Body.String(), want) {
				t.Fatalf("claim count missing: %s\n%s", want, response.Body.String())
			}
			if outcome == "error" {
				record.AssertFailure(t, "certificate.service.attempt", "error", string(failure.ServerCertificateFailed))
			}
			if kind == "service_queue" && (strings.Contains(response.Body.String(), `tnl_control_certificate_claims_total{tnl_certificate_kind="public_url"`) || strings.Contains(response.Body.String(), `tnl_control_certificate_claims_total{tnl_certificate_kind="managed_service"`)) {
				t.Fatal("unclassified claim invented a service kind")
			}
		})
	}
}
