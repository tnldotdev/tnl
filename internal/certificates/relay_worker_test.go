package certificates

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRelayWorkerAdvancesRelayCertificateOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const hostname = "relay-a.example.test"
	csrDER, certificatePEM := testCertificate(t, hostname, now)
	expires := now.Add(time.Hour)
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/1", Status: "pending", Expires: &expires,
			Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Authorizations: []string{"https://acme.example.test/authorization/1"},
			Finalize:       "https://acme.example.test/finalize/1",
		},
		authorization: acmeclient.Authorization{
			URL: "https://acme.example.test/authorization/1", Status: "pending", Expires: &expires,
			Identifier: acmeclient.Identifier{Type: "dns", Value: hostname},
			Challenges: []acmeclient.Challenge{{
				Type: "dns-01", URL: "https://acme.example.test/challenge/1", Status: "pending", Token: "token-1",
			}},
		},
		certificatePEM: certificatePEM,
	}
	dnsChallenges := &relayDNSChallengesStub{verified: true}
	worker := &RelayWorker{config: RelayConfig{
		Profile: "tlsserver", PollInterval: time.Second, FailedRetryInterval: time.Hour,
		DNSChallenges: dnsChallenges,
	}}
	work := controlstate.RelayCertificateOrderWork{
		ID: "relay_certificate_order_1", TLSServerName: hostname, CSRDER: csrDER,
		State: "pending", AvailableAt: now,
	}

	if err := worker.advance(t.Context(), api, &work, now); err != nil {
		t.Fatal(err)
	}
	if work.State != "authorizing" || work.OrderURL != api.order.URL {
		t.Fatalf("created order work = %#v", work)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "presenting" || work.AuthorizationURL == "" || work.PresentationReference == "" {
		t.Fatalf("presenting order work = %#v", work)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "presented" || dnsChallenges.presented != work.ID {
		t.Fatalf("presented order work = %#v, calls %#v", work, dnsChallenges)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "validating" || api.acceptedChallenge != work.ChallengeURL || dnsChallenges.verifiedOrder != work.ID {
		t.Fatalf("validating order work = %#v, calls %#v", work, dnsChallenges)
	}
	api.authorization.Status = "valid"
	if err := worker.advance(t.Context(), api, &work, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	api.order.Status = "ready"
	if err := worker.advance(t.Context(), api, &work, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	api.finalizedOrder = api.order
	api.finalizedOrder.Status = "processing"
	if err := worker.advance(t.Context(), api, &work, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	api.order.Status = "valid"
	api.order.Certificate = "https://acme.example.test/certificate/1"
	if err := worker.advance(t.Context(), api, &work, now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "cleaning" || len(work.CertificatePEM) == 0 || work.RenewAt == nil {
		t.Fatalf("issued order work = %#v", work)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "complete" || dnsChallenges.cleaned != work.ID {
		t.Fatalf("completed order work = %#v, calls %#v", work, dnsChallenges)
	}
	if !reflect.DeepEqual(work.CertificatePEM, certificatePEM) || work.NotBefore == nil || !work.NotBefore.Equal(now.Add(-time.Minute)) ||
		work.NotAfter == nil || !work.NotAfter.Equal(now.Add(time.Hour)) ||
		!reflect.DeepEqual(dnsChallenges.presentCalls, []string{"relay_certificate_order_1"}) ||
		!reflect.DeepEqual(dnsChallenges.verifyCalls, []string{"relay_certificate_order_1"}) ||
		!reflect.DeepEqual(dnsChallenges.cleanupCalls, []string{"relay_certificate_order_1"}) {
		t.Fatalf("completed certificate = %#v, DNS calls = %#v", work, dnsChallenges)
	}
	if !reflect.DeepEqual(api.newOrders, []newOrderCall{{[]string{hostname}, "tlsserver"}}) ||
		!reflect.DeepEqual(api.finalizations, []finalizeCall{{"https://acme.example.test/order/1", "https://acme.example.test/finalize/1", csrDER}}) ||
		!reflect.DeepEqual(api.certificateURLs, []string{"https://acme.example.test/certificate/1"}) {
		t.Fatalf("ACME requests = %#v", api)
	}
}

func TestRelayWorkerCleansTerminalChallengeFailure(t *testing.T) {
	now := time.Now().UTC()
	worker := &RelayWorker{config: RelayConfig{FailedRetryInterval: time.Hour, DNSChallenges: &relayDNSChallengesStub{}}}
	work := controlstate.RelayCertificateOrderWork{State: "validating", ChallengeURL: "https://acme.example.test/challenge/1"}
	worker.applyFailure(&work, &acmeclient.Error{
		Status: 404, Type: "urn:ietf:params:acme:error:malformed", Detail: "Expired authorization",
	}, now)
	if work.State != "failed_cleaning" || !work.AvailableAt.Equal(now) || work.LastError == "" {
		t.Fatalf("terminal work = %#v", work)
	}
	if err := worker.advance(t.Context(), nil, &work, now); err != nil {
		t.Fatal(err)
	}
	if work.State != "failed" || !work.AvailableAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("cleaned failure = %#v", work)
	}
}

type relayDNSChallengesStub struct {
	presented                               string
	verifiedOrder                           string
	cleaned                                 string
	verified                                bool
	err                                     error
	cleanup                                 func(context.Context) error
	presentCalls, verifyCalls, cleanupCalls []string
}

func (s *relayDNSChallengesStub) Present(_ context.Context, orderID string) error {
	s.presented = orderID
	s.presentCalls = append(s.presentCalls, orderID)
	return s.err
}
func (s *relayDNSChallengesStub) Verify(_ context.Context, orderID string) (bool, error) {
	s.verifiedOrder = orderID
	s.verifyCalls = append(s.verifyCalls, orderID)
	return s.verified, s.err
}
func (s *relayDNSChallengesStub) Cleanup(ctx context.Context, orderID string) error {
	s.cleaned = orderID
	s.cleanupCalls = append(s.cleanupCalls, orderID)
	if s.cleanup != nil {
		return s.cleanup(ctx)
	}
	return s.err
}
