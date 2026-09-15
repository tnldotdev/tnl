package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRelayWorkerAdvancesRelayCertificateOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const hostname = "relay-a.example.test"
	csrDER, certificatePEM := relayTestCertificate(t, hostname, now)
	expires := now.Add(time.Hour)
	api := &relayACMEStub{
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
	if work.State != "validating" || api.acceptedChallenge != work.ChallengeURL || dnsChallenges.verified != true {
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
}

func TestRelayWorkerCleansTerminalChallengeFailure(t *testing.T) {
	now := time.Now().UTC()
	worker := &RelayWorker{config: RelayConfig{FailedRetryInterval: time.Hour, DNSChallenges: &relayDNSChallengesStub{}}}
	work := controlstate.RelayCertificateOrderWork{State: "validating", ChallengeURL: "https://acme.example.test/challenge/1"}
	worker.applyFailure(&work, terminalf("authorization expired"), now)
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

type relayACMEStub struct {
	order             acmeclient.Order
	authorization     acmeclient.Authorization
	finalizedOrder    acmeclient.Order
	certificatePEM    []byte
	acceptedChallenge string
}

func (s *relayACMEStub) NewOrder(context.Context, []string, string) (acmeclient.Order, error) {
	return s.order, nil
}
func (s *relayACMEStub) GetOrder(context.Context, string) (acmeclient.Order, error) {
	return s.order, nil
}
func (s *relayACMEStub) GetAuthorization(context.Context, string) (acmeclient.Authorization, error) {
	return s.authorization, nil
}
func (s *relayACMEStub) AcceptChallenge(_ context.Context, challengeURL string) (time.Time, error) {
	s.acceptedChallenge = challengeURL
	return time.Time{}, nil
}
func (s *relayACMEStub) FinalizeOrder(context.Context, string, string, []byte) (acmeclient.Order, error) {
	return s.finalizedOrder, nil
}
func (s *relayACMEStub) DownloadCertificate(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.certificatePEM...), nil
}
func (s *relayACMEStub) KeyAuthorization(token string) (string, error) {
	return token + ".thumbprint", nil
}

type relayDNSChallengesStub struct {
	presented string
	cleaned   string
	verified  bool
	err       error
	cleanup   func(context.Context) error
}

func (s *relayDNSChallengesStub) Present(_ context.Context, orderID string) error {
	s.presented = orderID
	return s.err
}
func (s *relayDNSChallengesStub) Verify(context.Context, string) (bool, error) {
	return s.verified, s.err
}
func (s *relayDNSChallengesStub) Cleanup(ctx context.Context, orderID string) error {
	s.cleaned = orderID
	if s.cleanup != nil {
		return s.cleanup(ctx)
	}
	return s.err
}

func relayTestCertificate(t *testing.T, hostname string, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, key)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}
