package certificateworker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestWorkerAdvancesTLSALPNOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const hostname = "route.example.test"
	csrDER, certificatePEM := testCertificate(t, hostname, now)
	expires := now.Add(time.Hour)
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/1", Status: "pending", Expires: &expires,
			RetryAfter:     now.Add(time.Minute),
			Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Authorizations: []string{"https://acme.example.test/authorization/1"},
			Finalize:       "https://acme.example.test/finalize/1",
		},
		authorization: acmeclient.Authorization{
			URL: "https://acme.example.test/authorization/1", Status: "pending", Expires: &expires,
			Identifier: acmeclient.Identifier{Type: "dns", Value: hostname},
			Challenges: []acmeclient.Challenge{{
				Type: "tls-alpn-01", URL: "https://acme.example.test/challenge/1", Status: "pending", Token: "token-1",
			}},
		},
		certificatePEM:   certificatePEM,
		challengeRetryAt: now.Add(2 * time.Minute),
	}
	worker := &Worker{config: Config{Profile: "tlsserver", PollInterval: time.Second}}
	work := controlstate.ACMEOrderWork{
		CertificateIdentifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01", CSRDER: csrDER,
		State: "pending", AvailableAt: now,
	}
	if err := worker.advance(t.Context(), api, &work, now); err != nil {
		t.Fatal(err)
	}
	if work.State != "authorizing" || work.OrderURL != api.order.URL || len(work.Authorizations) != 0 ||
		!work.AvailableAt.Equal(api.order.RetryAfter) {
		t.Fatalf("created order work = %#v", work)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(work.Authorizations) != 1 || work.Authorizations[0].State != "presenting" || work.Authorizations[0].ChallengeDigest == ([32]byte{}) {
		t.Fatalf("presenting order work = %#v", work)
	}
	work.Authorizations[0].State = "presented"
	if err := worker.advance(t.Context(), api, &work, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.Authorizations[0].State != "validating" || api.acceptedChallenge != work.Authorizations[0].ChallengeURL ||
		!work.AvailableAt.Equal(api.challengeRetryAt) {
		t.Fatalf("validating order work = %#v, accepted = %q", work, api.acceptedChallenge)
	}
	api.authorization.Status = "valid"
	if err := worker.advance(t.Context(), api, &work, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.Authorizations[0].State != "valid" {
		t.Fatalf("valid authorization work = %#v", work)
	}
	api.order.Status = "ready"
	if err := worker.advance(t.Context(), api, &work, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "ready_to_finalize" {
		t.Fatalf("ready order work = %#v", work)
	}
	api.finalizedOrder = api.order
	api.finalizedOrder.Status = "processing"
	if err := worker.advance(t.Context(), api, &work, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "finalizing" || string(api.finalizedCSR) != string(csrDER) {
		t.Fatalf("finalizing order work = %#v", work)
	}
	api.order.Status = "valid"
	api.order.Certificate = "https://acme.example.test/certificate/1"
	if err := worker.advance(t.Context(), api, &work, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "waiting_for_install" || len(work.CertificatePEM) == 0 || work.NotBefore == nil || work.NotAfter == nil || work.RenewAt == nil {
		t.Fatalf("completed order work = %#v", work)
	}
}

func TestWorkerAdvancesDNSOrderAndCleansPresentation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const hostname = "route.example.test"
	csrDER, certificatePEM := testCertificate(t, hostname, now)
	expires := now.Add(time.Hour)
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/dns", Status: "pending", Expires: &expires,
			Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Authorizations: []string{"https://acme.example.test/authorization/dns"},
			Finalize:       "https://acme.example.test/finalize/dns",
		},
		authorization: acmeclient.Authorization{
			URL: "https://acme.example.test/authorization/dns", Status: "pending", Expires: &expires,
			Identifier: acmeclient.Identifier{Type: "dns", Value: hostname},
			Challenges: []acmeclient.Challenge{{
				Type: "dns-01", URL: "https://acme.example.test/challenge/dns", Status: "pending", Token: "dns-token",
			}},
		},
		certificatePEM: certificatePEM,
	}
	dnsChallenges := &dnsChallengesStub{verified: true}
	worker := &Worker{config: Config{
		Profile: "tlsserver", PollInterval: time.Second, DNSChallenges: dnsChallenges,
	}}
	work := controlstate.ACMEOrderWork{
		RouteID: "route_dns", CertificateIdentifiers: []string{hostname}, ChallengeMethod: "dns-01",
		CSRDER: csrDER, State: "pending", AvailableAt: now,
	}
	if err := worker.advance(t.Context(), api, &work, now); err != nil {
		t.Fatal(err)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(work.Authorizations) != 1 || work.Authorizations[0].State != "presenting" {
		t.Fatalf("persistable DNS authorization = %#v", work.Authorizations)
	}
	work.Authorizations[0].ID = "acme_authorization_dns"
	if err := worker.advance(t.Context(), api, &work, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.Authorizations[0].State != "presented" || dnsChallenges.presented != work.Authorizations[0].ID {
		t.Fatalf("presented DNS authorization = %#v, calls %#v", work.Authorizations[0], dnsChallenges)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.Authorizations[0].State != "validating" || dnsChallenges.verifiedAuthorization != work.Authorizations[0].ID {
		t.Fatalf("validating DNS authorization = %#v, calls %#v", work.Authorizations[0], dnsChallenges)
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
	api.order.Certificate = "https://acme.example.test/certificate/dns"
	if err := worker.advance(t.Context(), api, &work, now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "finalizing" || work.Authorizations[0].State != "cleaning" || len(work.CertificatePEM) == 0 {
		t.Fatalf("cleaning DNS order = %#v", work)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.Authorizations[0].State != "complete" || dnsChallenges.cleaned != work.Authorizations[0].ID {
		t.Fatalf("cleaned DNS authorization = %#v, calls %#v", work.Authorizations[0], dnsChallenges)
	}
	if err := worker.advance(t.Context(), api, &work, now.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if work.State != "waiting_for_install" {
		t.Fatalf("completed DNS order = %#v", work)
	}
}

func TestWorkerDistinguishesApexAndWildcardAuthorizations(t *testing.T) {
	now := time.Now().UTC()
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/namespace", Status: "pending",
			Finalize: "https://acme.example.test/finalize/namespace",
			Identifiers: []acmeclient.Identifier{
				{Type: "dns", Value: "member.example.test"}, {Type: "dns", Value: "*.member.example.test"},
			},
			Authorizations: []string{
				"https://acme.example.test/authorization/apex", "https://acme.example.test/authorization/wildcard",
			},
		},
		authorizations: map[string]acmeclient.Authorization{
			"https://acme.example.test/authorization/apex": {
				URL: "https://acme.example.test/authorization/apex", Status: "pending",
				Identifier: acmeclient.Identifier{Type: "dns", Value: "member.example.test"},
				Challenges: []acmeclient.Challenge{{Type: "dns-01", URL: "https://acme.example.test/challenge/apex", Token: "apex"}},
			},
			"https://acme.example.test/authorization/wildcard": {
				URL: "https://acme.example.test/authorization/wildcard", Status: "pending", Wildcard: true,
				Identifier: acmeclient.Identifier{Type: "dns", Value: "member.example.test"},
				Challenges: []acmeclient.Challenge{{Type: "dns-01", URL: "https://acme.example.test/challenge/wildcard", Token: "wildcard"}},
			},
		},
	}
	worker := &Worker{config: Config{Profile: "tlsserver", PollInterval: time.Second, DNSChallenges: &dnsChallengesStub{}}}
	work := controlstate.ACMEOrderWork{
		CertificateIdentifiers: []string{"*.member.example.test", "member.example.test"},
		ChallengeMethod:        "dns-01", OrderURL: api.order.URL, State: "authorizing",
	}
	if err := worker.advance(t.Context(), api, &work, now); err != nil {
		t.Fatal(err)
	}
	if len(work.Authorizations) != 2 || work.Authorizations[0].Identifier != "member.example.test" ||
		work.Authorizations[1].Identifier != "*.member.example.test" {
		t.Fatalf("multi-identifier authorizations = %#v", work.Authorizations)
	}
}

func TestWorkerPersistsTerminalAndRateLimitedFailures(t *testing.T) {
	now := time.Now().UTC()
	worker := &Worker{}
	terminalWork := controlstate.ACMEOrderWork{
		State:          "authorizing",
		Authorizations: []controlstate.ACMEAuthorizationWork{{State: "presenting"}},
	}
	worker.applyFailure(&terminalWork, terminalf("authorization expired"), now)
	if terminalWork.State != "failed" || terminalWork.Authorizations[0].State != "failed" ||
		terminalWork.Authorizations[0].LastError == "" || !terminalWork.AvailableAt.Equal(now) {
		t.Fatalf("terminal work = %#v", terminalWork)
	}
	retryAt := now.Add(17 * time.Second)
	rateLimitedWork := controlstate.ACMEOrderWork{State: "pending"}
	worker.applyFailure(&rateLimitedWork, &acmeclient.Error{
		Status: 429, Type: "urn:ietf:params:acme:error:rateLimited", Detail: "slow down", RetryAfter: retryAt,
	}, now)
	if rateLimitedWork.State != "pending" || !rateLimitedWork.AvailableAt.Equal(retryAt) || rateLimitedWork.LastError == "" {
		t.Fatalf("rate-limited work = %#v", rateLimitedWork)
	}
}

func TestWorkerRejectsMismatchedAndDuplicateAuthorizations(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	const hostname = "route.example.test"
	tests := []struct {
		name              string
		authorizationURLs []string
		identifier        string
	}{
		{name: "mismatch", authorizationURLs: []string{"https://acme.example.test/authorization/1"}, identifier: "other.example.test"},
		{name: "duplicate", authorizationURLs: []string{"https://acme.example.test/authorization/1", "https://acme.example.test/authorization/2"}, identifier: hostname},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &acmeStub{
				order: acmeclient.Order{
					URL: "https://acme.example.test/order/1", Status: "pending",
					Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}}, Authorizations: test.authorizationURLs,
				},
				authorization: acmeclient.Authorization{
					URL: "https://acme.example.test/authorization/1", Status: "pending",
					Identifier: acmeclient.Identifier{Type: "dns", Value: test.identifier},
					Challenges: []acmeclient.Challenge{{Type: "tls-alpn-01", URL: "https://acme.example.test/challenge/1", Token: "token-1"}},
				},
			}
			worker := &Worker{config: Config{Profile: "tlsserver", PollInterval: time.Second}}
			work := controlstate.ACMEOrderWork{
				CertificateIdentifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01",
				OrderURL: api.order.URL, State: "authorizing",
			}
			if err := worker.advance(t.Context(), api, &work, now); err == nil {
				t.Fatal("advance accepted invalid authorizations")
			}
		})
	}
}

func TestWorkerRejectsExpiredPresentedAuthorization(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	const hostname = "route.example.test"
	expires := now.Add(-time.Second)
	api := &acmeStub{order: acmeclient.Order{
		URL: "https://acme.example.test/order/1", Status: "pending",
		Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
		Authorizations: []string{"https://acme.example.test/authorization/1"},
	}}
	worker := &Worker{config: Config{Profile: "tlsserver", PollInterval: time.Second}}
	work := controlstate.ACMEOrderWork{
		CertificateIdentifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01",
		OrderURL: api.order.URL, State: "authorizing",
		Authorizations: []controlstate.ACMEAuthorizationWork{{
			Identifier: hostname, AuthorizationURL: api.order.Authorizations[0], State: "presented", ExpiresAt: &expires,
		}},
	}
	if err := worker.advance(t.Context(), api, &work, now); err == nil {
		t.Fatal("advance accepted an expired presented authorization")
	}
	if api.acceptedChallenge != "" {
		t.Fatalf("accepted expired challenge %q", api.acceptedChallenge)
	}
}

func TestWorkerRejectsFutureDatedCertificate(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	const hostname = "route.example.test"
	csrDER, certificatePEM := testCertificateValidity(t, hostname, now.Add(time.Minute), now.Add(time.Hour))
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/1", Status: "valid",
			Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Certificate: "https://acme.example.test/certificate/1",
		},
		certificatePEM: certificatePEM,
	}
	worker := &Worker{config: Config{Profile: "tlsserver", PollInterval: time.Second}}
	work := controlstate.ACMEOrderWork{
		CertificateIdentifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01", CSRDER: csrDER,
		OrderURL: api.order.URL, State: "finalizing",
	}
	if err := worker.advance(t.Context(), api, &work, now); err == nil {
		t.Fatal("advance accepted a certificate whose validity has not begun")
	}
}

func TestTruncateErrorPreservesUTF8(t *testing.T) {
	t.Parallel()

	message := strings.Repeat("e\u0301", 1000)
	truncated := truncateError(terminalf("%s", message))
	if len(truncated) > 1024 || !utf8.ValidString(truncated) {
		t.Fatalf("truncated error has %d bytes and valid UTF-8 = %v", len(truncated), utf8.ValidString(truncated))
	}
}

type acmeStub struct {
	order             acmeclient.Order
	authorization     acmeclient.Authorization
	authorizations    map[string]acmeclient.Authorization
	finalizedOrder    acmeclient.Order
	certificatePEM    []byte
	acceptedChallenge string
	challengeRetryAt  time.Time
	finalizedCSR      []byte
}

func (s *acmeStub) NewOrder(context.Context, []string, string) (acmeclient.Order, error) {
	return s.order, nil
}

func (s *acmeStub) GetOrder(context.Context, string) (acmeclient.Order, error) {
	return s.order, nil
}

func (s *acmeStub) GetAuthorization(_ context.Context, authorizationURL string) (acmeclient.Authorization, error) {
	if s.authorizations != nil {
		return s.authorizations[authorizationURL], nil
	}
	return s.authorization, nil
}

func (s *acmeStub) AcceptChallenge(_ context.Context, challengeURL string) (time.Time, error) {
	s.acceptedChallenge = challengeURL
	return s.challengeRetryAt, nil
}

func (s *acmeStub) FinalizeOrder(_ context.Context, _, _ string, csrDER []byte) (acmeclient.Order, error) {
	s.finalizedCSR = append([]byte(nil), csrDER...)
	return s.finalizedOrder, nil
}

func (s *acmeStub) DownloadCertificate(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.certificatePEM...), nil
}

func (s *acmeStub) KeyAuthorization(token string) (string, error) {
	return token + ".thumbprint", nil
}

type dnsChallengesStub struct {
	presented             string
	verifiedAuthorization string
	cleaned               string
	verified              bool
}

func (s *dnsChallengesStub) Present(_ context.Context, _, authorizationID string) error {
	s.presented = authorizationID
	return nil
}

func (s *dnsChallengesStub) Verify(_ context.Context, _, authorizationID string) (bool, error) {
	s.verifiedAuthorization = authorizationID
	return s.verified, nil
}

func (s *dnsChallengesStub) Cleanup(_ context.Context, _, authorizationID string) error {
	s.cleaned = authorizationID
	return nil
}

func testCertificate(t *testing.T, hostname string, now time.Time) ([]byte, []byte) {
	return testCertificateValidity(t, hostname, now.Add(-time.Minute), now.Add(time.Hour))
}

func testCertificateValidity(t *testing.T, hostname string, notBefore, notAfter time.Time) ([]byte, []byte) {
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
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}
