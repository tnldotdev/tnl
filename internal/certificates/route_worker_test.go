package certificates

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRouteWorkerAdvancesTLSALPNOrder(t *testing.T) {
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
	worker := &RouteWorker{config: RouteConfig{Profile: "tlsserver", PollInterval: time.Second}}
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
	if !reflect.DeepEqual(api.newOrders, []newOrderCall{{[]string{hostname}, "tlsserver"}}) ||
		!reflect.DeepEqual(api.finalizations, []finalizeCall{{"https://acme.example.test/order/1", "https://acme.example.test/finalize/1", csrDER}}) ||
		!reflect.DeepEqual(api.certificateURLs, []string{"https://acme.example.test/certificate/1"}) {
		t.Fatalf("ACME requests = %#v", api)
	}
}

func TestRouteWorkerAdvancesDNSOrderAndCleansPresentation(t *testing.T) {
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
	worker := &RouteWorker{config: RouteConfig{
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
	wantCall := [2]string{"route_dns", "acme_authorization_dns"}
	if !reflect.DeepEqual(dnsChallenges.presentCalls, [][2]string{wantCall}) ||
		!reflect.DeepEqual(dnsChallenges.verifyCalls, [][2]string{wantCall}) || !reflect.DeepEqual(dnsChallenges.cleanupCalls, [][2]string{wantCall}) {
		t.Fatalf("DNS challenge calls = %#v", dnsChallenges)
	}
}

func TestRouteWorkerDistinguishesApexAndWildcardAuthorizations(t *testing.T) {
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
	worker := &RouteWorker{config: RouteConfig{Profile: "tlsserver", PollInterval: time.Second, DNSChallenges: &dnsChallengesStub{}}}
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

func TestRouteWorkerTerminalFailureFailsAuthorizations(t *testing.T) {
	now := time.Now().UTC()
	worker := &RouteWorker{}
	terminalWork := controlstate.ACMEOrderWork{
		State:          "authorizing",
		Authorizations: []controlstate.ACMEAuthorizationWork{{State: "presenting"}},
	}
	worker.applyFailure(&terminalWork, terminalf("authorization expired"), now)
	if terminalWork.State != "failed" || terminalWork.Authorizations[0].State != "failed" ||
		terminalWork.Authorizations[0].LastError == "" || !terminalWork.AvailableAt.Equal(now) {
		t.Fatalf("terminal work = %#v", terminalWork)
	}
}

func TestRouteWorkerRateLimitHonorsRetryAfter(t *testing.T) {
	now := time.Now().UTC()
	worker := &RouteWorker{}
	retryAt := now.Add(17 * time.Second)
	rateLimitedWork := controlstate.ACMEOrderWork{State: "pending"}
	worker.applyFailure(&rateLimitedWork, &acmeclient.Error{
		Status: 429, Type: "urn:ietf:params:acme:error:rateLimited", Detail: "slow down", RetryAfter: retryAt,
	}, now)
	if rateLimitedWork.State != "pending" || !rateLimitedWork.AvailableAt.Equal(retryAt) || rateLimitedWork.LastError == "" {
		t.Fatalf("rate-limited work = %#v", rateLimitedWork)
	}
}

func TestRouteWorkerRejectsMismatchedAndDuplicateAuthorizations(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	const hostname = "route.example.test"
	tests := []struct {
		name              string
		authorizationURLs []string
		identifier        string
		message           string
	}{
		{name: "mismatch", authorizationURLs: []string{"https://acme.example.test/authorization/1"}, identifier: "other.example.test", message: "not in the certificate plan"},
		{name: "duplicate", authorizationURLs: []string{"https://acme.example.test/authorization/1", "https://acme.example.test/authorization/2"}, identifier: hostname, message: "repeats authorization identifier"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &acmeStub{
				order: acmeclient.Order{
					URL: "https://acme.example.test/order/1", Status: "pending",
					Finalize:    "https://acme.example.test/finalize/1",
					Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}}, Authorizations: test.authorizationURLs,
				},
				getAuthorization: func(url string) (acmeclient.Authorization, error) {
					return acmeclient.Authorization{
						URL: url, Status: "pending",
						Identifier: acmeclient.Identifier{Type: "dns", Value: test.identifier},
						Challenges: []acmeclient.Challenge{{Type: "tls-alpn-01", URL: "https://acme.example.test/challenge/1", Token: "token-1"}},
					}, nil
				},
			}
			worker := &RouteWorker{config: RouteConfig{Profile: "tlsserver", PollInterval: time.Second}}
			work := controlstate.ACMEOrderWork{
				CertificateIdentifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01",
				OrderURL: api.order.URL, State: "authorizing",
			}
			err := worker.advance(t.Context(), api, &work, now)
			var terminal *terminalError
			if !errors.As(err, &terminal) || !strings.Contains(err.Error(), test.message) || len(work.Authorizations) != 0 {
				t.Fatalf("invalid authorization discovery = %v, work %#v", err, work.Authorizations)
			}
		})
	}
}

func TestRouteWorkerReusedAuthorizationNeedsNoChallenge(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	for _, method := range []string{"dns-01", "tls-alpn-01"} {
		t.Run(method, func(t *testing.T) {
			authorization := acmeclient.Authorization{
				URL: "https://acme.example.test/authz/reused", Status: "valid",
				Identifier: acmeclient.Identifier{Type: "dns", Value: "member.example.test"},
				Expires:    timePointer(now.Add(time.Hour)),
				Challenges: []acmeclient.Challenge{{Type: "tls-alpn-01", Token: "old-token"}},
			}
			work, err := authorizationWork(&acmeStub{}, authorization, method, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			if work.State != "complete" || work.ValidatedAt == nil || work.CleanupCompletedAt == nil ||
				work.ChallengeType != "" || work.ChallengeURL != "" || work.ChallengeToken != "" ||
				work.ChallengeDigest != ([32]byte{}) || work.PresentationReference != "" {
				t.Fatalf("reused authorization fabricated challenge work: %#v", work)
			}
		})
	}
}

func TestRouteWorkerRejectsInvalidReusedAuthorizationDiscovery(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	for _, name := range []string{"invalid", "unrequested", "duplicate_identifier", "duplicate_url", "wrong_url", "wrong_type", "expired", "missing_expiry"} {
		t.Run(name, func(t *testing.T) {
			urls := []string{"https://acme.example.test/authz/base", "https://acme.example.test/authz/wildcard"}
			base := acmeclient.Authorization{URL: urls[0], Status: "valid", Expires: timePointer(now.Add(time.Hour)),
				Identifier: acmeclient.Identifier{Type: "dns", Value: "member.example.test"}}
			wildcard := base
			wildcard.URL, wildcard.Wildcard = urls[1], true
			switch name {
			case "invalid":
				wildcard.Status = "invalid"
			case "unrequested":
				wildcard.Identifier.Value = "other.example.test"
			case "duplicate_identifier":
				wildcard.Wildcard = false
			case "duplicate_url":
				urls[1] = urls[0]
			case "wrong_url":
				wildcard.URL = "https://acme.example.test/authz/other"
			case "wrong_type":
				wildcard.Identifier.Type = "ip"
			case "expired":
				wildcard.Expires = timePointer(now)
			case "missing_expiry":
				wildcard.Expires = nil
			}
			api := &acmeStub{order: acmeclient.Order{URL: "https://acme.example.test/order/1", Status: "pending",
				Finalize: "https://acme.example.test/finalize/1", Authorizations: urls,
				Identifiers: []acmeclient.Identifier{{Type: "dns", Value: "member.example.test"}, {Type: "dns", Value: "*.member.example.test"}}},
				authorizations: map[string]acmeclient.Authorization{urls[0]: base, "https://acme.example.test/authz/wildcard": wildcard}}
			worker := &RouteWorker{config: RouteConfig{DNSChallenges: &dnsChallengesStub{}, PollInterval: time.Second}}
			work := controlstate.ACMEOrderWork{State: "authorizing", OrderURL: api.order.URL, ChallengeMethod: "dns-01",
				CertificateIdentifiers: []string{"member.example.test", "*.member.example.test"}}
			err := worker.advance(t.Context(), api, &work, now)
			var terminal *terminalError
			if !errors.As(err, &terminal) || len(work.Authorizations) != 0 {
				t.Fatalf("invalid discovery = %v, persisted authorizations %#v", err, work.Authorizations)
			}
		})
	}
}

func TestRouteWorkerRejectsExpiredPresentedAuthorization(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	const hostname = "route.example.test"
	expires := now.Add(-time.Second)
	api := &acmeStub{order: acmeclient.Order{
		URL: "https://acme.example.test/order/1", Status: "pending",
		Finalize:       "https://acme.example.test/finalize/1",
		Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
		Authorizations: []string{"https://acme.example.test/authorization/1"},
	}}
	worker := &RouteWorker{config: RouteConfig{Profile: "tlsserver", PollInterval: time.Second}}
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

func TestRouteWorkerRejectsFutureDatedCertificate(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	const hostname = "route.example.test"
	csrDER, certificatePEM := testCertificateValidity(t, hostname, now.Add(time.Minute), now.Add(time.Hour))
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/1", Status: "valid",
			Finalize:    "https://acme.example.test/finalize/1",
			Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Certificate: "https://acme.example.test/certificate/1",
		},
		certificatePEM: certificatePEM,
	}
	worker := &RouteWorker{config: RouteConfig{Profile: "tlsserver", PollInterval: time.Second}}
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

type dnsChallengesStub struct {
	presented                               string
	verifiedAuthorization                   string
	cleaned                                 string
	verified                                bool
	err                                     error
	cleanup                                 func(context.Context) error
	presentCalls, verifyCalls, cleanupCalls [][2]string
}

func (s *dnsChallengesStub) Present(_ context.Context, routeID, authorizationID string) error {
	s.presented = authorizationID
	s.presentCalls = append(s.presentCalls, [2]string{routeID, authorizationID})
	return s.err
}

func (s *dnsChallengesStub) Verify(_ context.Context, routeID, authorizationID string) (bool, error) {
	s.verifiedAuthorization = authorizationID
	s.verifyCalls = append(s.verifyCalls, [2]string{routeID, authorizationID})
	return s.verified, s.err
}

func (s *dnsChallengesStub) Cleanup(ctx context.Context, routeID, authorizationID string) error {
	s.cleaned = authorizationID
	s.cleanupCalls = append(s.cleanupCalls, [2]string{routeID, authorizationID})
	if s.cleanup != nil {
		return s.cleanup(ctx)
	}
	return s.err
}
