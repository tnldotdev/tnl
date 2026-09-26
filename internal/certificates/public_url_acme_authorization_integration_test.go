package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationACMEAuthorizationDiscoveryAndReuse(t *testing.T) {
	for _, transient := range []bool{false, true} {
		t.Run(fmt.Sprintf("transient_second_fetch_%v", transient), func(t *testing.T) {
			databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "certificates_route_acme_authorization")
			if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
				t.Fatal(err)
			}
			database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(database.Close)

			now := time.Now().UTC().Truncate(time.Microsecond)
			expires := now.Add(time.Hour)
			identifiers := []string{"*.member.routes.example.test", "member.routes.example.test"}
			const (
				directoryURL        = "https://acme.example.test/directory"
				accountURL          = "https://acme.example.test/account/1"
				orderURL            = "https://acme.example.test/order/1"
				baseAuthorization   = "https://acme.example.test/authz/base"
				wildAuthorization   = "https://acme.example.test/authz/wildcard"
				wildChallenge       = "https://acme.example.test/challenge/wildcard"
				finalizeURL         = "https://acme.example.test/finalize/1"
				transientFetchError = "transient second authorization fetch"
			)
			account, err := database.EnsureACMEAccount(t.Context(), directoryURL, "operator@example.test", now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, accountURL, "", now); err != nil {
				t.Fatal(err)
			}
			for index := range 2 {
				name := fmt.Sprintf("authz-relay-%d", index)
				if _, err := database.RegisterRelay(t.Context(), controlstate.RelayRegistration{
					RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: 1,
					RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test",
					InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10,
				}, now, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			secret, err := database.EnsureExternalAuthorityPrincipal(t.Context(), "identity_authz", now)
			if err != nil {
				t.Fatal(err)
			}
			route, err := database.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{
				TeamID: "team_authz", DomainID: "domain_authz", MembershipID: "membership_authz", ActingIdentityID: "identity_authz",
				IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")), CanonicalHostname: "api." + identifiers[1],
				Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, DNSState: controlstate.PublicURLDNSPending,
				DNSAuthorityReference: "managed:routes.example.test", AuthorityIssuer: "https://authority.example.test", PolicyRevision: 1,
			}, now)
			if err != nil {
				t.Fatal(err)
			}
			setup, err := database.CreatePublishRun(t.Context(), controlstate.PublishRunRequest{
				PublicURLID: route.ID, TeamID: route.TeamID, MembershipID: route.MembershipID, ActingIdentityID: "identity_authz",
				RetrySecret: secret[:], IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")), PolicyRevision: 1,
				CertificateCacheKey: identifiers[1], CertificateScope: identifiers[1], CertificateIdentifiers: identifiers, CertificateChallenge: "dns-01",
				AuthorityIssuer: "https://authority.example.test", ExpectedMutationRevision: route.MutationRevision,
			}, now, time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifiers}, key)
			if err != nil {
				t.Fatal(err)
			}
			authentication := controlstate.PublishRunAuthentication{
				PublicURLID: route.ID, PublishRunID: setup.PublishRunID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken,
			}
			issuance, err := database.CreateCertificateIssuance(t.Context(), controlstate.CreateCertificateIssuanceRequest{
				Authentication: authentication, DirectoryURL: account.DirectoryURL, IdempotencyKey: "issuance",
				RequestDigest: sha256.Sum256(csr), CSRDER: csr,
			}, now)
			if err != nil {
				t.Fatal(err)
			}

			api := &acmeStub{order: acmeclient.Order{
				URL: orderURL, Status: "pending", Expires: &expires, Finalize: finalizeURL,
				Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: identifiers[0]}, {Type: "dns", Value: identifiers[1]}},
				Authorizations: []string{baseAuthorization, wildAuthorization},
			}}
			baseFetches, wildcardFetches := 0, 0
			api.getOrder = func(requestURL string) (acmeclient.Order, error) {
				if requestURL != orderURL {
					return acmeclient.Order{}, fmt.Errorf("unexpected ACME order URL %q", requestURL)
				}
				order := api.order
				if api.acceptCalls != 0 {
					order.Status = "ready"
				}
				return order, nil
			}
			api.getAuthorization = func(requestURL string) (acmeclient.Authorization, error) {
				switch requestURL {
				case baseAuthorization:
					baseFetches++
					return acmeclient.Authorization{
						URL: requestURL, Status: "valid", Expires: &expires,
						Identifier: acmeclient.Identifier{Type: "dns", Value: identifiers[1]},
						Challenges: []acmeclient.Challenge{{Type: "tls-alpn-01", URL: "https://acme.example.test/challenge/old", Status: "valid", Token: "old-token"}},
					}, nil
				case wildAuthorization:
					wildcardFetches++
					if transient && wildcardFetches == 1 {
						return acmeclient.Authorization{}, &acmeclient.Error{
							Status: http.StatusServiceUnavailable, Type: "urn:ietf:params:acme:error:serverInternal", Detail: transientFetchError,
						}
					}
					return acmeclient.Authorization{
						URL: requestURL, Status: "pending", Wildcard: true, Expires: &expires,
						Identifier: acmeclient.Identifier{Type: "dns", Value: identifiers[1]},
						Challenges: []acmeclient.Challenge{{Type: "dns-01", URL: wildChallenge, Token: "wildcard-token"}},
					}, nil
				default:
					return acmeclient.Authorization{}, fmt.Errorf("unexpected ACME authorization URL %q", requestURL)
				}
			}

			store := &authorizationRecordingStore{Database: database}
			dns := &authorizationDNSRecorder{}
			worker, err := NewPublicURLWorker(store, PublicURLConfig{
				WorkerID: "authorization-test", Profile: "tlsserver", HTTPClient: http.DefaultClient,
				DNSChallenges: dns, PollInterval: time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }
			workerNow := now
			worker.now = func() time.Time { return workerNow }
			for range 10 {
				found, err := worker.processOne(t.Context())
				if err != nil || !found {
					t.Fatalf("worker iteration: found %v, error %v", found, err)
				}
				if store.saved[len(store.saved)-1].State == "ready_to_finalize" {
					break
				}
				workerNow = workerNow.Add(10 * time.Second)
			}
			last := store.saved[len(store.saved)-1]
			if last.ID != issuance.ID || last.State != "ready_to_finalize" || len(last.Authorizations) != 2 || api.newOrderCalls != 1 || api.acceptCalls != 1 {
				t.Fatalf("authorization result: %#v, orders %d, accepts %d", last, api.newOrderCalls, api.acceptCalls)
			}
			wildcard, base := last.Authorizations[0], last.Authorizations[1]
			if base.Identifier != identifiers[1] || base.State != "complete" || base.ChallengeType != "" || base.ChallengeURL != "" || base.ChallengeToken != "" ||
				base.ChallengeDigest != ([32]byte{}) || base.PresentationReference != "" || base.ValidatedAt == nil || base.CleanupCompletedAt == nil ||
				base.PresentedAt != nil || wildcard.Identifier != identifiers[0] || wildcard.State != "valid" || wildcard.ChallengeType != "dns-01" ||
				wildcard.PresentationReference == "" || api.acceptedChallenge != wildChallenge || dns.presented != wildcard.ID || dns.verified != wildcard.ID ||
				dns.cleaned != "" || dns.presentCalls != 1 || dns.verifyCalls != 1 || dns.cleanupCalls != 0 {
				t.Fatalf("mixed reused/pending authorizations = %#v; DNS calls %#v", last.Authorizations, dns)
			}
			discovered, failures := false, 0
			for _, saved := range store.saved {
				if len(saved.Authorizations) == 2 && saved.State == "authorizing" &&
					saved.Authorizations[0].State == "presenting" && saved.Authorizations[1].State == "complete" {
					discovered = true
				}
				if saved.LastError == "" {
					continue
				}
				failures++
				if !transient || !strings.Contains(saved.LastError, transientFetchError) || saved.State != "authorizing" ||
					len(saved.Authorizations) != 0 || saved.OrderURL != orderURL {
					t.Fatalf("partial or terminal discovery persisted: %#v", saved)
				}
			}
			if !discovered || failures != map[bool]int{false: 0, true: 1}[transient] ||
				baseFetches != map[bool]int{false: 1, true: 2}[transient] || wildcardFetches != map[bool]int{false: 1, true: 2}[transient] {
				t.Fatalf("discovery: found %v, failures %d, base fetches %d, wildcard fetches %d", discovered, failures, baseFetches, wildcardFetches)
			}

			// Claim from PostgreSQL again so nullable challenge fields and revisions round-trip.
			restartNow := workerNow.Add(10 * time.Second)
			work, found, err := database.ClaimACMEOrderWork(t.Context(), "authorization-restart", restartNow, time.Minute)
			if err != nil || !found || work.ID != last.ID || work.OrderRevision != last.OrderRevision || len(work.Authorizations) != 2 {
				t.Fatalf("restart claim: found %v, error %v, work %#v", found, err, work)
			}
			wildcard, base = work.Authorizations[0], work.Authorizations[1]
			if base.ID != last.Authorizations[1].ID || base.Revision == 0 || base.Revision != last.Authorizations[1].Revision ||
				wildcard.Revision == 0 || wildcard.Revision != last.Authorizations[0].Revision || base.ChallengeType != "" || base.ChallengeURL != "" ||
				base.ChallengeToken != "" || base.ChallengeDigest != ([32]byte{}) || base.PresentationReference != "" || base.PresentedAt != nil ||
				base.ValidatedAt == nil || base.CleanupCompletedAt == nil {
				t.Fatalf("authorization PostgreSQL round-trip: last %#v, claimed %#v", last.Authorizations, work.Authorizations)
			}
			for _, name := range []string{"partial", "token", "digest", "presentation", "not_complete", "expired"} {
				invalid := work
				invalid.Authorizations = slices.Clone(work.Authorizations)
				switch name {
				case "partial":
					invalid.Authorizations = invalid.Authorizations[:1]
				case "token":
					invalid.Authorizations[1].ChallengeToken = "fabricated"
				case "digest":
					invalid.Authorizations[1].ChallengeDigest = sha256.Sum256([]byte("fabricated"))
				case "presentation":
					invalid.Authorizations[1].PresentationReference = "fabricated"
				case "not_complete":
					invalid.Authorizations[1].State = "presenting"
				case "expired":
					invalid.Authorizations[1].ExpiresAt = invalid.Authorizations[1].ValidatedAt
				}
				if _, err := database.SaveACMEOrderWork(t.Context(), invalid, restartNow); !errors.Is(err, controlstate.ErrCertificateIssuanceInvalid) {
					t.Fatalf("%s authorization save = %v", name, err)
				}
			}
			work.AvailableAt = restartNow.Add(time.Hour)
			if _, err := database.SaveACMEOrderWork(t.Context(), work, restartNow); err != nil {
				t.Fatalf("unchanged reused authorization save: %v", err)
			}
			public, err := database.GetCertificateIssuance(t.Context(), work.ID, setup.PublishRunToken, restartNow)
			if err != nil || len(public.Challenges) != 0 {
				t.Fatalf("public challenge collection = %#v, %v", public.Challenges, err)
			}

			// An ACME authorization URL may also be reused by a later order for this account.
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifiers}, key)
			if err != nil {
				t.Fatal(err)
			}
			second, err := database.CreateCertificateIssuance(t.Context(), controlstate.CreateCertificateIssuanceRequest{
				Authentication: authentication, DirectoryURL: account.DirectoryURL, IdempotencyKey: "second-issuance",
				RequestDigest: sha256.Sum256(csr), CSRDER: csr,
			}, restartNow)
			if err != nil {
				t.Fatal(err)
			}
			secondNow := restartNow.Add(time.Second)
			reused, found, err := database.ClaimACMEOrderWork(t.Context(), "authorization-second-order", secondNow, time.Minute)
			if err != nil || !found || reused.ID != second.ID {
				t.Fatalf("second order claim: found %v, error %v, work %#v", found, err, reused)
			}
			reused.State = "ready_to_finalize"
			for _, previous := range work.Authorizations {
				authorization := base
				authorization.ID, authorization.Revision = "", 0
				authorization.Identifier, authorization.AuthorizationURL = previous.Identifier, previous.AuthorizationURL
				reused.Authorizations = append(reused.Authorizations, authorization)
			}
			if _, err := database.SaveACMEOrderWork(t.Context(), reused, secondNow); err != nil {
				t.Fatalf("authorization URL reuse across orders: %v", err)
			}
			if api.newOrderCalls != 1 {
				t.Fatalf("ACME new order calls after durable URL reuse = %d", api.newOrderCalls)
			}
		})
	}
}

type authorizationRecordingStore struct {
	*controlstate.Database
	saved []controlstate.ACMEOrderWork
}

func (s *authorizationRecordingStore) SaveACMEOrderWork(ctx context.Context, work controlstate.ACMEOrderWork, now time.Time) (controlstate.ACMEOrderWork, error) {
	result, err := s.Database.SaveACMEOrderWork(ctx, work, now)
	if err == nil {
		s.saved = append(s.saved, result)
	}
	return result, err
}

type authorizationDNSRecorder struct {
	presented, verified, cleaned            string
	presentCalls, verifyCalls, cleanupCalls int
}

func (d *authorizationDNSRecorder) Present(_ context.Context, _, id string) error {
	d.presented = id
	d.presentCalls++
	return nil
}

func (d *authorizationDNSRecorder) Verify(_ context.Context, _, id string) (bool, error) {
	d.verified = id
	d.verifyCalls++
	return true, nil
}

func (d *authorizationDNSRecorder) Cleanup(_ context.Context, _, id string) error {
	d.cleaned = id
	d.cleanupCalls++
	return nil
}
