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

	"github.com/tnldotdev/tnl/internal/control/certificates/acme"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationACMEAuthorizationDiscoveryAndReuse(t *testing.T) {
	for _, transient := range []bool{false, true} {
		t.Run(fmt.Sprintf("transient_second_fetch_%v", transient), func(t *testing.T) {
			databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "certificates_service_acme_authorization")
			if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
				t.Fatal(err)
			}
			database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(database.Close)

			now := time.Now().UTC().Truncate(time.Microsecond)
			expires := now.Add(time.Hour)
			const (
				directoryURL        = "https://acme.example.test/directory"
				accountURL          = "https://acme.example.test/account/1"
				orderURL            = "https://acme.example.test/order/1"
				wildAuthorization   = "https://acme.example.test/authz/wildcard"
				wildChallenge       = "https://acme.example.test/challenge/wildcard"
				finalizeURL         = "https://acme.example.test/finalize/1"
				transientFetchError = "transient authorization fetch"
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
			prepared, run := serviceCertificateRun(t, database, "routes.example.test", now)
			identifiers := prepared.CertificatePlan.Identifiers
			if len(identifiers) != 1 || identifiers[0] != prepared.Hostname {
				t.Fatalf("service plan must capture the exact hostname: %#v", prepared.CertificatePlan)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifiers}, key)
			if err != nil {
				t.Fatal(err)
			}
			issuance, err := database.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token,
				account.DirectoryURL, "issuance", run.RunNumber, csr, now)
			if err != nil {
				t.Fatal(err)
			}

			api := &acmeStub{order: acme.Order{
				URL: orderURL, Status: "pending", Expires: &expires, Finalize: finalizeURL,
				Identifiers:    []acme.Identifier{{Type: "dns", Value: identifiers[0]}},
				Authorizations: []string{wildAuthorization},
			}}
			wildcardFetches := 0
			api.getOrder = func(requestURL string) (acme.Order, error) {
				if requestURL != orderURL {
					return acme.Order{}, fmt.Errorf("unexpected ACME order URL %q", requestURL)
				}
				order := api.order
				if api.acceptCalls != 0 {
					order.Status = "ready"
				}
				return order, nil
			}
			api.getAuthorization = func(requestURL string) (acme.Authorization, error) {
				switch requestURL {
				case wildAuthorization:
					wildcardFetches++
					if transient && wildcardFetches == 1 {
						return acme.Authorization{}, &acme.Error{
							Status: http.StatusServiceUnavailable, Type: "urn:ietf:params:acme:error:serverInternal", Detail: transientFetchError,
						}
					}
					return acme.Authorization{
						URL: requestURL, Status: "pending", Expires: &expires,
						Identifier: acme.Identifier{Type: "dns", Value: strings.TrimPrefix(identifiers[0], "*.")},
						Challenges: []acme.Challenge{{Type: "dns-01", URL: wildChallenge, Token: "wildcard-token"}},
					}, nil
				default:
					return acme.Authorization{}, fmt.Errorf("unexpected ACME authorization URL %q", requestURL)
				}
			}

			store := &authorizationRecordingStore{Database: database}
			dns := &authorizationDNSRecorder{}
			worker, err := NewServiceWorker(store, ServiceConfig{
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
				workerNow = store.saved[len(store.saved)-1].AvailableAt
			}
			last := store.saved[len(store.saved)-1]
			if last.ID != issuance.ID || last.State != "ready_to_finalize" || len(last.Authorizations) != 1 || api.newOrderCalls != 1 || api.acceptCalls != 1 {
				t.Fatalf("authorization result: %#v, orders %d, accepts %d", last, api.newOrderCalls, api.acceptCalls)
			}
			wildcard := last.Authorizations[0]
			if wildcard.Identifier != identifiers[0] || wildcard.State != "valid" || wildcard.ChallengeType != "dns-01" ||
				wildcard.PresentationReference == "" || api.acceptedChallenge != wildChallenge || dns.presented != wildcard.ID || dns.verified != wildcard.ID ||
				dns.cleaned != "" || dns.presentCalls != 1 || dns.verifyCalls != 1 || dns.cleanupCalls != 0 {
				t.Fatalf("service authorization = %#v; DNS calls %#v", last.Authorizations, dns)
			}
			discovered, failures := false, 0
			for _, saved := range store.saved {
				if len(saved.Authorizations) == 1 && saved.State == "authorizing" &&
					saved.Authorizations[0].State == "presenting" {
					discovered = true
				}
				if saved.LastError == "" {
					continue
				}
				failures++
				if !transient || saved.LastError != "server.certificate_failed" || strings.Contains(saved.LastError, transientFetchError) || saved.State != "authorizing" ||
					len(saved.Authorizations) != 0 || saved.OrderURL != orderURL {
					t.Fatalf("partial or terminal discovery persisted: state=%s error=%q authorizations=%d order=%q",
						saved.State, saved.LastError, len(saved.Authorizations), saved.OrderURL)
				}
			}
			if !discovered || failures != map[bool]int{false: 0, true: 1}[transient] ||
				wildcardFetches != map[bool]int{false: 1, true: 2}[transient] {
				t.Fatalf("discovery: found %v, failures %d, wildcard fetches %d", discovered, failures, wildcardFetches)
			}

			// claim from PostgreSQL again so challenge fields and revisions round-trip.
			restartNow := workerNow.Add(time.Second)
			work, found, err := database.ClaimACMEOrderWork(t.Context(), "authorization-restart", restartNow, time.Minute)
			if err != nil || !found || work.ID != last.ID || work.OrderRevision != last.OrderRevision || len(work.Authorizations) != 1 {
				t.Fatalf("restart claim: found %v, error %v, work %#v", found, err, work)
			}
			wildcard = work.Authorizations[0]
			if wildcard.ID != last.Authorizations[0].ID || wildcard.Revision == 0 || wildcard.Revision != last.Authorizations[0].Revision ||
				wildcard.ChallengeType != "dns-01" || wildcard.PresentationReference == "" || wildcard.PresentedAt == nil || wildcard.ValidatedAt == nil {
				t.Fatalf("authorization PostgreSQL round-trip: last %#v, claimed %#v", last.Authorizations, work.Authorizations)
			}
			for _, name := range []string{"duplicate", "token", "digest", "presentation"} {
				invalid := work
				invalid.Authorizations = slices.Clone(work.Authorizations)
				expected := controlstate.ErrACMEWorkStale
				switch name {
				case "duplicate":
					invalid.Authorizations = append(invalid.Authorizations, invalid.Authorizations[0])
					expected = controlstate.ErrCertificateIssuanceInvalid
				case "token":
					invalid.Authorizations[0].ChallengeToken = "fabricated"
				case "digest":
					invalid.Authorizations[0].ChallengeDigest = sha256.Sum256([]byte("fabricated"))
				case "presentation":
					invalid.Authorizations[0].PresentationReference = "fabricated"
				}
				if _, err := database.SaveACMEOrderWork(t.Context(), invalid, restartNow); !errors.Is(err, expected) {
					t.Fatalf("%s authorization save = %v", name, err)
				}
			}
			work.AvailableAt = restartNow.Add(time.Hour)
			if _, err := database.SaveACMEOrderWork(t.Context(), work, restartNow); err != nil {
				t.Fatalf("unchanged reused authorization save: %v", err)
			}
			current, err := database.GetServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token, work.ID, restartNow)
			if err != nil || current.CertificatePlan.ChallengeMethod != "dns-01" {
				t.Fatalf("service certificate plan = %#v, %v", current.CertificatePlan, err)
			}

			// an ACME authorization URL may also be reused by a later order for this account.
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifiers}, key)
			if err != nil {
				t.Fatal(err)
			}
			second, err := database.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token,
				account.DirectoryURL, "second-issuance", run.RunNumber, csr, restartNow)
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
				authorization := previous
				authorization.ID, authorization.Revision = "", 0
				authorization.State, authorization.ChallengeType = "complete", ""
				authorization.ChallengeURL, authorization.ChallengeToken, authorization.PresentationReference = "", "", ""
				authorization.ChallengeDigest = [32]byte{}
				authorization.PresentedAt = nil
				authorization.Attempts = 0
				authorization.CleanupCompletedAt = authorization.ValidatedAt
				reused.Authorizations = append(reused.Authorizations, authorization)
			}
			// reused authorizations have no live challenge material. validate
			// their complete state and lifetime independently of active challenges.
			for _, name := range []string{"token", "digest", "presentation", "not_complete", "expired"} {
				invalid := reused
				invalid.Authorizations = slices.Clone(reused.Authorizations)
				switch name {
				case "token":
					invalid.Authorizations[0].ChallengeToken = "fabricated"
				case "digest":
					invalid.Authorizations[0].ChallengeDigest = sha256.Sum256([]byte("fabricated"))
				case "presentation":
					invalid.Authorizations[0].PresentationReference = "fabricated"
				case "not_complete":
					invalid.Authorizations[0].State = "presenting"
				case "expired":
					invalid.Authorizations[0].ExpiresAt = invalid.Authorizations[0].ValidatedAt
				}
				if _, err := database.SaveACMEOrderWork(t.Context(), invalid, secondNow); !errors.Is(err, controlstate.ErrCertificateIssuanceInvalid) {
					t.Fatalf("%s reused authorization save = %v", name, err)
				}
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

func (d *authorizationDNSRecorder) PresentSubject(_ context.Context, _ controlstate.CertificateSubject, id string) error {
	d.presented = id
	d.presentCalls++
	return nil
}

func (d *authorizationDNSRecorder) VerifySubject(_ context.Context, _ controlstate.CertificateSubject, id string) (bool, error) {
	d.verified = id
	d.verifyCalls++
	return true, nil
}

func (d *authorizationDNSRecorder) CleanupSubject(_ context.Context, _ controlstate.CertificateSubject, id string) error {
	d.cleaned = id
	d.cleanupCalls++
	return nil
}
