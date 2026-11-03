package certificates

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/certificates/acme"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func TestCertificateCleanupRequiresIssuedPayloadBeforeDNS(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, field := range []string{"pem", "not_before", "not_after", "renew_at"} {
		t.Run(field, func(t *testing.T) {
			api, work := dnsSafetyOrder(t, "waiting_for_install", now)
			switch field {
			case "pem":
				work.CertificatePEM = nil
			case "not_before":
				work.NotBefore = nil
			case "not_after":
				work.NotAfter = nil
			case "renew_at":
				work.RenewAt = nil
			}
			dns := &dnsChallengesStub{}
			worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: dns}}
			if err := worker.advance(t.Context(), api, &work, now); err == nil || len(dns.cleanupCalls) != 0 || work.State != controlstate.ACMEOrderWaitingForInstall {
				t.Fatal("malformed issued public URL reached DNS cleanup", err)
			}
			relayDNS := &relayDNSChallengesStub{}
			relay := &RelayWorker{config: RelayConfig{DNSChallenges: relayDNS}}
			relayWork := controlstate.RelayCertificateOrderWork{State: controlstate.RelayCertificateCleaning, CertificatePEM: work.CertificatePEM, NotBefore: work.NotBefore, NotAfter: work.NotAfter, RenewAt: work.RenewAt}
			if err := relay.advance(t.Context(), api, &relayWork, now); err == nil || len(relayDNS.cleanupCalls) != 0 || relayWork.State != controlstate.RelayCertificateCleaning {
				t.Fatal("malformed issued relay reached DNS cleanup", err)
			}
		})
	}
}

func TestRelayWorkerRecoversDeadlineBeforeChallengeView(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	const authorizationURL = "https://acme.example/authz"
	api := &acmeStub{authorization: acme.Authorization{URL: authorizationURL, Identifier: acme.Identifier{Type: "dns", Value: "relay-a.example.test"}}}
	dns := &relayDNSChallengesStub{}
	worker := &RelayWorker{config: RelayConfig{DNSChallenges: dns}}
	work := controlstate.RelayCertificateOrderWork{
		ID: "order", State: controlstate.RelayCertificatePresenting, TLSServerName: "relay-a.example.test",
		AuthorizationURL: authorizationURL, ChallengeURL: "https://acme.example/challenge", ChallengeToken: "token", ChallengeDigest: [32]byte{1}, PresentationReference: "presentation",
	}
	if err := worker.advance(t.Context(), api, &work, now); err != nil || work.AuthorizationExpiresAt == nil || !work.AuthorizationExpiresAt.Equal(now.Add(5*time.Minute)) || len(dns.presentCalls) != 1 || work.State != controlstate.RelayCertificatePresented {
		t.Fatal("legacy challenge deadline was not recovered before presentation", err)
	}
}

func TestRetiredIssuanceKeepsUncertainFinalizationRecoverable(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, retired := range []controlstate.ACMEOrderState{controlstate.ACMEOrderFailed, controlstate.ACMEOrderCanceled} {
		for _, status := range []string{"pending", "ready", "processing", "unavailable"} {
			t.Run(string(retired)+"/"+status, func(t *testing.T) {
				api, work := dnsSafetyOrder(t, "finalizing", now)
				work.State, work.FinalizationPossible = retired, true
				work.CertificatePEM, work.NotBefore, work.NotAfter, work.RenewAt = nil, nil, nil, nil
				api.order.Status = status
				if status == "unavailable" {
					api.getOrderErr = &acme.Error{Status: 503}
				}
				dns := &dnsChallengesStub{}
				worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: dns, PollInterval: time.Second}}
				err := worker.advance(t.Context(), api, &work, now)
				if status == "unavailable" {
					if err == nil {
						t.Fatal("CA outage was ignored")
					}
					worker.applyFailure(&work, err, now)
				} else if err != nil {
					t.Fatal(err)
				}
				want := retired
				if status == "pending" {
					want = controlstate.ACMEOrderAuthorizing
				} else if status == "ready" {
					want = controlstate.ACMEOrderReadyToFinalize
				}
				if work.State != want || !work.FinalizationPossible || work.NotAfter != nil || len(dns.cleanupCalls) != 0 || len(api.finalizations) != 0 {
					t.Fatal("uncertain finalization was cleaned up or lost its recovery path")
				}
			})
		}
	}
}

func TestPublicURLWorkerChallengeMethodPayloadBoundary(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, method, reference string
		valid                   bool
	}{
		{"dns", "dns-01", "presentation", true},
		{"dns_without_reference", "dns-01", "", false},
		{"tls_alpn_without_reference", "tls-alpn-01", "", false},
		{"tls_alpn_with_reference", "tls-alpn-01", "presentation", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &acmeStub{}
			dns := &dnsChallengesStub{verified: true}
			worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: dns}}
			work := controlstate.ACMEOrderWork{Subject: testCertificateSubject("public-url")}
			authorization := controlstate.ACMEAuthorizationWork{
				ID: "authorization", Identifier: "app.example.test", State: controlstate.ACMEAuthorizationPresented,
				AuthorizationURL: "https://acme.example/authz", ChallengeURL: "https://acme.example/challenge",
				ChallengeType: certificateidentity.ChallengeMethod(test.method), ChallengeToken: "token", ChallengeDigest: [32]byte{1},
				PresentationReference: test.reference, ExpiresAt: timePointer(now.Add(time.Hour)),
			}
			err := worker.acceptAuthorizationWork(t.Context(), api, &work, &authorization, now)
			if test.valid {
				if err != nil || api.acceptCalls != 1 || len(dns.verifyCalls) != 1 || authorization.State != controlstate.ACMEAuthorizationValidating {
					t.Fatal("valid DNS challenge did not verify before acceptance", err)
				}
			} else if !isTerminal(err) || api.acceptCalls != 0 || len(dns.verifyCalls) != 0 || authorization.State != controlstate.ACMEAuthorizationPresented {
				t.Fatal("invalid challenge payload reached DNS or the CA", err)
			}
		})
	}
}

func TestPublicURLWorkerReusesAuthorizationWithOldTLSALPNChallenge(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	const hostname = "app.example.test"
	for _, status := range []string{"valid", "pending"} {
		t.Run(status, func(t *testing.T) {
			api := &acmeStub{
				order: acme.Order{URL: "https://acme.example/order", Finalize: "https://acme.example/finalize", Status: "pending",
					Identifiers: []acme.Identifier{{Type: "dns", Value: hostname}}, Authorizations: []string{"https://acme.example/authz"}},
				authorization: acme.Authorization{URL: "https://acme.example/authz", Status: status, Identifier: acme.Identifier{Type: "dns", Value: hostname},
					Expires: timePointer(now.Add(time.Hour)), Challenges: []acme.Challenge{{Type: "tls-alpn-01", URL: "https://acme.example/old-challenge", Token: "old-token"}}},
			}
			dns := &dnsChallengesStub{}
			worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: dns}}
			work := controlstate.ACMEOrderWork{Subject: testCertificateSubject("public-url"), State: controlstate.ACMEOrderAuthorizing,
				OrderURL: api.order.URL, ChallengeMethod: certificateidentity.ChallengeDNS01, CertificateIdentifiers: []string{hostname}}
			err := worker.advance(t.Context(), api, &work, now)
			if status == "valid" {
				if err != nil || work.State != controlstate.ACMEOrderReadyToFinalize || len(work.Authorizations) != 1 ||
					work.Authorizations[0].ChallengeType != "" || work.Authorizations[0].ChallengeURL != "" || work.Authorizations[0].PresentationReference != "" || work.Authorizations[0].State != controlstate.ACMEAuthorizationComplete {
					t.Fatal("reused authorization fabricated TLS-ALPN or DNS challenge work", err)
				}
			} else if !isTerminal(err) || len(work.Authorizations) != 0 {
				t.Fatal("pending TLS-ALPN challenge was accepted by DNS-only issuance", err)
			}
			if api.acceptCalls != 0 || len(dns.presentCalls) != 0 || len(dns.verifyCalls) != 0 || len(dns.cleanupCalls) != 0 {
				t.Fatal("old TLS-ALPN challenge reached the CA or DNS")
			}
		})
	}
}

func TestPublicURLWorkerDiscoversRequiredAuthorizationExpiry(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, orderExpires := range []*time.Time{nil, timePointer(now.Add(time.Hour))} {
		remote := acme.Authorization{URL: "https://acme.example/authz", Status: "pending", Identifier: acme.Identifier{Type: "dns", Value: "app.example.test"},
			Challenges: []acme.Challenge{{Type: "dns-01", URL: "https://acme.example/challenge", Token: "token"}}}
		work, err := authorizationWork(&acmeStub{}, remote, certificateidentity.ChallengeDNS01, orderExpires, now)
		if err != nil {
			t.Fatal(err)
		}
		// the store assigns this reference before the next worker claim.
		work.PresentationReference = "presentation"
		challenge, err := work.Challenge()
		want := now.Add(5 * time.Minute)
		if orderExpires != nil {
			want = *orderExpires
		}
		if err != nil || !challenge.ExpiresAt.Equal(want) {
			t.Fatal("discovery omitted the required authorization deadline", err)
		}
	}
}
