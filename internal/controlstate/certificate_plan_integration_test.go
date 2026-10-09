package controlstate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestIntegrationHostedDNSChallengeContext(t *testing.T) {
	for _, kind := range []string{"managed", "custom", "builtin_control"} {
		t.Run(kind, func(t *testing.T) {
			database, now := newCertificatePlanDatabase(t)
			const domain = "routes.example.test"
			reference := "dns_authority_0123456789abcdef0123456789abcdef"
			// Managed-zone identity comes from daemon configuration, not builtin domain rows.
			contextDomain := ""
			if kind == "custom" {
				contextDomain = domain
				authority, err := database.CreateDNSAuthority(t.Context(), CreateDNSAuthorityRequest{
					TeamID: "team_external", DomainID: "domain_external", CanonicalDomain: domain,
					IdempotencyKey: "authority", RequestDigest: sha256.Sum256([]byte("authority")),
				}, now)
				if err != nil {
					t.Fatal(err)
				}
				work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "dns-test", now, time.Minute)
				if err != nil || !found || work.Reference != authority.Reference {
					t.Fatalf("claim DNS authority = %v, found %v", err, found)
				}
				work.State, work.ProviderZoneID = "ready", "ZCLAIMED"
				work.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
				work.AvailableAt = now
				work, err = database.SaveDNSAuthorityWork(t.Context(), work, now)
				if err != nil || work.State != "ready" {
					t.Fatalf("ready DNS authority = %q, %v", work.State, err)
				}
				reference = authority.Reference
			}
			plan := CertificatePlan{CacheKey: "member." + domain, Scope: "member." + domain,
				Identifiers: []string{"member." + domain, "*.member." + domain}, ChallengeMethod: "dns-01"}
			var route PublicURL
			var authentication PublishRunAuthentication
			if kind == "builtin_control" {
				local, err := database.CreateBuiltinControlSession(t.Context(), domain, 1, time.Hour, 24*time.Hour, now)
				if err != nil {
					t.Fatal(err)
				}
				membership := local.Identity.Memberships[0]
				domains, err := database.ListTeamDomains(t.Context(), local.Identity.Identity.ID, membership.TeamID)
				if err != nil || len(domains) != 1 {
					t.Fatalf("builtin domains = %#v, %v", domains, err)
				}
				reference = domains[0].DNSAuthorityReference
				namespace := membership.ManagedLabel + "." + domain
				plan.CacheKey, plan.Scope, plan.Identifiers = namespace, namespace, []string{namespace, "*." + namespace}
				slices.Sort(plan.Identifiers)
				route, err = database.CreatePublicURL(t.Context(), CreatePublicURLRequest{
					TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
					ActingIdentityID: local.Identity.Identity.ID, IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")),
					CanonicalHostname: "api." + namespace, Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
					DNSState: PublicURLDNSPending, DNSAuthorityReference: reference,
				}, now)
				if err != nil {
					t.Fatal(err)
				}
				principal, err := database.AuthenticateAccessToken(t.Context(), local.AccessToken, 1, now)
				if err != nil {
					t.Fatal(err)
				}
				setup, err := database.CreatePublishRun(t.Context(), PublishRunRequest{
					PublicURLID: route.ID, TeamID: route.TeamID, MembershipID: membership.ID, ActingIdentityID: principal.IdentityID,
					RetrySecret: principal.RetrySecret[:], PolicyRevision: uint64(membership.PolicyRevision),
					IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")), ExpectedMutationRevision: route.MutationRevision,
					CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod,
				}, now, time.Hour, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				authentication = PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
			} else {
				route, authentication = newExternalPlanSession(t, database, now, "team_external", "api.member."+domain, reference, plan)
			}
			work := createPlanIssuanceWork(t, database, now, authentication, plan, false, nil)
			for _, authorization := range work.Authorizations {
				t.Run(authorization.Identifier, func(t *testing.T) {
					challenge, err := database.GetDNSChallengeContext(t.Context(), route.ID, authorization.ID)
					if err != nil {
						t.Fatalf("DNS challenge context for %s domain with reference %q: %v", kind, reference, err)
					}
					if challenge.CanonicalDomain != contextDomain || challenge.DNSAuthorityReference != reference ||
						challenge.TeamID != route.TeamID || challenge.Identifier != authorization.Identifier ||
						challenge.PresentationReference != authorization.PresentationReference || challenge.ChallengeDigest != authorization.ChallengeDigest ||
						len(challenge.Presentations) != 2 {
						t.Fatalf("challenge context = %#v", challenge)
					}
					for _, presentation := range challenge.Presentations {
						if !presentation.Active {
							t.Fatal("presenting authorization was not active")
						}
					}
				})
			}
			if _, err := database.GetDNSChallengeContext(t.Context(), "another_route", work.Authorizations[0].ID); !errors.Is(err, ErrDNSChallengeNotFound) {
				t.Fatalf("wrong-route challenge lookup = %v", err)
			}
		})
	}
}

func TestIntegrationCertificatePlanReuseAcrossPublicURLs(t *testing.T) {
	for _, test := range []struct {
		name, team, hostname string
		wantError            bool
	}{
		{"same_team_same_plan", "team_external", "second.member.routes.example.test", false},
		{"different_team_rejected", "team_other", "second.member.routes.example.test", true},
		{"uncovered_hostname_rejected", "team_external", "deep.second.member.routes.example.test", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, now := newCertificatePlanDatabase(t)
			plan := CertificatePlan{CacheKey: "member.routes.example.test", Scope: "member.routes.example.test",
				Identifiers: []string{"member.routes.example.test", "*.member.routes.example.test"}, ChallengeMethod: "dns-01"}
			_, first := newExternalPlanSession(t, database, now, "team_external", "first.member.routes.example.test", "managed:routes.example.test", plan)
			work := createPlanIssuanceWork(t, database, now, first, plan, true, nil)
			if _, err := database.MarkPublicURLCertificateInstalled(t.Context(), first, work.ID, *work.NotAfter, now); err != nil {
				t.Fatalf("originating-route install control: %v", err)
			}
			if err := database.ClosePublishRun(t.Context(), first.PublishRunID, first.PublishRunToken, now); err != nil {
				t.Fatal(err)
			}
			_, second := newExternalPlanSession(t, database, now, test.team, test.hostname, "managed:routes.example.test", plan)
			lifecycle, err := database.MarkPublicURLCertificateInstalled(t.Context(), second, work.ID, *work.NotAfter, now)
			if test.wantError {
				if !errors.Is(err, ErrPublicURLCertificate) {
					t.Fatalf("certificate acknowledgement = %v; want ErrPublicURLCertificate", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("same-team same-plan certificate acknowledgement for second public_url: %v", err)
			}
			if lifecycle.CertificateAt == nil || lifecycle.Routable {
				t.Fatalf("certificate acknowledgement must not bypass connection readiness: %#v", lifecycle)
			}
		})
	}
}

func TestIntegrationCertificatePlanInstallGuards(t *testing.T) {
	for _, name := range []string{"same_plan_control", "cache_key", "scope", "identifiers", "method", "not_after", "expired", "stale_session", "wrong_token", "wrong_version", "revoked"} {
		t.Run(name, func(t *testing.T) {
			database, now := newCertificatePlanDatabase(t)
			const hostname = "api.member.routes.example.test"
			plan := CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "dns-01"}
			route, first := newExternalPlanSession(t, database, now, "team_external", hostname, "managed:routes.example.test", plan)
			work := createPlanIssuanceWork(t, database, now, first, plan, true, nil)
			if _, err := database.MarkPublicURLCertificateInstalled(t.Context(), first, work.ID, *work.NotAfter, now); err != nil {
				t.Fatalf("valid issuance precondition: %v", err)
			}
			if err := database.ClosePublishRun(t.Context(), first.PublishRunID, first.PublishRunToken, now); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "cache_key":
				plan.CacheKey = "another-cache-key"
			case "scope":
				plan.Scope = "member.routes.example.test"
			case "identifiers":
				plan.Identifiers = append(plan.Identifiers, "member.routes.example.test")
			case "method":
				plan.ChallengeMethod = "tls-alpn-01"
			}
			// start a new publish run on the same public URL so a public URL identity
			// mismatch cannot mask the certificate plan checks.
			authentication := startExternalPlanSession(t, database, now, route, plan, "replacement")
			notAfter, installedAt := *work.NotAfter, now
			wantErr := ErrPublicURLCertificate
			if name == "not_after" {
				notAfter = notAfter.Add(time.Second)
			}
			if name == "expired" {
				installedAt = notAfter
			}
			if name == "stale_session" {
				authentication, wantErr = first, ErrPublishRunStale
			}
			if name == "wrong_token" {
				token, _, _, err := credentials.NewPublishRunToken()
				if err != nil {
					t.Fatal(err)
				}
				authentication.PublishRunToken, wantErr = token, ErrPublishRunCredential
			}
			if name == "wrong_version" {
				authentication.PublishRunNumber++
				wantErr = ErrPublishRunStale
			}
			if name == "revoked" {
				if err := database.ClosePublishRun(t.Context(), authentication.PublishRunID, authentication.PublishRunToken, now); err != nil {
					t.Fatal(err)
				}
				wantErr = ErrPublishRunStale
			}
			lifecycle, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, work.ID, notAfter, installedAt)
			if name == "same_plan_control" {
				if err != nil || lifecycle.CertificateAt == nil {
					t.Fatalf("same-route same-plan renewal = %#v, %v", lifecycle, err)
				}
			} else if !errors.Is(err, wantErr) {
				t.Fatalf("%s mismatch acknowledgement = %v; want %v", name, err, wantErr)
			}
		})
	}
}

func newCertificatePlanDatabase(t *testing.T) (*Database, time.Time) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "certificate_plan")
	registerCertificatePlanRelays(t, database, now)
	return database, now
}

func registerCertificatePlanRelays(t *testing.T, database *Database, now time.Time) {
	t.Helper()
	for index := range 2 {
		name := fmt.Sprintf("plan-relay-%d", index)
		if _, err := database.RegisterRelay(t.Context(), RelayRegistration{
			RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: 1,
			RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test",
			InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 100, StreamCapacity: 100,
		}, now, 48*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
}

func newExternalPlanSession(t *testing.T, database *Database, now time.Time, team, hostname, reference string, plan CertificatePlan) (PublicURL, PublishRunAuthentication) {
	t.Helper()
	suffix := strings.TrimPrefix(team, "team_")
	identity := "identity_" + suffix
	var exists bool
	if err := database.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.identities WHERE id=$1)`, identity).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		seedControlPublicURL(t, database, now, suffix)
		if _, err := database.pool.Exec(t.Context(), `DELETE FROM control.public_urls WHERE id=$1`, "public_url_"+suffix); err != nil {
			t.Fatal(err)
		}
	}
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := database.sealSecret(publicURLRequestDigestContext(id), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.pool.Exec(t.Context(), `INSERT INTO control.public_urls(id,team_id,domain_id,membership_id,created_by_identity_id,idempotency_key,request_digest_ciphertext,request_digest_storage_key_id,canonical_hostname,target,public_url_scope,purpose,policy_revision,ip_policy,lifecycle_state,dns_state,dns_authority_reference,created_at,updated_at,dns_available_at)
	 VALUES($1,$2,$3,$4,$5,$1,$6,$7,$8,'http://127.0.0.1:3000','member','app',1,'allow_all','enabled','pending',$9,$10,$10,$10)`, id, team, "domain_"+suffix, "membership_"+suffix, identity, digest, database.storageKey.CurrentID(), hostname, reference, now)
	if err != nil {
		t.Fatal(err)
	}
	route, err := database.GetPublicURLForAuthorization(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return route, startExternalPlanSession(t, database, now, route, plan, "session")
}

func startExternalPlanSession(t *testing.T, database *Database, now time.Time, route PublicURL, plan CertificatePlan, key string) PublishRunAuthentication {
	t.Helper()
	plan.Identifiers = slices.Clone(plan.Identifiers)
	slices.Sort(plan.Identifiers)
	current, err := database.GetPublicURLForAuthorization(t.Context(), route.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret := sha256.Sum256([]byte("plan-retry"))
	setup, err := database.CreatePublishRun(t.Context(), PublishRunRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, MembershipID: route.MembershipID, ActingIdentityID: "identity_" + strings.TrimPrefix(route.TeamID, "team_"),
		RetrySecret: secret[:], IdempotencyKey: key, RequestDigest: sha256.Sum256([]byte(key)), PolicyRevision: 1,
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope, CertificateIdentifiers: slices.Clone(plan.Identifiers),
		CertificateChallenge: plan.ChallengeMethod, ExpectedMutationRevision: current.MutationRevision,
	}, now, 48*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
}

func createPlanIssuanceWork(t *testing.T, database *Database, now time.Time, authentication PublishRunAuthentication, plan CertificatePlan, complete bool, edit func(*ACMEOrderWork)) ACMEOrderWork {
	t.Helper()
	plan.Identifiers = slices.Clone(plan.Identifiers)
	slices.Sort(plan.Identifiers)
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1", "", now); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: plan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := database.CreateCertificateIssuance(t.Context(), CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: account.DirectoryURL, IdempotencyKey: "issuance",
		RequestDigest: sha256.Sum256(csr), CSRDER: csr,
	}, now)
	if err != nil {
		t.Fatalf("full-plan CSR precondition: %v", err)
	}
	work, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-plan-test", now, time.Minute)
	if err != nil || !found || work.ID != issuance.ID {
		t.Fatalf("claim issuance work = %v, found %v", err, found)
	}
	work.State, work.AvailableAt = "authorizing", now
	expiresAt := now.Add(time.Hour)
	for index, identifier := range plan.Identifiers {
		work.Authorizations = append(work.Authorizations, ACMEAuthorizationWork{
			Identifier: identifier, AuthorizationURL: fmt.Sprintf("https://acme.example.test/authz/%d", index),
			ChallengeType: plan.ChallengeMethod, ChallengeURL: fmt.Sprintf("https://acme.example.test/challenge/%d", index),
			ChallengeToken: fmt.Sprintf("token-%d", index), ChallengeDigest: sha256.Sum256([]byte(identifier)),
			State: "presenting", AvailableAt: now, ExpiresAt: &expiresAt,
		})
	}
	if complete {
		// the fixture replaces only the CA exchange: real CSR/key, signed leaf, matching SANs,
		// completed authorizations, and persisted work all precede acknowledgement.
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		ca, err = x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: plan.Identifiers,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			t.Fatal(err)
		}
		work.State = "waiting_for_install"
		work.CertificatePEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
		work.NotBefore, work.NotAfter = &leaf.NotBefore, &leaf.NotAfter
		work.OrderURL, work.FinalizeURL, work.CertificateURL = "https://acme.example.test/order/1", "https://acme.example.test/finalize/1", "https://acme.example.test/certificate/1"
		for index := range work.Authorizations {
			work.Authorizations[index].State = "complete"
			work.Authorizations[index].PresentedAt, work.Authorizations[index].ValidatedAt, work.Authorizations[index].CleanupCompletedAt = &now, &now, &now
		}
	}
	if edit != nil {
		edit(&work)
	}
	work, err = database.SaveACMEOrderWork(t.Context(), work, now)
	if err != nil {
		t.Fatalf("save valid certificate work: %v", err)
	}
	return work
}

func TestIntegrationCertificateInstallMaterial(t *testing.T) {
	for _, name := range []string{"valid", "valid_blank_lines", "malformed_pem", "leading_garbage", "malformed_der", "wrong_key", "extra_identity", "wrong_eku", "actual_not_after", "failed", "canceled"} {
		t.Run(name, func(t *testing.T) {
			database, now := newCertificatePlanDatabase(t)
			const hostname = "api.member.routes.example.test"
			plan := CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "dns-01"}
			_, authentication := newExternalPlanSession(t, database, now, "team_external", hostname, "managed:routes.example.test", plan)
			work := createPlanIssuanceWork(t, database, now, authentication, plan, true, func(work *ACMEOrderWork) {
				switch name {
				case "valid_blank_lines":
					leaf, rest := decodeTestPEM(t, work.CertificatePEM, "CERTIFICATE")
					work.CertificatePEM = append([]byte(" \r\n\t"), pem.EncodeToMemory(leaf)...)
					work.CertificatePEM = append(work.CertificatePEM, '\n')
					work.CertificatePEM = append(work.CertificatePEM, rest...)
					work.CertificatePEM = append(work.CertificatePEM, '\n', ' ', '\t')
				case "malformed_pem":
					work.CertificatePEM = []byte("not a certificate")
				case "leading_garbage":
					work.CertificatePEM = append([]byte("garbage\n"), work.CertificatePEM...)
				case "malformed_der":
					work.CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})
				case "actual_not_after":
					changed := work.NotAfter.Add(time.Hour)
					work.NotAfter = &changed
				case "failed", "canceled":
					work.State = ACMEOrderState(name)
				case "wrong_key", "extra_identity", "wrong_eku":
					leafBlock, rest := decodeTestPEM(t, work.CertificatePEM, "CERTIFICATE")
					caBlock, _ := decodeTestPEM(t, rest, "CERTIFICATE")
					leaf, err := x509.ParseCertificate(leafBlock.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					ca, err := x509.ParseCertificate(caBlock.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "wrong_key":
						leaf.PublicKey = &key.PublicKey
					case "extra_identity":
						leaf.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
					case "wrong_eku":
						leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
					}
					// Re-sign with a test CA while preserving the CSR key unless that is the tested mismatch.
					ca.PublicKey = &key.PublicKey
					caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
					if err != nil {
						t.Fatal(err)
					}
					ca, err = x509.ParseCertificate(caDER)
					if err != nil {
						t.Fatal(err)
					}
					der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
					if err != nil {
						t.Fatal(err)
					}
					work.CertificatePEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
				}
			})
			_, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now)
			if name == "valid" || name == "valid_blank_lines" {
				if err != nil {
					t.Fatalf("valid certificate acknowledgement: %v", err)
				}
			} else if !errors.Is(err, ErrPublicURLCertificate) {
				t.Fatalf("%s certificate acknowledgement = %v; want ErrPublicURLCertificate", name, err)
			}
		})
	}
}
