package state

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
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationHostedDNSChallengeContext(t *testing.T) {
	for _, kind := range []string{"managed", "custom"} {
		t.Run(kind, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			database, now := f.database, f.now
			var domain, reference string
			if err := database.pool.QueryRow(t.Context(), `SELECT canonical_domain, COALESCE(dns_authority_reference,'') FROM control.domains WHERE id=$1`, f.service.DomainID).Scan(&domain, &reference); err != nil {
				t.Fatal(err)
			}
			contextDomain := domain
			if kind == "custom" {
				contextDomain = domain
				var err error
				reference, err = opaqueid.New(opaqueid.DNSAuthorityPrefix)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256([]byte("authority"))
				if err := controlstatedb.New(database.pool).CreateCustomDNSAuthority(t.Context(), controlstatedb.CreateCustomDNSAuthorityParams{
					AuthorityReference: reference, TeamID: f.service.TeamID, DomainID: f.service.DomainID, CanonicalDomain: domain,
					CreateIdempotencyKey: "authority", CreateRequestDigest: digest[:], CreatedAt: timestamptz(now),
				}); err != nil {
					t.Fatal(err)
				}
				work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "dns-test", now, time.Minute)
				if err != nil || !found || work.Reference != reference {
					t.Fatalf("claim DNS authority = %v, found %v", err, found)
				}
				work.State, work.ProviderZoneID = "ready", "ZCLAIMED"
				work.Nameservers = []string{"ns-1.example.test", "ns-2.example.test"}
				work.AvailableAt = now
				work, err = database.SaveDNSAuthorityWork(t.Context(), work, now)
				if err != nil || work.State != "ready" {
					t.Fatalf("ready DNS authority = %q, %v", work.State, err)
				}
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.domains SET kind='custom',team_id=$2,dns_authority_reference=$3 WHERE id=$1`, f.service.DomainID, f.service.TeamID, reference); err != nil {
					t.Fatal(err)
				}
			}
			work := createPlanIssuanceWork(t, database, now, f.run, f.prepared.CertificatePlan, false, nil)
			for _, authorization := range work.Authorizations {
				t.Run(authorization.Identifier, func(t *testing.T) {
					challenge, err := database.GetDNSChallengeContextForSubject(t.Context(), work.Subject, authorization.ID)
					if err != nil {
						t.Fatalf("DNS challenge context for %s domain with reference %q: %v", kind, reference, err)
					}
					if challenge.CanonicalDomain != contextDomain || challenge.DNSAuthorityReference != reference ||
						challenge.TeamID != f.service.TeamID || challenge.Identifier != authorization.Identifier ||
						challenge.PresentationReference != authorization.PresentationReference || challenge.ChallengeDigest != authorization.ChallengeDigest ||
						len(challenge.Presentations) != len(work.Authorizations) {
						t.Fatalf("challenge context = %#v", challenge)
					}
					assertDNSChallengeSubjectBinding(t, database, work.Subject, challenge)
					for _, presentation := range challenge.Presentations {
						if !presentation.Active {
							t.Fatal("presenting authorization was not active")
						}
					}
				})
			}
			wrong := work.Subject
			wrong.ID = "another_route"
			if _, err := database.GetDNSChallengeContextForSubject(t.Context(), wrong, work.Authorizations[0].ID); !errors.Is(err, ErrDNSChallengeNotFound) {
				t.Fatalf("wrong-route challenge lookup = %v", err)
			}
		})
	}
}

func TestIntegrationCertificatePlanInstallGuards(t *testing.T) {
	for _, name := range []string{"same_plan_control", "cache_key", "scope", "identifiers", "not_after", "expired", "stale_session", "wrong_token", "wrong_version", "revoked"} {
		t.Run(name, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			database, now := f.database, f.now
			first, plan := f.run, f.prepared.CertificatePlan
			work := createPlanIssuanceWork(t, database, now, first, plan, true, nil)
			if err := database.MarkServiceCertificateInstalled(t.Context(), first.ServiceID, first.RunID, first.Token, work.ID, first.RunNumber, *work.NotAfter, now); err != nil {
				t.Fatalf("valid issuance precondition: %v", err)
			}
			if err := database.CloseServiceRun(t.Context(), first.ServiceID, first.RunID, first.Token, now); err != nil {
				t.Fatal(err)
			}
			f.start(t, "replacement", now)
			switch name {
			case "cache_key":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET certificate_cache_key='another-cache-key' WHERE id=$1`, work.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "scope":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET certificate_scope='another.example.test' WHERE id=$1`, work.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "identifiers":
				_, err := database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET certificate_identifiers=ARRAY['another.example.test'] WHERE id=$1`, work.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			authentication := f.run
			notAfter, installedAt := *work.NotAfter, now
			wantErr := ErrCertificateIssuanceInvalid
			if name == "not_after" {
				notAfter = notAfter.Add(time.Second)
			}
			if name == "expired" {
				installedAt = notAfter
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, authentication.RunID, notAfter.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			if name == "stale_session" {
				authentication, wantErr = first, ErrServiceAccess
			}
			if name == "wrong_token" {
				token, _, err := credentials.NewServiceRunToken()
				if err != nil {
					t.Fatal(err)
				}
				authentication.Token, wantErr = token.String(), ErrServiceAccess
			}
			if name == "wrong_version" {
				authentication.RunNumber++
				wantErr = ErrServiceAccess
			}
			if name == "revoked" {
				if err := database.CloseServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now); err != nil {
					t.Fatal(err)
				}
				wantErr = ErrServiceAccess
			}
			err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, work.ID, authentication.RunNumber, notAfter, installedAt)
			if name == "same_plan_control" {
				if err != nil {
					t.Fatalf("same-service same-plan renewal: %v", err)
				}
				state, err := database.HeartbeatServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				if err != nil || state.State != "starting" {
					t.Fatal("certificate bypassed connection readiness", state, err)
				}
				f.readyConnections(t, now)
				state, err = database.HeartbeatServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				if err != nil || state.State != "ready" {
					t.Fatal("certificate and ready connections did not enable serving", state, err)
				}
			} else if !errors.Is(err, wantErr) {
				t.Fatalf("%s mismatch acknowledgement = %v; want %v", name, err, wantErr)
			}
		})
	}
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

type planIssuanceOptions struct {
	publisherSource netip.Addr
	lifetime        time.Duration
}

func createPlanIssuanceWork(t *testing.T, database *Database, now time.Time, run ServiceRunState, plan CertificatePlan, complete bool, edit func(*ACMEOrderWork), options ...planIssuanceOptions) ACMEOrderWork {
	t.Helper()
	if len(options) > 1 {
		t.Fatal("select at most one certificate fixture option")
	}
	option := planIssuanceOptions{lifetime: 24 * time.Hour}
	if len(options) == 1 {
		option = options[0]
	}
	if option.lifetime <= 0 {
		t.Fatal("certificate fixture lifetime must be positive")
	}
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
	issuance, err := database.CreateServiceCertificateIssuance(WithPublisherRequestSource(t.Context(), option.publisherSource), run.ServiceID, run.RunID, run.Token, account.DirectoryURL, fmt.Sprintf("issuance-%x", sha256.Sum256(csr)), run.RunNumber, csr, now)
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
			Identifier: identifier, AuthorizationURL: fmt.Sprintf("https://acme.example.test/authz/%s/%d", work.ID, index),
			ChallengeType: plan.ChallengeMethod, ChallengeURL: fmt.Sprintf("https://acme.example.test/challenge/%s/%d", work.ID, index),
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
			KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(max(48*time.Hour, option.lifetime+24*time.Hour))}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		ca, err = x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: plan.Identifiers,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(option.lifetime),
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
		renew := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
		work.NotBefore, work.NotAfter, work.RenewAt = &leaf.NotBefore, &leaf.NotAfter, &renew
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

func installPrivateTestCertificate(t *testing.T, d *Database, prep ServiceRunPreparation, run ServiceRunState, now time.Time, lifetime ...time.Duration) {
	t.Helper()
	if len(lifetime) > 1 {
		t.Fatal("select at most one certificate fixture lifetime")
	}
	option := planIssuanceOptions{lifetime: 24 * time.Hour}
	if len(lifetime) == 1 {
		option.lifetime = lifetime[0]
	}
	work := createPlanIssuanceWork(t, d, now, run, prep.CertificatePlan, true, nil, option)
	if err := d.MarkServiceCertificateInstalled(t.Context(), run.ServiceID, run.RunID, run.Token, work.ID, run.RunNumber, *work.NotAfter, now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationCertificateInstallMaterial(t *testing.T) {
	for _, name := range []string{"valid", "valid_blank_lines", "malformed_pem", "leading_garbage", "malformed_der", "wrong_key", "uncovered_hostname", "extra_identity", "wrong_eku", "actual_not_after", "failed", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			database, now, authentication, plan := f.database, f.now, f.run, f.prepared.CertificatePlan
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
				case "wrong_key", "uncovered_hostname", "extra_identity", "wrong_eku":
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
					case "uncovered_hostname":
						leaf.DNSNames = []string{"another.example.test"}
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
			err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, work.ID, authentication.RunNumber, *work.NotAfter, now)
			if name == "valid" || name == "valid_blank_lines" {
				if err != nil {
					t.Fatalf("valid certificate acknowledgement: %v", err)
				}
			} else if !errors.Is(err, ErrCertificateIssuanceInvalid) {
				t.Fatalf("%s certificate acknowledgement = %v; want ErrCertificateIssuanceInvalid", name, err)
			}
		})
	}
}
