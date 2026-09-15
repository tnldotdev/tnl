package publisher

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/acme"
)

const certificateTestRouteID = "route_0123456789abcdef0123456789abcdef"

func TestCertificateIssuanceNamespaceCoverage(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	issuance := controlv1.CertificateIssuance{
		Id: "issuance_1", RouteId: control.setup.Route.Id, RouteSessionId: control.setup.RouteSession.Id,
		RouteVersion: 1, CertificatePlan: control.setup.CertificatePlan, State: controlv1.CertificateIssuanceStatePending,
	}
	for _, test := range []struct {
		hostname string
		valid    bool
	}{
		{"member.example", true},
		{"app.member.example", true},
		{"deep.app.member.example", false},
		{"other.example", false},
	} {
		t.Run(test.hostname, func(t *testing.T) {
			err := validateCertificateIssuance(issuance, issuance.RouteSessionId, issuance.RouteId, 1, test.hostname, issuance.Id, control.setup.CertificatePlan)
			if (err == nil) != test.valid {
				t.Fatalf("namespace issuance for %s: %v; want accepted = %t", test.hostname, err, test.valid)
			}
		})
	}
}

func TestCertificateIssuanceRejectsInconsistentIdentityAndState(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	for _, test := range []struct {
		name   string
		change func(*controlv1.CertificateIssuance)
	}{
		{"session", func(i *controlv1.CertificateIssuance) { i.RouteSessionId = "session_other" }},
		{"route", func(i *controlv1.CertificateIssuance) { i.RouteId = "route_other" }},
		{"version", func(i *controlv1.CertificateIssuance) { i.RouteVersion++ }},
		{"issuance", func(i *controlv1.CertificateIssuance) { i.Id = "issuance_other" }},
		{"empty_issuance", func(i *controlv1.CertificateIssuance) { i.Id = "" }},
		{"plan_key", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.CacheKey = "another-key" }},
		{"plan_scope", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.Scope = "another-scope" }},
		{"plan_identifiers", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.Identifiers = []string{"member.example"} }},
		{"plan_method", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.ChallengeMethod = controlv1.TlsAlpn01 }},
		{"unknown_state", func(i *controlv1.CertificateIssuance) { i.State = "unknown" }},
		{"installed_without_material", func(i *controlv1.CertificateIssuance) { i.State = controlv1.CertificateIssuanceStateInstalled }},
		{"pending_with_material", func(i *controlv1.CertificateIssuance) { i.CertificatePem = pointer("invalid") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			i := controlv1.CertificateIssuance{
				Id: "issuance_1", RouteId: control.setup.Route.Id, RouteSessionId: control.setup.RouteSession.Id,
				RouteVersion: 1, CertificatePlan: control.setup.CertificatePlan, State: controlv1.CertificateIssuanceStatePending,
			}
			test.change(&i)
			if err := validateCertificateIssuance(i, control.setup.RouteSession.Id, control.setup.Route.Id, 1, "member.example", "issuance_1", control.setup.CertificatePlan); err == nil {
				t.Fatal("inconsistent issuance was accepted")
			}
		})
	}
}

func TestCertificateTransactionRecoversResponseLoss(t *testing.T) {
	for _, phase := range []string{"create", "challenge_ready", "challenge_removed", "installed"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", phase, committed), func(t *testing.T) {
				control, route, state := newCertificateTransactionTest(t)
				var issued controlv1.CertificateIssuance
				var firstCSR []byte
				var firstKey string
				lost, finalized, installed := false, false, false
				control.create = func(csr []byte, key string) (controlv1.CertificateIssuance, error) {
					if firstCSR == nil {
						firstCSR, firstKey = bytes.Clone(csr), key
					} else if !bytes.Equal(csr, firstCSR) || key != firstKey {
						t.Error("retry changed the CSR or idempotency key")
					}
					if phase == "create" && !lost && !committed {
						lost = true
						return controlv1.CertificateIssuance{}, controlclient.ErrUnavailable
					}
					if issued.Id == "" {
						var err error
						issued, err = control.issue(csr)
						if err != nil {
							return issued, err
						}
						issued.Challenges = pointer([]controlv1.CertificateChallenge{certificateTestChallenge()})
					}
					if phase == "create" && !lost {
						lost = true
						return controlv1.CertificateIssuance{}, controlclient.ErrUnavailable
					}
					if finalized {
						return issued, nil
					}
					pending := issued
					pending.State, pending.CertificatePem, pending.NotBefore, pending.NotAfter = controlv1.CertificateIssuanceStateAuthorizing, nil, nil, nil
					return pending, nil
				}
				control.challengeReady = func() (controlv1.CertificateIssuance, error) {
					if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example", SupportedProtos: []string{acme.ALPNProto}}); err != nil {
						t.Errorf("challenge-ready preceded local challenge installation: %v", err)
					}
					if phase == "challenge_ready" && !lost {
						lost, finalized = true, committed
						return controlv1.CertificateIssuance{}, controlclient.ErrUnavailable
					}
					finalized = true
					return issued, nil
				}
				control.removed = func() error {
					if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example", SupportedProtos: []string{acme.ALPNProto}}); err == nil {
						t.Error("challenge removal acknowledged while still served locally")
					}
					if phase == "challenge_removed" && !lost {
						lost = true
						if committed {
							issued.Challenges = nil
						}
						return controlclient.ErrUnavailable
					}
					issued.Challenges = nil
					return nil
				}
				control.installed = func(string, uint64, string, time.Time) error {
					_, found, err := state.Staged(t.Context(), "route.example")
					if err != nil || !found {
						t.Errorf("state before installation acknowledgement: found=%t error=%v", found, err)
					}
					if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"}); err == nil {
						t.Error("unacknowledged certificate was available to visitors")
					}
					if phase == "installed" && !lost {
						lost, installed = true, committed
						if installed {
							issued.State = controlv1.CertificateIssuanceStateInstalled
						}
						return controlclient.ErrUnavailable
					}
					installed = true
					return nil
				}
				if _, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false); !errors.Is(err, controlclient.ErrUnavailable) {
					t.Fatalf("injected response loss = %v", err)
				}
				if !lost {
					t.Fatal("response-loss boundary was not reached")
				}
				// Reopen the cache and route to include recovery of locally committed, unacknowledged material.
				var err error
				state, err = control.store.Certificates(control.setup.Route.TeamId, control.setup.CertificatePlan)
				if err != nil {
					t.Fatal(err)
				}
				_ = route.Close()
				route = certificateTestRoute(t, "route.example", control.setup.CertificatePlan)
				material, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
				if err != nil || material.IssuanceID == "" || !installed {
					t.Fatalf("response-loss recovery: server_installed=%t error=%v", installed, err)
				}
			})
		}
	}
}

func TestCertificateTransactionPendingPollingIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control, route, state := newCertificateTransactionTest(t)
		var firstCSR []byte
		var firstKey string
		calls := 0
		control.create = func(csr []byte, key string) (controlv1.CertificateIssuance, error) {
			calls++
			if calls == 1 {
				firstCSR, firstKey = bytes.Clone(csr), key
			} else if !bytes.Equal(csr, firstCSR) || key != firstKey {
				t.Error("pending polling changed the certificate attempt")
			}
			i, err := control.issue(csr)
			i.State, i.CertificatePem, i.NotBefore, i.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
			i.RetryAt = pointer(time.Now().Add(3 * time.Second))
			return i, err
		}
		ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
		defer cancel()
		_, err := issueInitialCertificate(ctx, control, route, state, control.setup)
		if !errors.Is(err, context.DeadlineExceeded) || calls != 3 {
			t.Fatalf("pending polling: calls=%d error=%v; want 3 calls then deadline", calls, err)
		}
		if _, found, err := state.Current(t.Context(), "route.example"); err != nil || found {
			t.Fatalf("pending issuance committed material: found=%t error=%v", found, err)
		}
	})
}

func TestCertificateTransactionRejectsInvalidMaterialBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.CertificateIssuance, *x509.Certificate)
	}{
		{"extra_SAN", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.DNSNames = append(leaf.DNSNames, "other.example")
		}},
		{"CA", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.IsCA, leaf.BasicConstraintsValid = true, true
		}},
		{"wrong_EKU", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}},
		{"expired", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.NotAfter = time.Now().Add(-time.Second)
		}},
		{"future", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.NotBefore = time.Now().Add(time.Hour)
		}},
		{"invalid_PEM", func(i *controlv1.CertificateIssuance, _ *x509.Certificate) {
			i.CertificatePem = pointer("not a certificate")
		}},
		{"key_mismatch", func(i *controlv1.CertificateIssuance, _ *x509.Certificate) {
			certificate := routeTestCertificate(t, "route.example")
			i.CertificatePem = pointer(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})))
		}},
		{"validity_metadata", func(i *controlv1.CertificateIssuance, _ *x509.Certificate) {
			i.NotBefore = pointer(i.NotBefore.Add(time.Second))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			control, route, state := newCertificateTransactionTest(t)
			control.change = test.change
			acks := 0
			control.installed = func(string, uint64, string, time.Time) error { acks++; return nil }
			if _, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false); err == nil {
				t.Error("invalid certificate material was accepted")
			}
			if _, found, err := state.Current(t.Context(), "route.example"); err != nil || found {
				t.Errorf("invalid issuance changed durable current material: found=%t error=%v", found, err)
			}
			if acks != 0 {
				t.Errorf("invalid issuance installation acknowledgements = %d", acks)
			}
			if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"}); err == nil {
				t.Error("invalid issuance became available to visitors")
			}
		})
	}
}

func TestCertificateTransactionTerminalCleanupAfterLostReadyResponse(t *testing.T) {
	for _, terminal := range []controlv1.CertificateIssuanceState{controlv1.CertificateIssuanceStateFailed, controlv1.CertificateIssuanceStateCanceled} {
		t.Run(string(terminal), func(t *testing.T) {
			control, route, state := newCertificateTransactionTest(t)
			var issuance controlv1.CertificateIssuance
			var csr []byte
			control.create = func(request []byte, _ string) (controlv1.CertificateIssuance, error) {
				if issuance.Id == "" {
					csr = bytes.Clone(request)
					var err error
					issuance, err = control.issue(request)
					if err != nil {
						return issuance, err
					}
					issuance.State, issuance.CertificatePem, issuance.NotBefore, issuance.NotAfter = controlv1.CertificateIssuanceStateAuthorizing, nil, nil, nil
					issuance.Challenges = pointer([]controlv1.CertificateChallenge{certificateTestChallenge()})
				}
				return issuance, nil
			}
			control.challengeReady = func() (controlv1.CertificateIssuance, error) {
				issuance.State, issuance.Challenges = terminal, nil
				return controlv1.CertificateIssuance{}, controlclient.ErrUnavailable
			}
			removals := 0
			control.removed = func() error { removals++; return nil }
			_, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
			if !errors.Is(err, controlclient.ErrUnavailable) {
				t.Fatalf("lost ready response = %v", err)
			}
			_, err = attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
			var terminalError *terminalCertificateIssuanceError
			if !errors.As(err, &terminalError) {
				t.Fatalf("terminal response = %v", err)
			}
			if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example", SupportedProtos: []string{acme.ALPNProto}}); err == nil {
				t.Error("terminal issuance left its TLS-ALPN challenge available after a lost ready response")
			}
			if removals != 1 {
				t.Errorf("terminal challenge removal acknowledgements = %d, want 1", removals)
			}
			pending, err := state.Pending(t.Context(), "route.example")
			if err != nil || bytes.Equal(pending.CSRDER, csr) {
				t.Fatalf("terminal attempt did not rotate the CSR: %v", err)
			}
		})
	}
}

func TestInitialCertificateTerminalFailureIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control, route, state := newCertificateTransactionTest(t)
		calls := 0
		var previousCSR []byte
		var previousKey string
		control.create = func(csr []byte, key string) (controlv1.CertificateIssuance, error) {
			calls++
			if calls > 1 && (bytes.Equal(previousCSR, csr) || previousKey == key) {
				t.Error("terminal issuance retry reused its failed CSR or idempotency key")
			}
			previousCSR, previousKey = bytes.Clone(csr), key
			i, err := control.issue(csr)
			i.State, i.CertificatePem, i.NotBefore, i.NotAfter = controlv1.CertificateIssuanceStateFailed, nil, nil, nil
			return i, err
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, err := issueInitialCertificate(ctx, control, route, state, control.setup)
		var terminal *terminalCertificateIssuanceError
		if !errors.As(err, &terminal) || calls != 2 {
			t.Fatalf("terminal issuance retry: calls=%d error=%v, want 2 calls and terminal failure", calls, err)
		}
	})
}

func TestInitialCertificateUsesCurrentMaterialBeforeContendedLock(t *testing.T) {
	control, firstRoute, state := newCertificateTransactionTest(t)
	material, err := attemptCertificateTransaction(t.Context(), control, firstRoute, state, control.setup, false)
	if err != nil {
		t.Fatal(err)
	}
	setup := control.setup
	setup.RouteSession.Id = "route_session_22222222222222222222222222222222"
	setup.RouteSession.RouteVersion = 2
	control.setup = setup
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("current certificate triggered another issuance")
	}
	acknowledged := false
	control.installed = func(session string, version uint64, issuance string, notAfter time.Time) error {
		acknowledged = session == setup.RouteSession.Id && version == 2 && issuance == material.IssuanceID && notAfter.Equal(material.Certificate.Leaf.NotAfter)
		return nil
	}
	lock, err := state.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	route := certificateTestRoute(t, "route.example", setup.CertificatePlan)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := issueInitialCertificate(ctx, control, route, state, setup)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("initial session waited for the cache lock despite valid current material")
	}
	selected, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"})
	if err != nil || !acknowledged || !bytes.Equal(selected.Certificate[0], material.Certificate.Certificate[0]) {
		t.Fatalf("current material acknowledgement/install: acknowledged=%t error=%v", acknowledged, err)
	}
}

func TestCertificateRenewalPreservesOldCertificateUntilExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control, route, state := newCertificateTransactionTest(t)
		initial, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(initial.RenewAt))
		control.create = func(csr []byte, _ string) (controlv1.CertificateIssuance, error) {
			request, err := x509.ParseCertificateRequest(csr)
			if err != nil {
				return controlv1.CertificateIssuance{}, err
			}
			if request.PublicKey.(*ecdsa.PublicKey).Equal(initial.Certificate.Leaf.PublicKey) {
				t.Error("renewal reused the current application key")
			}
			i, err := control.issue(csr)
			i.State, i.CertificatePem, i.NotBefore, i.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
			return i, err
		}
		_, err = attemptCertificateTransaction(t.Context(), control, route, state, control.setup, true)
		var pending *pendingCertificateIssuanceError
		if !errors.As(err, &pending) {
			t.Fatalf("pending renewal = %v", err)
		}
		selected, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"})
		if err != nil || !bytes.Equal(selected.Certificate[0], initial.Certificate.Certificate[0]) {
			t.Fatalf("pending renewal displaced the valid certificate: %v", err)
		}
		current, found, err := state.Current(t.Context(), "route.example")
		if err != nil || !found || !bytes.Equal(current.Certificate.Certificate[0], initial.Certificate.Certificate[0]) {
			t.Fatalf("pending renewal displaced durable current material: found=%t error=%v", found, err)
		}
		<-route.certificateExpiration()
		if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"}); !errors.Is(err, errCertificateExpired) {
			t.Fatalf("expired certificate remained available during renewal: %v", err)
		}
		if _, _, err := state.Current(t.Context(), "route.example"); !errors.Is(err, clientstate.ErrCertificateExpired) {
			t.Fatalf("expired cached certificate remained reusable: %v", err)
		}
	})
}

func TestCertificateRenewalAcknowledgementPreservesCurrent(t *testing.T) {
	for _, failure := range []error{controlclient.ErrUnavailable, controlclient.ErrStatusConflict, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				control, route, cache := newCertificateTransactionTest(t)
				initial, err := attemptCertificateTransaction(t.Context(), control, route, cache, control.setup, false)
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Until(initial.RenewAt))
				control.installed = func(string, uint64, string, time.Time) error { return failure }
				if _, err := attemptCertificateTransaction(t.Context(), control, route, cache, control.setup, true); !errors.Is(err, failure) {
					t.Fatalf("lost renewal ACK: %v", err)
				}
				current, found, err := cache.Current(t.Context(), "route.example")
				if err != nil || !found || current.IssuanceID != initial.IssuanceID {
					t.Fatalf("unacknowledged renewal displaced current: %t, %v", found, err)
				}
				selected, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"})
				if err != nil || !bytes.Equal(selected.Certificate[0], initial.Certificate.Certificate[0]) {
					t.Fatalf("unacknowledged renewal displaced serving certificate: %v", err)
				}
				staged, found, err := cache.Staged(t.Context(), "route.example")
				if err != nil || !found || staged.IssuanceID == initial.IssuanceID {
					t.Fatalf("recoverable renewal missing: %t, %v", found, err)
				}
				control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
					return controlv1.CertificateIssuance{}, errors.New("staged renewal requested another issuance")
				}
				control.installed = nil
				material, err := attemptCertificateTransaction(t.Context(), control, route, cache, control.setup, true)
				if err != nil || material.IssuanceID != staged.IssuanceID {
					t.Fatalf("staged renewal did not recover: %v", err)
				}
			})
		})
	}
}

type certificateTestControl struct {
	publisherControlStub
	setup          controlv1.RouteSessionSetup
	store          *clientstate.Store
	signer         tls.Certificate
	create         func([]byte, string) (controlv1.CertificateIssuance, error)
	challengeReady func() (controlv1.CertificateIssuance, error)
	removed        func() error
	installed      func(string, uint64, string, time.Time) error
	change         func(*controlv1.CertificateIssuance, *x509.Certificate)
	ready          func() error
}

func newCertificateTestControl(t *testing.T, hostname string, plan controlv1.CertificatePlan) *certificateTestControl {
	t.Helper()
	token, _, _, err := credentials.NewRouteSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	signer := routeTestCertificate(t, "issuer.example")
	signer.Leaf.IsCA, signer.Leaf.BasicConstraintsValid = true, true
	signer.Leaf.KeyUsage, signer.Leaf.ExtKeyUsage = x509.KeyUsageCertSign, nil
	signer.Leaf.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, signer.Leaf, signer.Leaf, signer.Leaf.PublicKey, signer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signer.Certificate = [][]byte{der}
	signer.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certificateTestControl{
		signer: signer,
		setup: controlv1.RouteSessionSetup{
			Route:             controlv1.Route{Id: certificateTestRouteID, CanonicalHostname: hostname, TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"), RouteScope: controlv1.Member, LifecycleState: controlv1.Enabled},
			RouteSession:      controlv1.RouteSession{Id: "route_session_0123456789abcdef0123456789abcdef", RouteId: certificateTestRouteID, TeamId: "team_1", RouteVersion: 1, ExpiresAt: time.Now().Add(time.Hour)},
			RouteSessionToken: token.String(), CertificatePlan: plan,
		},
	}
}

func namespaceCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01}
}

func routeCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: controlv1.TlsAlpn01}
}

func newCertificateTransactionTest(t *testing.T) (*certificateTestControl, *RouteServer, *clientstate.CertificateCache) {
	t.Helper()
	control := newCertificateTestControl(t, "route.example", routeCertificateTestPlan())
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	state, err := control.store.Certificates(control.setup.Route.TeamId, control.setup.CertificatePlan)
	if err != nil {
		t.Fatal(err)
	}
	return control, certificateTestRoute(t, "route.example", control.setup.CertificatePlan), state
}

func certificateTestStore(t *testing.T, root string) *clientstate.Store {
	t.Helper()
	database, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func certificateTestRoute(t *testing.T, hostname string, plan controlv1.CertificatePlan) *RouteServer {
	t.Helper()
	route, err := NewRouteServer(RouteServerConfig{Hostname: hostname, Target: "http://127.0.0.1:3000", CertificatePlan: plan})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	return route
}

func certificateTestChallenge() controlv1.CertificateChallenge {
	digest := sha256.Sum256([]byte("test TLS-ALPN key authorization"))
	return controlv1.CertificateChallenge{Token: "challenge_1", Identifier: "route.example", Method: controlv1.TlsAlpn01, Digest: base64.RawURLEncoding.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(10 * time.Minute)}
}

// The fixture signs the submitted key only when the actual CSR matches the authoritative plan.
func (c *certificateTestControl) issue(csrDER []byte) (controlv1.CertificateIssuance, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return controlv1.CertificateIssuance{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return controlv1.CertificateIssuance{}, err
	}
	want, got := slices.Clone(c.setup.CertificatePlan.Identifiers), slices.Clone(csr.DNSNames)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) || len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0 || csr.Subject.String() != "" {
		return controlv1.CertificateIssuance{}, fmt.Errorf("CSR identifiers = %q; authoritative plan requires %q", csr.DNSNames, c.setup.CertificatePlan.Identifiers)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Minute).UTC().Truncate(time.Second), NotAfter: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	digest := sha256.Sum256(csrDER)
	i := controlv1.CertificateIssuance{Id: fmt.Sprintf("issuance_%x", digest[:16]), RouteId: c.setup.Route.Id, RouteSessionId: c.setup.RouteSession.Id, RouteVersion: c.setup.RouteSession.RouteVersion, CertificatePlan: c.setup.CertificatePlan, State: controlv1.CertificateIssuanceStateWaitingForInstall, NotBefore: pointer(leaf.NotBefore), NotAfter: pointer(leaf.NotAfter)}
	if c.change != nil {
		c.change(&i, leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, c.signer.Leaf, csr.PublicKey, c.signer.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return i, err
	}
	if i.CertificatePem == nil {
		chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.signer.Certificate[0]})...)
		i.CertificatePem = pointer(string(chain))
	}
	return i, nil
}

func (c *certificateTestControl) CreateCertificateIssuance(_ context.Context, session string, version uint64, token credentials.RouteSessionToken, csr []byte, key string) (controlv1.CertificateIssuance, error) {
	if session != c.setup.RouteSession.Id || version != uint64(c.setup.RouteSession.RouteVersion) || token.String() != c.setup.RouteSessionToken || key == "" {
		return controlv1.CertificateIssuance{}, errors.New("unexpected certificate request identity")
	}
	if c.create != nil {
		return c.create(csr, key)
	}
	return c.issue(csr)
}

func (c *certificateTestControl) MarkCertificateChallengeReady(_ context.Context, _ string, _ credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	if c.challengeReady == nil {
		return controlv1.CertificateIssuance{}, errors.New("unexpected challenge-ready request")
	}
	return c.challengeReady()
}

func (c *certificateTestControl) MarkCertificateChallengeRemoved(context.Context, string, credentials.RouteSessionToken) error {
	if c.removed != nil {
		return c.removed()
	}
	return nil
}

func (c *certificateTestControl) MarkRouteSessionCertificateInstalled(_ context.Context, session string, version uint64, issuance string, notAfter time.Time, token credentials.RouteSessionToken) error {
	if token.String() != c.setup.RouteSessionToken {
		return errors.New("unexpected certificate installation token")
	}
	if c.installed != nil {
		return c.installed(session, version, issuance, notAfter)
	}
	return nil
}
