package publisher

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/acme"
)

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
				// reopen the cache and public URL server to recover locally committed,
				// unacknowledged certificate material.
				var err error
				state, err = control.store.Certificates(control.setup.PublicUrl.TeamId, control.setup.CertificatePlan)
				if err != nil {
					t.Fatal(err)
				}
				_ = route.Close()
				route = certificateTestPublicURL(t, "route.example", control.setup.CertificatePlan)
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
	control, firstPublicURL, state := newCertificateTransactionTest(t)
	material, err := attemptCertificateTransaction(t.Context(), control, firstPublicURL, state, control.setup, false)
	if err != nil {
		t.Fatal(err)
	}
	setup := control.setup
	setup.PublishRun.Id = "publish_run_22222222222222222222222222222222"
	setup.PublishRun.PublishRunNumber = 2
	control.setup = setup
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("current certificate triggered another issuance")
	}
	acknowledged := false
	control.installed = func(session string, version uint64, issuance string, notAfter time.Time) error {
		acknowledged = session == setup.PublishRun.Id && version == 2 && issuance == material.IssuanceID && notAfter.Equal(material.Certificate.Leaf.NotAfter)
		return nil
	}
	lock, err := state.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	route := certificateTestPublicURL(t, "route.example", setup.CertificatePlan)
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
