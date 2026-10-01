package publisher

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRunSubmitsAuthoritativeNamespaceCSR(t *testing.T) {
	for _, hostname := range []string{"member.example", "app.member.example"} {
		t.Run(hostname, func(t *testing.T) {
			control := newCertificateTestControl(t, hostname, namespaceCertificateTestPlan())
			control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
			config := startCertificateTLSYamuxHarness(t, control)
			var submitted *x509.CertificateRequest
			control.create = func(csr []byte, _ string) (controlv1.CertificateIssuance, error) {
				var err error
				submitted, err = x509.ParseCertificateRequest(csr)
				if err != nil {
					return controlv1.CertificateIssuance{}, err
				}
				return control.issue(csr)
			}
			reachedReady := errors.New("test reached ready")
			control.ready = func() error { return reachedReady }
			err := runCertificateSessionTest(t, config)
			if submitted == nil {
				t.Fatalf("publisher did not submit a CSR: %v", err)
			}
			want, got := slices.Clone(control.setup.CertificatePlan.Identifiers), slices.Clone(submitted.DNSNames)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(want, got) {
				t.Fatalf("submitted CSR SANs = %q, want authoritative session SANs %q; Run = %v", submitted.DNSNames, control.setup.CertificatePlan.Identifiers, err)
			}
			if !errors.Is(err, reachedReady) || len(control.installations) != 1 || !slices.Equal(control.closedSessions, []string{control.setup.PublishRun.Id}) {
				t.Fatalf("authorized namespace issuance did not reach ready: %v", err)
			}
		})
	}
}

func TestRunReacknowledgesCachedCertificateForEachSession(t *testing.T) {
	control, route, state := newCertificateTransactionTest(t)
	material, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
	if err != nil {
		t.Fatal(err)
	}
	config := startCertificateTLSYamuxHarness(t, control)
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		t.Error("cached, unexpired certificate triggered a new issuance")
		return controlv1.CertificateIssuance{}, errors.New("unexpected issuance")
	}
	for version := int64(2); version <= 3; version++ {
		control.setup.PublishRun.Id = fmt.Sprintf("publish_run_%032x", version)
		control.setup.PublishRun.PublishRunNumber = version
		acks := 0
		control.installed = func(session string, gotVersion uint64, issuance string, notAfter time.Time) error {
			acks++
			if session != control.setup.PublishRun.Id || gotVersion != uint64(version) || issuance != material.IssuanceID || !notAfter.Equal(material.Certificate.Leaf.NotAfter) {
				t.Error("cached certificate acknowledgement did not identify the current publish run and certificate")
			}
			return nil
		}
		reachedReady := errors.New("test reached ready")
		control.ready = func() error {
			if acks != 1 {
				t.Errorf("ready preceded per-session installation acknowledgement: calls=%d", acks)
			}
			return reachedReady
		}
		err := runCertificateSessionTest(t, config)
		if !errors.Is(err, reachedReady) || acks != 1 {
			t.Fatalf("session %d: acknowledgements=%d Run=%v", version, acks, err)
		}
	}
}

func TestRunSessionRetriesReadinessConflict(t *testing.T) {
	control, route, state := newCertificateTransactionTest(t)
	if _, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false); err != nil {
		t.Fatal(err)
	}
	config := startCertificateTLSYamuxHarness(t, control)
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("cached certificate triggered a new issuance")
	}
	readyAttempts := 0
	control.ready = func() error {
		readyAttempts++
		if readyAttempts == 1 {
			return controlclient.ErrStatusConflict
		}
		return nil
	}
	reachedReady := errors.New("test reached ready")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := runSession(ctx, config, control.setup, func() error { return reachedReady })
	if !errors.Is(err, reachedReady) || readyAttempts != 2 {
		t.Fatalf("readiness attempts = %d, session error = %v", readyAttempts, err)
	}
}

func TestRunSessionDoesNotRetryReadyCallbackAfterControlAccepts(t *testing.T) {
	control, route, state := newCertificateTransactionTest(t)
	if _, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false); err != nil {
		t.Fatal(err)
	}
	config := startCertificateTLSYamuxHarness(t, control)
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("cached certificate triggered a new issuance")
	}
	readyAttempts := 0
	control.ready = func() error { readyAttempts++; return nil }
	callbackAttempts := 0
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := runSession(ctx, config, control.setup, func() error {
		callbackAttempts++
		return controlclient.ErrStatusConflict
	})
	if !errors.Is(err, controlclient.ErrStatusConflict) || readyAttempts != 1 || callbackAttempts != 1 {
		t.Fatalf("ready calls = %d, callback calls = %d, session error = %v", readyAttempts, callbackAttempts, err)
	}
}

func TestRunTransportFallbackObserverErrorCancelsSession(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	config := startCertificateTLSYamuxHarness(t, control)
	observerError := errors.New("fallback observer failed")
	config.Observe = func(event Event) error {
		if event.Type == EventTransportFallback {
			return observerError
		}
		return nil
	}
	if err := runCertificateSessionTest(t, config); !errors.Is(err, observerError) {
		t.Fatalf("Run error = %v, want fallback observer error", err)
	}
}

func TestRunDoesNotReuseCertificateFromIncompatibleSessionPlan(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.CertificatePlan)
	}{
		{"cache_key", func(p *controlv1.CertificatePlan) { p.CacheKey = "another-cache-key" }},
		{"same_key_scope", func(p *controlv1.CertificatePlan) { p.Scope = "another-scope" }},
		{"same_key_identifiers", func(p *controlv1.CertificatePlan) { p.Identifiers = []string{"route.example", "*.route.example"} }},
		{"same_key_method", func(p *controlv1.CertificatePlan) { p.ChallengeMethod = controlv1.TlsAlpn01 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			control, route, _ := newCertificateTransactionTest(t)
			control.setup.CertificatePlan.ChallengeMethod = controlv1.Dns01
			state, err := control.store.Certificates(control.setup.PublicUrl.TeamId, control.setup.CertificatePlan)
			if err != nil {
				t.Fatal(err)
			}
			material, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
			if err != nil {
				t.Fatal(err)
			}
			config := startCertificateTLSYamuxHarness(t, control)
			test.change(&control.setup.CertificatePlan)
			control.setup.PublishRun.PublishRunNumber++
			control.setup.PublishRun.Id = "publish_run_22222222222222222222222222222222"
			submitted := false
			control.create = func(csr []byte, _ string) (controlv1.CertificateIssuance, error) {
				submitted = true
				return control.issue(csr)
			}
			control.installed = func(_ string, _ uint64, issuance string, _ time.Time) error {
				if issuance == material.IssuanceID {
					t.Error("acknowledged material from an incompatible plan")
				}
				return nil
			}
			reachedReady := errors.New("test reached ready")
			control.ready = func() error { return reachedReady }
			err = runCertificateSessionTest(t, config)
			if !submitted || !errors.Is(err, reachedReady) {
				t.Fatalf("incompatible plan replacement: submitted=%t Run=%v", submitted, err)
			}
		})
	}
}

func TestRunSharesNamespaceMaterialWithoutHoldingTransactionLock(t *testing.T) {
	first := newCertificateTestControl(t, "first.member.example", namespaceCertificateTestPlan())
	first.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	firstConfig := startCertificateTLSYamuxHarness(t, first)
	ready := make(chan struct{})
	first.ready = func() error { close(ready); return nil }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, firstConfig) }()
	defer func() {
		cancel()
		if err := awaitPublisherTest(t, done); err != nil {
			t.Errorf("first publisher: %v", err)
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("first publisher did not become ready")
	}
	second := newCertificateTestControl(t, "second.member.example", namespaceCertificateTestPlan())
	second.store = first.store
	second.setup.PublicUrl.Id = "public_url_22222222222222222222222222222222"
	second.setup.PublishRun.PublicUrlId = second.setup.PublicUrl.Id
	second.setup.PublishRun.Id = "publish_run_22222222222222222222222222222222"
	secondConfig := startCertificateTLSYamuxHarness(t, second)
	second.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("second route requested another namespace certificate")
	}
	acks := 0
	second.installed = func(session string, version uint64, _ string, _ time.Time) error {
		if session != second.setup.PublishRun.Id || version != 1 {
			t.Error("wrong second-session acknowledgement")
		}
		acks++
		return nil
	}
	reachedReady := errors.New("second publisher ready")
	second.ready = func() error { return reachedReady }
	if err := Run(ctx, secondConfig); !errors.Is(err, reachedReady) || acks != 1 {
		t.Fatalf("shared namespace while first tunnel remains active: acknowledgements=%d error=%v", acks, err)
	}
}

func TestConcurrentNamespaceCertificateLifecycle(t *testing.T) {
	for _, test := range []struct {
		name          string
		renew, expire bool
	}{
		{"cold", false, false},
		{"renew", true, false},
		{"renew_expired", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				renew := test.renew
				store := certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
				controls := [2]*certificateTestControl{}
				configs := [2]Config{}
				ready, heartbeats, acknowledgements := [2]int{}, [2]int{}, [2]string{}
				var acknowledgedCertificates [2][]byte
				orders := map[string]controlv1.CertificateIssuance{}
				requests := map[string][]byte{}
				var mu sync.Mutex
				complete := false
				var original clientstate.Material
				for slot := range controls {
					control := newCertificateTestControl(t, fmt.Sprintf("app%d.member.example", slot), namespaceCertificateTestPlan())
					control.setup.PublicUrl.Id = fmt.Sprintf("public_url_%032x", slot+1)
					control.setup.PublishRun.Id = fmt.Sprintf("publish_run_%032x", slot+1)
					control.setup.PublishRun.PublicUrlId = control.setup.PublicUrl.Id
					control.store = store
					controls[slot] = control
					cache, err := store.Certificates(control.setup.PublicUrl.TeamId, control.setup.CertificatePlan)
					if err != nil {
						t.Fatal(err)
					}
					if renew && slot == 0 {
						control.change = func(issuance *controlv1.CertificateIssuance, leaf *x509.Certificate) {
							leaf.NotAfter = time.Now().Add(90 * time.Second).UTC().Truncate(time.Second)
							issuance.NotAfter = pointer(leaf.NotAfter)
						}
						route := certificateTestPublicURL(t, control.setup.PublicUrl.CanonicalHostname, control.setup.CertificatePlan)
						original, err = attemptCertificateTransaction(t.Context(), control, route, cache, control.setup, false)
						if err != nil {
							t.Fatal(err)
						}
						control.change = nil
					}
					control.create = func(csr []byte, key string) (controlv1.CertificateIssuance, error) {
						mu.Lock()
						defer mu.Unlock()
						id := control.setup.PublishRun.Id + ":" + key
						issuance, found := orders[id]
						if !found {
							var err error
							issuance, err = control.issue(csr)
							if err != nil {
								return issuance, err
							}
							// Control idempotency is session-scoped, even for identical CSRs.
							issuance.Id = fmt.Sprintf("issuance_%032x", len(orders)+100)
							orders[id], requests[id] = issuance, bytes.Clone(csr)
						} else if !bytes.Equal(csr, requests[id]) {
							t.Error("retry changed the CSR under one idempotency key")
						}
						if !complete {
							issuance.State, issuance.CertificatePem, issuance.NotBefore, issuance.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
							issuance.RetryAt = pointer(time.Now().Add(time.Second))
						}
						return issuance, nil
					}
					control.installed = func(session string, version uint64, issuance string, notAfter time.Time) error {
						mu.Lock()
						defer mu.Unlock()
						if session != control.setup.PublishRun.Id || version != 1 {
							t.Error("wrong per-session installation acknowledgement")
						}
						current, found, err := cache.Staged(t.Context(), control.setup.PublicUrl.CanonicalHostname)
						if err == nil && !found {
							current, found, err = cache.Current(t.Context(), control.setup.PublicUrl.CanonicalHostname)
						}
						if err != nil || !found || current.IssuanceID != issuance || !current.Certificate.Leaf.NotAfter.Equal(notAfter) {
							return fmt.Errorf("acknowledged different certificate material: found=%t error=%v", found, err)
						}
						acknowledgements[slot] = issuance
						acknowledgedCertificates[slot] = bytes.Clone(current.Certificate.Certificate[0])
						return nil
					}
					control.ready = func() error {
						mu.Lock()
						defer mu.Unlock()
						ready[slot]++
						return nil
					}
					control.heartbeat = func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
						mu.Lock()
						defer mu.Unlock()
						heartbeats[slot]++
						session := control.setup.PublishRun
						session.ExpiresAt = time.Now().Add(time.Hour)
						return controlv1.PublishRunHeartbeat{PublishRun: session}, nil
					}
					connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
						return &certificateTestTransport{done: make(chan struct{})}, nil
					})
					configs[slot] = Config{Control: control, State: store, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", PublicURLScope: controlv1.Member,
						Hostname: control.setup.PublicUrl.CanonicalHostname, Target: "http://127.0.0.1:3000", QUICConnector: connector, TCPConnector: connector,
						FallbackDelay: time.Millisecond, DrainTime: time.Millisecond, ProvisioningStalledDelay: time.Minute}
					for connection := range 2 {
						control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
							ConnectionSlot: connection, ConnectionAssignmentRevision: 1, PublisherConnectionId: fmt.Sprintf("connection_%d", connection),
							PublisherConnectionCredential: "test-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(48 * time.Hour),
							RelayServiceId: fmt.Sprintf("relay_service_%d", connection), RelayAddress: "relay.example:443", TlsServerName: "relay.example", State: controlv1.PublisherConnectionStateAssigned,
						})
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 2)
				var wantSessionError error
				defer func() {
					cancel()
					for range controls {
						if err := <-done; !errors.Is(err, wantSessionError) {
							t.Errorf("session: %v, want %v", err, wantSessionError)
						}
					}
				}()
				for slot, control := range controls {
					go func() { done <- runSession(ctx, configs[slot], control.setup, func() error { return nil }) }()
					synctest.Wait()
				}
				if renew {
					mu.Lock()
					started := ready
					mu.Unlock()
					if started != [2]int{1, 1} {
						t.Fatalf("sessions did not start on existing material: %v", started)
					}
					time.Sleep(time.Until(original.RenewAt))
				}
				time.Sleep(heartbeatInterval + time.Second)
				synctest.Wait()
				mu.Lock()
				if len(orders) != 1 {
					t.Errorf("concurrent certificate provisioning created %d session-scoped orders, want 1", len(orders))
				}
				for slot := range controls {
					if heartbeats[slot] < 2 {
						t.Errorf("session %d stopped heartbeats during provisioning", slot)
					}
					if !renew && (ready[slot] != 0 || acknowledgements[slot] != "") {
						t.Errorf("session %d became ready before issuance completed", slot)
					}
					if renew && acknowledgements[slot] != original.IssuanceID {
						t.Errorf("session %d displaced its valid certificate during pending renewal", slot)
					}
				}
				mu.Unlock()
				if test.expire {
					wantSessionError = errCertificateExpired
					time.Sleep(time.Until(original.Certificate.Leaf.NotAfter))
					synctest.Wait()
					cache, err := store.Certificates("team_1", namespaceCertificateTestPlan())
					if err != nil {
						t.Fatal(err)
					}
					lockCtx, stop := context.WithTimeout(t.Context(), time.Second)
					defer stop()
					lock, err := cache.Lock(lockCtx)
					if err != nil {
						t.Fatalf("expired renewal retained its cache lock: %v", err)
					}
					defer lock.Close()
					mu.Lock()
					if len(orders) != 1 || len(done) != 2 {
						t.Errorf("expiration: orders=%d completed sessions=%d", len(orders), len(done))
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				complete = true
				mu.Unlock()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				mu.Lock()
				if len(orders) != 1 || ready != [2]int{1, 1} || acknowledgements[0] == "" || acknowledgements[0] != acknowledgements[1] ||
					!bytes.Equal(acknowledgedCertificates[0], acknowledgedCertificates[1]) || renew && acknowledgements[0] == original.IssuanceID {
					t.Errorf("shared issuance completion: orders=%d ready=%v acknowledgements=%v", len(orders), ready, acknowledgements)
				}
				mu.Unlock()
			})
		})
	}
}

func TestRunReusesCompatibleCertificateAfterRouteRecreation(t *testing.T) {
	control, route, state := newCertificateTransactionTest(t)
	material, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
	if err != nil {
		t.Fatal(err)
	}
	// A recreated route has a new identity but the same server-authorized certificate cache key and plan.
	control.setup.PublicUrl.Id = "public_url_22222222222222222222222222222222"
	control.setup.PublishRun.PublicUrlId = control.setup.PublicUrl.Id
	control.setup.PublishRun.Id = "publish_run_22222222222222222222222222222222"
	config := startCertificateTLSYamuxHarness(t, control)
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("recreated route requested issuance instead of reusing compatible cached material")
	}
	acks := 0
	control.installed = func(session string, version uint64, issuance string, notAfter time.Time) error {
		acks++
		if session != control.setup.PublishRun.Id || version != 1 || issuance != material.IssuanceID || !notAfter.Equal(material.Certificate.Leaf.NotAfter) {
			t.Error("recreated route did not acknowledge cached material for its own session")
		}
		return nil
	}
	reachedReady := errors.New("test reached ready")
	control.ready = func() error { return reachedReady }
	err = runCertificateSessionTest(t, config)
	if !errors.Is(err, reachedReady) || acks != 1 {
		t.Fatalf("compatible cache reuse across route identities: acknowledgements=%d Run=%v", acks, err)
	}
}

func runCertificateSessionTest(t *testing.T, config Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return Run(ctx, config)
}
