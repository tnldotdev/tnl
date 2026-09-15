package publisher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRunSubmitsAuthoritativeNamespaceCSR(t *testing.T) {
	for _, hostname := range []string{"member.example", "app.member.example"} {
		t.Run(hostname, func(t *testing.T) {
			control := newCertificateTestControl(t, hostname, namespaceCertificateTestPlan())
			control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
			config := certificateSessionTestConfig(t, control)
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
			if !errors.Is(err, reachedReady) {
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
	config := certificateSessionTestConfig(t, control)
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		t.Error("cached, unexpired certificate triggered a new issuance")
		return controlv1.CertificateIssuance{}, errors.New("unexpected issuance")
	}
	for version := int64(2); version <= 3; version++ {
		control.setup.RouteSession.Id = fmt.Sprintf("route_session_%032x", version)
		control.setup.RouteSession.RouteVersion = version
		acks := 0
		control.installed = func(session string, gotVersion uint64, issuance string, notAfter time.Time) error {
			acks++
			if session != control.setup.RouteSession.Id || gotVersion != uint64(version) || issuance != material.IssuanceID || !notAfter.Equal(material.Certificate.Leaf.NotAfter) {
				t.Error("cached certificate acknowledgement did not identify the current route session and certificate")
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
	previous := activationRetry
	activationRetry = time.Millisecond
	defer func() { activationRetry = previous }()

	control, route, state := newCertificateTransactionTest(t)
	if _, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false); err != nil {
		t.Fatal(err)
	}
	config := certificateSessionTestConfig(t, control)
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
			state, err := control.store.Certificates(control.setup.Route.TeamId, control.setup.CertificatePlan)
			if err != nil {
				t.Fatal(err)
			}
			material, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
			if err != nil {
				t.Fatal(err)
			}
			config := certificateSessionTestConfig(t, control)
			test.change(&control.setup.CertificatePlan)
			control.setup.RouteSession.RouteVersion++
			control.setup.RouteSession.Id = "route_session_22222222222222222222222222222222"
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
	firstConfig := certificateSessionTestConfig(t, first)
	ready := make(chan struct{})
	first.ready = func() error { close(ready); return nil }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, firstConfig) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
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
	second.setup.Route.Id = "route_22222222222222222222222222222222"
	second.setup.RouteSession.RouteId = second.setup.Route.Id
	second.setup.RouteSession.Id = "route_session_22222222222222222222222222222222"
	secondConfig := certificateSessionTestConfig(t, second)
	second.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("second route requested another namespace certificate")
	}
	acks := 0
	second.installed = func(session string, version uint64, _ string, _ time.Time) error {
		if session != second.setup.RouteSession.Id || version != 1 {
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
					control.setup.Route.Id = fmt.Sprintf("route_%032x", slot+1)
					control.setup.RouteSession.Id = fmt.Sprintf("route_session_%032x", slot+1)
					control.setup.RouteSession.RouteId = control.setup.Route.Id
					control.store = store
					controls[slot] = control
					cache, err := store.Certificates(control.setup.Route.TeamId, control.setup.CertificatePlan)
					if err != nil {
						t.Fatal(err)
					}
					if renew && slot == 0 {
						control.change = func(issuance *controlv1.CertificateIssuance, leaf *x509.Certificate) {
							leaf.NotAfter = time.Now().Add(90 * time.Second).UTC().Truncate(time.Second)
							issuance.NotAfter = pointer(leaf.NotAfter)
						}
						route := certificateTestRoute(t, control.setup.Route.CanonicalHostname, control.setup.CertificatePlan)
						original, err = attemptCertificateTransaction(t.Context(), control, route, cache, control.setup, false)
						if err != nil {
							t.Fatal(err)
						}
						control.change = nil
					}
					control.create = func(csr []byte, key string) (controlv1.CertificateIssuance, error) {
						mu.Lock()
						defer mu.Unlock()
						id := control.setup.RouteSession.Id + ":" + key
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
						if session != control.setup.RouteSession.Id || version != 1 {
							t.Error("wrong per-session installation acknowledgement")
						}
						current, found, err := cache.Staged(t.Context(), control.setup.Route.CanonicalHostname)
						if err == nil && !found {
							current, found, err = cache.Current(t.Context(), control.setup.Route.CanonicalHostname)
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
					control.heartbeat = func(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
						mu.Lock()
						defer mu.Unlock()
						heartbeats[slot]++
						session := control.setup.RouteSession
						session.ExpiresAt = time.Now().Add(time.Hour)
						return controlv1.RouteSessionHeartbeat{RouteSession: session}, nil
					}
					connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
						return &certificateTestTransport{done: make(chan struct{})}, nil
					})
					configs[slot] = Config{Control: control, State: store, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", RouteScope: controlv1.Member,
						Hostname: control.setup.Route.CanonicalHostname, Target: "http://127.0.0.1:3000", QUICConnector: connector, TCPConnector: connector,
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

// In-memory transport lets synctest exercise runSession's handshake, certificate
// lifecycle, acknowledgements, and heartbeats without external network I/O.
type certificateTestTransport struct {
	done chan struct{}
	once sync.Once
}

func (s *certificateTestTransport) OpenStream(context.Context) (muxsession.Stream, error) {
	local, remote := net.Pipe()
	go func() {
		defer remote.Close()
		if _, err := tunnelv1.ReadControl(remote); err != nil {
			return
		}
		if err := tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version}); err != nil {
			return
		}
		request, err := tunnelv1.ReadControl(remote)
		if err != nil {
			return
		}
		if request.Type != tunnelv1.Drain || request.RequestID == "" {
			return
		}
		if err := tunnelv1.WriteControl(remote, tunnelv1.Message{
			Type: tunnelv1.Draining, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID,
		}); err != nil {
			return
		}
		if err := tunnelv1.WriteControl(remote, tunnelv1.Message{
			Type: tunnelv1.Drained, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID,
		}); err != nil {
			return
		}
		<-s.done
	}()
	return certificateTestStream{local}, nil
}

func (s *certificateTestTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, muxsession.ErrClosed
	}
}
func (s *certificateTestTransport) Close() error          { s.once.Do(func() { close(s.done) }); return nil }
func (s *certificateTestTransport) Done() <-chan struct{} { return s.done }
func (s *certificateTestTransport) Err() error {
	select {
	case <-s.done:
		return muxsession.ErrClosed
	default:
		return nil
	}
}

type certificateTestStream struct{ net.Conn }

func (s certificateTestStream) CloseWrite() error  { return s.Close() }
func (s certificateTestStream) Reset(uint32) error { return s.Close() }

func TestRunReusesCompatibleCertificateAfterRouteRecreation(t *testing.T) {
	control, route, state := newCertificateTransactionTest(t)
	material, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false)
	if err != nil {
		t.Fatal(err)
	}
	// A recreated route has a new identity but the same server-authorized certificate cache key and plan.
	control.setup.Route.Id = "route_22222222222222222222222222222222"
	control.setup.RouteSession.RouteId = control.setup.Route.Id
	control.setup.RouteSession.Id = "route_session_22222222222222222222222222222222"
	config := certificateSessionTestConfig(t, control)
	control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
		return controlv1.CertificateIssuance{}, errors.New("recreated route requested issuance instead of reusing compatible cached material")
	}
	acks := 0
	control.installed = func(session string, version uint64, issuance string, notAfter time.Time) error {
		acks++
		if session != control.setup.RouteSession.Id || version != 1 || issuance != material.IssuanceID || !notAfter.Equal(material.Certificate.Leaf.NotAfter) {
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

func certificateSessionTestConfig(t *testing.T, control *certificateTestControl) Config {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(upstream.Close)
	control.setup.Route.Target = upstream.URL
	control.routes = []controlv1.Route{control.setup.Route}
	certificate := routeTestCertificate(t, "relay.example")
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); workers.Wait() })
	for slot := range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
			ConnectionSlot: slot, ConnectionAssignmentRevision: 1, PublisherConnectionId: fmt.Sprintf("connection_%d", slot),
			PublisherConnectionCredential: "test-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Hour),
			RelayServiceId: fmt.Sprintf("relay_service_%d", slot), RelayAddress: listener.Addr().String(), TlsServerName: "relay.example", State: controlv1.PublisherConnectionStateAssigned,
		})
		workers.Go(func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					defer connection.Close()
					stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
					defer stop()
					transport, err := muxsession.AcceptTLSYamux(ctx, connection, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
					if err != nil {
						return
					}
					defer transport.Close()
					session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
						if hello.Role != tunnelv1.Publisher || hello.Credential != "test-credential" || hello.PublisherConnection == nil || hello.PublisherConnection.ConnectionSlot != uint8(slot) {
							return errors.New("unexpected publisher hello")
						}
						return nil
					})
					if err != nil {
						return
					}
					defer session.Close()
					if err := session.HandlePublisherDrain(ctx, func(context.Context) error { return nil }); err == nil {
						select {
						case <-ctx.Done():
						case <-transport.Done():
						}
					}
				})
			}
		})
	}
	return Config{
		Control: control, State: control.store, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", RouteScope: controlv1.Member,
		Hostname: control.setup.Route.CanonicalHostname, Target: upstream.URL,
		FallbackDelay: time.Millisecond, DrainTime: time.Millisecond,
		QUICConnector: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			return nil, errors.New("test uses TLS/yamux")
		}),
		TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)}},
	}
}

func runCertificateSessionTest(t *testing.T, config Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return Run(ctx, config)
}

func (c *certificateTestControl) CreateRouteSession(_ context.Context, routeID, key string) (controlv1.RouteSessionSetup, error) {
	if routeID != c.setup.Route.Id || key == "" {
		return controlv1.RouteSessionSetup{}, errors.New("unexpected route session request")
	}
	return c.setup, nil
}

func (c *certificateTestControl) HeartbeatRouteSession(ctx context.Context, session string, version uint64, token credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
	if c.heartbeat != nil {
		return c.heartbeat(ctx, session, version, token)
	}
	return controlv1.RouteSessionHeartbeat{RouteSession: c.setup.RouteSession, PublisherConnections: c.setup.PublisherConnections}, nil
}

func (c *certificateTestControl) MarkRouteSessionReady(context.Context, string, uint64, credentials.RouteSessionToken) error {
	if c.ready != nil {
		return c.ready()
	}
	return nil
}

func TestAutomaticRouteAcceptsNamespaceCertificate(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	key := control.signer.PrivateKey
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: control.setup.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := control.issue(csr)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(*issuance.CertificatePem), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"member.example", "app.member.example"} {
		t.Run(hostname, func(t *testing.T) {
			route := certificateTestRoute(t, hostname, control.setup.CertificatePlan)
			if err := route.InstallCertificate(certificate); err != nil {
				t.Fatalf("authorized namespace certificate rejected: %v", err)
			}
			selected, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: hostname})
			if err != nil || !bytes.Equal(selected.Certificate[0], certificate.Certificate[0]) {
				t.Fatalf("namespace certificate selection = %v", err)
			}
			if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "other.member.example"}); err == nil {
				t.Fatal("wildcard certificate allowed SNI for a different route")
			}
		})
	}
	t.Run("uncovered_depth", func(t *testing.T) {
		route, err := NewRouteServer(RouteServerConfig{Hostname: "deep.app.member.example", Target: "http://127.0.0.1:3000", Certificate: certificate, CertificatePlan: control.setup.CertificatePlan})
		if err == nil {
			_ = route.Close()
			t.Fatal("namespace wildcard certificate covered a deeper hostname")
		}
	})
}
