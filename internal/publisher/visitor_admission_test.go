package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestReadinessHasIndependentBoundedProbeCapacity(t *testing.T) {
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: "url-1", Number: 1}
	proof, err := NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 4), make(chan struct{})
	var workers sync.WaitGroup
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, ReadinessProof: proof, Limits: ApplicationLimits{Requests: 1, Concurrency: 1, RateRequests: 1, RatePer: time.Hour},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if localproxy.IsReadinessProbe(r) {
				entered <- struct{}{}
				<-release
			}
			w.WriteHeader(204)
		})})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	defer func() { close(release); workers.Wait() }()
	request := func(path, token string) *http.Request {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = run.Hostname
		r.TLS = &tls.ConnectionState{ServerName: run.Hostname}
		if token != "" {
			r.Header.Set(localproxy.ReadinessProbeHeader, token)
		}
		return r
	}
	for range 4 {
		token, err := proof.Renew()
		if err != nil {
			t.Fatal(err)
		}
		r := request("/health", token)
		workers.Go(func() {
			w := httptest.NewRecorder()
			route.http.Handler.ServeHTTP(w, r)
			if w.Code != 204 {
				t.Errorf("admitted probe status=%d", w.Code)
			}
		})
		awaitPublisherTest(t, entered)
	}
	token, _ := proof.Renew()
	rejected := httptest.NewRecorder()
	route.http.Handler.ServeHTTP(rejected, request("/health", token))
	if rejected.Code != 503 {
		t.Fatalf("unbounded probes: status=%d", rejected.Code)
	}
	ordinary := httptest.NewRecorder()
	route.http.Handler.ServeHTTP(ordinary, request("/app", ""))
	if ordinary.Code != 204 || route.admission.used != 1 || route.admission.active != 0 {
		t.Fatalf("probes spent application budgets: status=%d used=%d active=%d", ordinary.Code, route.admission.used, route.admission.active)
	}
}

func TestReadinessProofDoesNotAuthorizeBodiesOrUpgrades(t *testing.T) {
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: "url-1", Number: 1}
	proof, _ := NewReadinessProof(run, "/health")
	body := httptest.NewRequest("GET", "/health", strings.NewReader("private-body"))
	body.Header.Set(localproxy.ReadinessProbeHeader, proof.HeaderValue())
	if proof.consume(body, run) {
		t.Fatal("body was admitted as a probe")
	}
	upgrade := httptest.NewRequest("GET", "/health", nil)
	upgrade.Header.Set(localproxy.ReadinessProbeHeader, proof.HeaderValue())
	upgrade.Header.Set("Upgrade", "websocket")
	if proof.consume(upgrade, run) {
		t.Fatal("upgrade was admitted as a probe")
	}
	get := httptest.NewRequest("GET", "/health", nil)
	get.Header.Set(localproxy.ReadinessProbeHeader, proof.HeaderValue())
	if !proof.consume(get, run) {
		t.Fatal("rejected requests consumed a valid proof")
	}
}

func mixedVisitorClient(t *testing.T, route *PublicURLServer, h2, denied bool) *http.Client {
	t.Helper()
	var dialed atomic.Bool
	transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, *route.certificate.Load())},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("test attempted to replace its visitor connection")
			}
			visitor, engine := net.Pipe()
			done := make(chan struct{})
			go func() { route.handleVisitor(engine, denied); close(done) }()
			t.Cleanup(func() { _ = visitor.Close(); awaitPublisherTest(t, done) })
			header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
			if err == nil {
				_, err = visitor.Write(header)
			}
			return visitor, err
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestReadinessDoesNotPromoteOrSpendApplicationBudgets(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, denied := range []bool{false, true} {
			name := "http1"
			if h2 {
				name = "http2"
			}
			if denied {
				name += "/denied"
			}
			t.Run(name, func(t *testing.T) {
				run := PublishRunIdentity{Hostname: "route.example", PublicURLID: "public-test", Number: 1}
				proof, err := NewReadinessProof(run, "/health")
				if err != nil {
					t.Fatal(err)
				}
				var app, probes, promoted atomic.Int32
				route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number,
					ReadinessProof: proof, Certificate: publicURLTestCertificate(t, run.Hostname), Limits: ApplicationLimits{Requests: 1, RateRequests: 1, RatePer: time.Hour},
					PromoteVisitor: func(_ context.Context, v Visitor) error {
						if v.Readiness {
							t.Error("proof reached ordinary ingress promotion")
						}
						promoted.Add(1)
						return nil
					},
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if localproxy.IsReadinessProbe(r) {
							probes.Add(1)
						} else {
							app.Add(1)
						}
						w.WriteHeader(204)
					}),
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = route.Close() })
				if err := route.Start(); err != nil {
					t.Fatal(err)
				}
				client := mixedVisitorClient(t, route, h2, denied)
				get := func(path, token string, status int) {
					t.Helper()
					r, _ := http.NewRequest("GET", "https://route.example"+path, nil)
					if token != "" {
						r.Header.Set(localproxy.ReadinessProbeHeader, token)
					}
					response, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
					wantProto := 1
					if h2 {
						wantProto = 2
					}
					if response.StatusCode != status || response.ProtoMajor != wantProto {
						t.Fatalf("%s: status=%d protocol=%d", path, response.StatusCode, response.ProtoMajor)
					}
				}
				get("/health", proof.HeaderValue(), 204)
				status := 204
				if denied {
					status = 403
				}
				get("/app", "", status)
				token, err := proof.Renew()
				if err != nil {
					t.Fatal(err)
				}
				get("/health", token, 204)
				status = 503
				if denied {
					status = 403
				}
				get("/app", "", status)
				wantApp := int32(1)
				if denied {
					wantApp = 0
				}
				if probes.Load() != 2 || app.Load() != wantApp || promoted.Load() != wantApp {
					t.Fatalf("probes=%d app=%d promotion=%d", probes.Load(), app.Load(), promoted.Load())
				}
			})
		}
	}
}

func TestReadinessDoesNotCacheRejectedApplicationPromotion(t *testing.T) {
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: "public-test", Number: 1}
	for _, h2 := range []bool{false, true} {
		proof, _ := NewReadinessProof(run, "/health")
		var calls atomic.Int32
		route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, Certificate: publicURLTestCertificate(t, run.Hostname), ReadinessProof: proof,
			PromoteVisitor: func(context.Context, Visitor) error {
				calls.Add(1)
				return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !localproxy.IsReadinessProbe(r) {
					t.Error("ordinary request bypassed ingress decision")
				}
				w.WriteHeader(204)
			})})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = route.Close() })
		if err := route.Start(); err != nil {
			t.Fatal(err)
		}
		client := mixedVisitorClient(t, route, h2, false)
		r, _ := http.NewRequest("GET", "https://route.example/health", nil)
		r.Header.Set(localproxy.ReadinessProbeHeader, proof.HeaderValue())
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 204 || calls.Load() != 0 {
			t.Fatal("readiness promoted application traffic")
		}
		for range 2 {
			response, err = client.Get("https://route.example/app")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != 503 {
				t.Fatalf("ordinary status=%d", response.StatusCode)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("stable ingress rejection was replayed")
		}
	}
}

func TestPromotionWaiterCancellationDoesNotCancelSharedDecision(t *testing.T) {
	life, cancelLife := context.WithCancel(t.Context())
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	v := &visitorSession{life: life, cancel: cancelLife, promote: func(ctx context.Context, _ Visitor) error {
		calls.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}}
	t.Cleanup(v.close)
	firstCtx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { first <- v.admit(firstCtx) }()
	awaitPublisherTest(t, started)
	cancel()
	if err := awaitPublisherTest(t, first); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() { second <- v.admit(t.Context()) }()
	close(release)
	if err := awaitPublisherTest(t, second); err != nil {
		t.Fatal(err)
	}
	if err := v.admit(t.Context()); err != nil || calls.Load() != 1 {
		t.Fatalf("cached promotion=%v calls=%d", err, calls.Load())
	}
	cancelLife()
	if err := v.admit(t.Context()); !errors.Is(err, context.Canceled) {
		t.Fatal("closed connection reused cached promotion", err)
	}
}

func TestHTTP2CanceledFirstRequestDoesNotPoisonConnection(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	firstDone := make(chan struct{})
	var calls, forwarded atomic.Int32
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"),
		PromoteVisitor: func(ctx context.Context, _ Visitor) error {
			calls.Add(1)
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); w.WriteHeader(204) })})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	previous := route.http.Handler
	route.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			defer close(firstDone)
		}
		previous.ServeHTTP(w, r)
	})
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	client := mixedVisitorClient(t, route, true, false)
	ctx, cancel := context.WithCancel(t.Context())
	r, _ := http.NewRequestWithContext(ctx, "GET", "https://route.example/first", nil)
	first := make(chan error, 1)
	go func() {
		response, err := client.Do(r)
		if response != nil {
			_ = response.Body.Close()
		}
		first <- err
	}()
	awaitPublisherTest(t, started)
	cancel()
	if err := awaitPublisherTest(t, first); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	awaitPublisherTest(t, firstDone)
	close(release)
	response, err := client.Get("https://route.example/second")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || response.ProtoMajor != 2 || calls.Load() != 1 || forwarded.Load() != 1 {
		t.Fatalf("status=%d calls=%d forwarded=%d", response.StatusCode, calls.Load(), forwarded.Load())
	}
}

func TestHTTP2ProofDoesNotWaitForApplicationPromotion(t *testing.T) {
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: "url-1", Number: 1}
	proof, _ := NewReadinessProof(run, "/health")
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, Certificate: publicURLTestCertificate(t, run.Hostname), ReadinessProof: proof,
		Limits: ApplicationLimits{Requests: 1, Concurrency: 1, RateRequests: 1, RatePer: time.Hour},
		PromoteVisitor: func(ctx context.Context, _ Visitor) error {
			calls.Add(1)
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	client := mixedVisitorClient(t, route, true, false)
	ordinary := make(chan int, 1)
	go func() {
		r, err := client.Get("https://route.example/app")
		status := 0
		if err == nil {
			status = r.StatusCode
			_ = r.Body.Close()
		}
		ordinary <- status
	}()
	awaitPublisherTest(t, started)
	r, _ := http.NewRequest("GET", "https://route.example/health", nil)
	r.Header.Set(localproxy.ReadinessProbeHeader, proof.HeaderValue())
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || calls.Load() != 1 {
		t.Fatalf("probe borrowed application promotion: status=%d calls=%d", response.StatusCode, calls.Load())
	}
	close(release)
	if status := awaitPublisherTest(t, ordinary); status != 204 {
		t.Fatalf("ordinary status=%d", status)
	}
}

func TestPromotionCloseCancelsAndJoinsSharedWork(t *testing.T) {
	life, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	v := &visitorSession{life: life, cancel: cancel, promote: func(ctx context.Context, _ Visitor) error { close(started); <-ctx.Done(); return ctx.Err() }}
	result := make(chan error, 1)
	go func() { result <- v.admit(t.Context()) }()
	awaitPublisherTest(t, started)
	v.close()
	if err := awaitPublisherTest(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := v.admit(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed admission=%v", err)
	}
}

func TestExtremeRatePeriodRetryAfterDoesNotOverflow(t *testing.T) {
	a, err := newApplicationAdmission(ApplicationLimits{RateRequests: 1, RatePer: time.Duration(math.MaxInt64), RateBurst: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if status, _ := a.enter(now); status != 0 {
		t.Fatal(status)
	}
	a.leave()
	status, retry := a.enter(now)
	if status != 429 || retry != time.Duration(math.MaxInt64) || retryAfterSeconds(retry) != 9223372037 {
		t.Fatalf("status=%d retry=%d seconds=%d", status, retry, retryAfterSeconds(retry))
	}
	_, retry = a.enter(now.Add(time.Second))
	if retry < time.Duration(math.MaxInt64)-2*time.Second {
		t.Fatalf("overflow after partial refill: %s", retry)
	}
}

type certificateAuthorizerFunc func(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState) error

func (f certificateAuthorizerFunc) AuthorizeVisitorCertificate(ctx context.Context, scope controlclient.VisitorCertificateScope, state tls.ConnectionState) error {
	return f(ctx, scope, state)
}

func TestLiveCertificateAdapterBindsRunAndTrustedSource(t *testing.T) {
	scope := controlclient.VisitorCertificateScope{PublishRunID: "run-1", PublicURLID: "url-1", PublishRunNumber: 7, PublishRunToken: credentials.PublishRunToken("private-run-token")}
	var calls int
	authorize := VisitorCertificateAuthorization(certificateAuthorizerFunc(func(_ context.Context, got controlclient.VisitorCertificateScope, _ tls.ConnectionState) error {
		calls++
		if got.PublishRunID != scope.PublishRunID || got.PublicURLID != scope.PublicURLID || got.PublishRunNumber != scope.PublishRunNumber || got.PublishRunToken != scope.PublishRunToken || got.SourceIP.String() != "192.0.2.10" {
			t.Error("certificate authorization lost exact scope")
		}
		return nil
	}), scope)
	v := Visitor{Run: PublishRunIdentity{PublicURLID: scope.PublicURLID, PublishRunID: scope.PublishRunID, Number: scope.PublishRunNumber}, Source: netip.MustParseAddrPort("192.0.2.10:1234")}
	if err := authorize(t.Context(), v, tls.ConnectionState{}); err != nil {
		t.Fatal(err)
	}
	v.Run.PublishRunID = "other"
	if err := authorize(t.Context(), v, tls.ConnectionState{}); err == nil || calls != 1 {
		t.Fatal("accepted a replaced run")
	}
}

func TestDeniedDatabaseVisitorReachesTLSAuthorization(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql, controlv1.Redis} {
		t.Run(string(protocol), func(t *testing.T) {
			var greeting []byte
			if protocol == controlv1.Mysql {
				greeting = testMySQLGreeting()
			}
			address, received := plaintextCaptureTarget(t, greeting)
			certificate := publicURLTestCertificate(t, "route.example")
			var authorized, promoted atomic.Int32
			route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", ServiceProtocol: protocol, PublicPort: 5432, Target: address, Certificate: certificate,
				AuthorizeVisitorCertificate: func(_ context.Context, v Visitor, state tls.ConnectionState) error {
					if !v.Header.IPPolicyDenied || !state.HandshakeComplete {
						t.Error("missing trusted denial or TLS")
					}
					authorized.Add(1)
					return errors.New("test live policy rejects visitor")
				},
				PromoteVisitor: func(context.Context, Visitor) error { promoted.Add(1); return nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer route.Close()
			client, engine := net.Pipe()
			done := make(chan struct{})
			go func() { route.handleVisitor(engine, true); close(done) }()
			t.Cleanup(func() { _ = client.Close(); awaitPublisherTest(t, done) })
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			header, _ := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("203.0.113.10:5432")})
			_, _ = client.Write(header)
			if protocol == controlv1.Postgres {
				_, _ = client.Write(postgresSSLRequest[:])
				readDatabaseByte(t, client, 'S')
			}
			if protocol == controlv1.Mysql {
				if _, err := readMySQLPacket(client, 64<<10); err != nil {
					t.Fatal(err)
				}
				_, _ = client.Write(mysqlTestSSLRequest())
			}
			secured := tls.Client(client, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
			if err := secured.Handshake(); err != nil {
				t.Fatal(err)
			}
			_, _ = io.ReadAll(secured)
			if b := awaitPublisherTest(t, received); len(b) != 0 || authorized.Load() != 1 || promoted.Load() != 0 {
				t.Fatalf("auth bytes=%x authorize=%d promote=%d", b, authorized.Load(), promoted.Load())
			}
		})
	}
}
