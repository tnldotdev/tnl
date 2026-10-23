package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func realHTTPVisitor(t *testing.T, route *PublicURLServer) net.Conn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			route.handleVisitorHeader(c, false, tunnelv1.VisitorStreamHeader{VisitorConnectionID: "test-visitor"})
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close(); awaitPublisherTest(t, done) })
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(header); err != nil {
		t.Fatal(err)
	}
	return c
}

type deniedHTTPDecision struct {
	shareHeaderDecisionClient
	called chan controlv1.HTTPVisitorRequest
}

func (c *deniedHTTPDecision) AuthorizeHTTPVisitor(_ context.Context, _ string, request controlv1.HTTPVisitorRequest, _ credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error) {
	c.called <- request
	return controlv1.HTTPVisitorResponse{VisitAllowed: false}, nil
}

func TestHTTPAuthorizationPrecedesPromotionAndTarget(t *testing.T) {
	certificate := publicURLTestCertificate(t, "route.example")
	client := &deniedHTTPDecision{called: make(chan controlv1.HTTPVisitorRequest, 1)}
	var promoted, forwarded atomic.Int32
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{
		Hostname: "route.example", PublicURLID: certificateTestPublicURLID, PublishRunNumber: 7, Certificate: certificate, AccessMode: "restricted",
		BrowserAccess:  &browserAccess{client: client, publicURLID: "public-test", runID: "run-test", version: 7},
		PromoteVisitor: func(context.Context, Visitor) error { promoted.Add(1); return nil },
		Handler:        http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	visitor := realHTTPVisitor(t, route)
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(secured, "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(secured), nil)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatal("local visitor authorization did not reject before promotion", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	select {
	case <-client.called:
		t.Fatal("prepared visitor authorization made a synchronous control request")
	default:
	}
	if promoted.Load() != 0 || forwarded.Load() != 0 {
		t.Fatalf("authorization bypassed: promotions=%d forwarded=%d", promoted.Load(), forwarded.Load())
	}
}

func TestReadinessProofIsExactSingleUseAndStripped(t *testing.T) {
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: certificateTestPublicURLID, Number: 8}
	proof, err := NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	secret := proof.HeaderValue()
	var forwarded, promoted, checked int
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, ReadinessProof: proof,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(publisherproxy.ReadinessProbeHeader) != "" || !publisherproxy.IsReadinessProbe(r) {
				t.Error("unverified or unstripped readiness proof")
			}
			forwarded++
			w.WriteHeader(204)
		})})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	for _, test := range []struct {
		method, path, proof string
		status              int
	}{
		{"POST", "/health", secret, 403}, {"GET", "/health?x=1", secret, 403}, {"GET", "/other", secret, 403}, {"GET", "/health", "1", 403},
		{"GET", "/health", secret, 204}, {"GET", "/health", secret, 403},
	} {
		r := httptest.NewRequest(test.method, test.path, nil)
		r.Host = run.Hostname
		r.TLS = &tls.ConnectionState{ServerName: run.Hostname}
		r.Header.Set(publisherproxy.ReadinessProbeHeader, test.proof)
		r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, true))
		r = r.WithContext(context.WithValue(r.Context(), visitorSessionKey{}, &visitorSession{visitor: Visitor{Run: run}, guard: func(_ context.Context, v Visitor) error {
			if !v.Readiness {
				t.Error("verified readiness did not reach ownership guard")
			}
			checked++
			return nil
		}, promote: func(context.Context, Visitor) error { promoted++; return nil }}))
		w := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s %s: status=%d", test.method, test.path, w.Code)
		}
	}
	if forwarded != 1 || promoted != 0 || checked != 1 {
		t.Fatalf("forwarded=%d promoted=%d checked=%d", forwarded, promoted, checked)
	}
	other, _ := NewReadinessProof(run, "/health")
	r := httptest.NewRequest("GET", "/health", nil)
	r.Header.Set(publisherproxy.ReadinessProbeHeader, other.HeaderValue())
	run.Number++
	if other.consume(r, run) {
		t.Fatal("proof crossed publish runs")
	}
}

func TestReadinessProofForHTTPSTargetIsSingleUseAndPrivate(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get("Authorization") != "caller-value" || r.Header.Get(publisherproxy.ReadinessProbeHeader) != "" {
			t.Error("application auth or readiness credential separation failed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	options := publisherproxy.TargetOptions{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	if err := publisherproxy.PreflightWithOptions(t.Context(), upstream.URL, options); err != nil {
		t.Fatal(err)
	}
	if forwarded.Load() != 0 {
		t.Fatal("preflight sent an HTTP request to the target")
	}
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: certificateTestPublicURLID, Number: 8}
	proof, err := NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := publisherproxy.NewWithMountsHooksOptions(upstream.URL, run.Hostname, 1, nil, publisherproxy.ResponseHooks{}, options)
	if err != nil {
		t.Fatal(err)
	}
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, ReadinessProof: proof, Handler: proxy, AccessMode: "restricted"})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	secret := proof.HeaderValue()
	for _, want := range []int{http.StatusNoContent, http.StatusForbidden} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
		r.Host = run.Hostname
		r.TLS = &tls.ConnectionState{ServerName: run.Hostname}
		r.Header.Set(publisherproxy.ReadinessProbeHeader, secret)
		r.Header.Set("Authorization", "caller-value")
		r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, true))
		w := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("readiness status = %d, want %d", w.Code, want)
		}
	}
	if forwarded.Load() != 1 || proof.HeaderValue() != "" {
		t.Fatal("readiness proof was not consumed exactly once")
	}
}

func TestHTTPPromotionRunsOncePerVisitorAndBeforeTarget(t *testing.T) {
	var promoted atomic.Int32
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"),
		PromoteVisitor: func(_ context.Context, v Visitor) error {
			if v.Source.Addr().String() != "192.0.2.10" {
				t.Error("lost trusted visitor source")
			}
			promoted.Add(1)
			return nil
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if promoted.Load() != 1 {
				t.Error("forwarded before promotion")
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
	client := singleConnectionRouteClient(t, route, false)
	for range 2 {
		response, err := client.Get("https://route.example/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 204 {
			t.Fatalf("status=%d", response.StatusCode)
		}
	}
	if promoted.Load() != 1 {
		t.Fatalf("promotions=%d", promoted.Load())
	}
}

func TestHTTPPublisherAcceptsVerifiedTargetTLSServerName(t *testing.T) {
	certificate := publicURLTestCertificate(t, "target.internal")
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "target.internal" {
			t.Error("target TLS name missing")
		}
		w.WriteHeader(204)
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	target.StartTLS()
	defer target.Close()
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Target: target.URL, TargetTLSName: "target.internal", TargetOptions: publisherproxy.TargetOptions{RootCAs: rootsForCertificate(t, certificate)}})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "route.example"
	r.TLS = &tls.ConnectionState{ServerName: "route.example"}
	w := httptest.NewRecorder()
	route.http.Handler.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("publisher target TLS status=%d", w.Code)
	}
}
