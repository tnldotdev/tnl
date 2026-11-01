package publisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"go.opentelemetry.io/otel/trace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type publicAuthorizationObserver struct {
	ctx     context.Context
	metrics *observability.Metrics
	mu      sync.Mutex
	spans   []*tracepb.Span
}

func newPublicAuthorizationObserver(t *testing.T) *publicAuthorizationObserver {
	t.Helper()
	o := &publicAuthorizationObserver{}
	collector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var batch collectortrace.ExportTraceServiceRequest
		if r.URL.Path != "/v1/traces" || err != nil || proto.Unmarshal(body, &batch) != nil {
			http.Error(w, "invalid export", http.StatusBadRequest)
			return
		}
		o.mu.Lock()
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				o.spans = append(o.spans, scope.Spans...)
			}
		}
		o.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		response, _ := proto.Marshal(&collectortrace.ExportTraceServiceResponse{})
		_, _ = w.Write(response)
	}))
	t.Cleanup(collector.Close)
	certificate := filepath.Join(t.TempDir(), "collector.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: collector.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", collector.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", certificate)
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "60000")
	var err error
	o.ctx, o.metrics, err = observability.StartProcess(t.Context(), "publisher")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := o.metrics.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	o.ctx = observability.WithFields(o.ctx, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "public_endpoint", Exposure: "public"})
	return o
}

func (o *publicAuthorizationObserver) snapshot(t *testing.T) []*tracepb.Span {
	t.Helper()
	if err := o.metrics.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]*tracepb.Span(nil), o.spans...)
}

func publicAuthorizationCount(t *testing.T, m *observability.Metrics, family string, want map[string]string) uint64 {
	t.Helper()
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, point := range f.Metric {
			labels := map[string]string{}
			for _, label := range point.Label {
				labels[label.GetName()] = label.GetValue()
			}
			match := true
			for key, value := range want {
				match = match && labels[key] == value
			}
			if match {
				if point.Histogram != nil {
					count += point.GetHistogram().GetSampleCount()
				} else {
					count += uint64(point.GetCounter().GetValue())
				}
			}
		}
	}
	return count
}

func assertPublicAuthorizationDecision(t *testing.T, spans []*tracepb.Span, state, outcome, code string) {
	t.Helper()
	var operation, decision, request *tracepb.Span
	for _, span := range spans {
		switch span.Name {
		case "publisher.http":
			request = span
		case "publisher.visitor_authorization":
			if operation != nil {
				t.Fatal("local authorization operation finished more than once")
			}
			operation = span
		case "publisher.authorization":
			if decision != nil {
				t.Fatal("local authorization decision recorded more than once")
			}
			decision = span
		}
	}
	if request == nil || operation == nil || decision == nil || !bytes.Equal(operation.TraceId, request.TraceId) || !bytes.Equal(operation.ParentSpanId, request.SpanId) || !bytes.Equal(decision.TraceId, operation.TraceId) || !bytes.Equal(decision.ParentSpanId, operation.SpanId) {
		t.Fatal("local permission/bind did not export the exact HTTP -> authorization operation -> result parent chain")
	}
	for _, span := range []*tracepb.Span{operation, decision} {
		want := map[string]string{"tnl.component": "publisher", "tnl.service_protocol": "http", "tnl.access_path": "public_endpoint", "tnl.exposure": "public", "tnl.outcome": outcome, "tnl.operation": span.Name}
		if code != "" {
			want["error.type"] = code
		}
		if span == decision {
			want["tnl.state"] = state
		}
		for _, attr := range span.Attributes {
			value, ok := want[attr.Key]
			if !ok || attr.Value.GetStringValue() != value {
				t.Fatal("authorization exported an unapproved field or value", attr.Key)
			}
			delete(want, attr.Key)
		}
		if len(want) != 0 || len(span.Events) != 0 || span.Status.GetMessage() != "" && span.Status.GetMessage() != outcome {
			t.Fatal("authorization fields/status changed or included private cause context")
		}
	}
}

func TestPublicHTTPAuthorizationObservationRealPermissionAndBind(t *testing.T) {
	for _, scenario := range []string{"anonymous", "signed", "bad credential", "ambiguous credential", "IP denied", "expired", "revoked", "revoked key", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			o := newPublicAuthorizationObserver(t)
			policy, update, token := httpPermissionFixture(t, true)
			r := permissionRequest().WithContext(o.ctx)
			r.URL.Path = "/private-request-path"
			r.Header.Set("Authorization", "private-application-credential")
			state, outcome, code := "admitted", "success", ""
			status := http.StatusNoContent
			if scenario != "anonymous" {
				r.Header.Set(visitorTokenHeader, token.Reveal())
			}
			switch scenario {
			case "bad credential":
				r.Header.Set(visitorTokenHeader, "private-invalid-visitor-token")
			case "ambiguous credential":
				r.AddCookie(&http.Cookie{Name: visitorTokenCookie, Value: token.Reveal()})
			case "IP denied":
				ip, err := ippolicy.New([32]byte{1}, nil)
				if err != nil {
					t.Fatal(err)
				}
				update.IP = &ip
			case "expired":
				issued := time.Now().Add(-2 * time.Minute)
				key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
				expired, err := visitortoken.Sign(update.View.Issuer, "http", key, visitortoken.Permission{Scope: update.View.Scope, Hostname: update.View.Hostname, Port: 443, VisitorPolicyRevision: 1, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22)}, ExpiresAt: issued.Add(time.Minute)}, issued)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set(visitorTokenHeader, expired.Reveal())
			case "revoked":
				update.View.VisitorPolicyRevision++
			case "revoked key":
				update.KeyRevision++
				key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
				update.View = update.View.WithVerificationKeys(map[string]ed25519.PublicKey{"replacement": key.Public().(ed25519.PublicKey)})
			case "canceled":
				ctx, cancel := context.WithCancel(o.ctx)
				cancel()
				r = r.WithContext(ctx)
			}
			if err := policy.Apply(policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
			if scenario != "anonymous" && scenario != "signed" {
				state, outcome, code, status = "denied", "denied", string(diagnostic.VisitorAccessDenied), http.StatusForbidden
			}
			if scenario == "revoked key" {
				state, outcome, code = "failed", "error", string(diagnostic.ServerUnavailable)
			}
			if scenario == "canceled" {
				state, outcome, code = "failed", "canceled", observability.FailureCode(context.Canceled)
			}
			var parent trace.SpanContext
			forwarded := 0
			route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: update.View.Hostname, VisitorPolicy: policy,
				AdmitRequest: func(r *http.Request) error { parent = trace.SpanContextFromContext(r.Context()); return nil },
				Handler: http.HandlerFunc(func(w http.ResponseWriter, bound *http.Request) {
					forwarded++
					if !trace.SpanContextFromContext(bound.Context()).Equal(parent) || bound.Context().Done() == r.Context().Done() || bound.Header.Get(visitorTokenHeader) != "" || bound.Header.Get("Authorization") != "private-application-credential" {
						t.Error("authorization changed the HTTP parent, discarded guarded cancellation or altered application credentials")
					}
					if publicAuthorizationCount(t, o.metrics, "tnl_publisher_operation_duration_seconds", map[string]string{"tnl_operation": "visitor_authorization"}) != 1 {
						t.Error("authorization remained open during target handling")
					}
					w.WriteHeader(http.StatusNoContent)
				})})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			w := httptest.NewRecorder()
			serveTestPublicRequest(t, route, w, r)
			if w.Code != status || forwarded != map[bool]int{true: 1, false: 0}[status == http.StatusNoContent] {
				t.Fatal("permission result or target reachability changed", w.Code, forwarded)
			}
			assertPublicAuthorizationDecision(t, o.snapshot(t), state, outcome, code)
			if publicAuthorizationCount(t, o.metrics, "tnl_publisher_authorization_decisions_total", map[string]string{"tnl_state": state, "tnl_outcome": outcome}) != 1 {
				t.Fatal("authorization count/classification changed")
			}
		})
	}
}

func TestPublicHTTPAuthorizationObservationBindExpiryRetainsCause(t *testing.T) {
	o := newPublicAuthorizationObserver(t)
	base, armed, checks := time.Now(), false, 0
	policy, _, token := httpPermissionFixtureClock(t, true, func() time.Time {
		if armed {
			checks++
			if checks > 1 {
				return base.Add(time.Minute)
			}
		}
		return base
	})
	r := permissionRequest().WithContext(o.ctx)
	r.Header.Set(visitorTokenHeader, token.Reveal())
	armed = true
	var permission httpPermission
	var decisionErr error
	observability.PublisherHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var guard *publicHTTPGuard
		var guarded *http.Request
		permission, guard, guarded, decisionErr = authorizeHTTPRequest(w, r, policy, nil)
		if guard != nil || guarded != nil {
			t.Error("expired bind created a request guard")
		}
	})).ServeHTTP(httptest.NewRecorder(), r)
	if !permission.permission.Valid() || !errors.Is(decisionErr, visitortoken.ErrPolicy) {
		t.Fatal("did not verify the real signed token before the current bind failed", decisionErr)
	}
	assertPublicAuthorizationDecision(t, o.snapshot(t), "denied", "denied", string(diagnostic.VisitorAccessDenied))
}

func TestPublicHTTPAuthorizationObservationSkipsReadinessAndSeparatesCapacity(t *testing.T) {
	m := observability.New("publisher")
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	ctx := observability.WithMetrics(t.Context(), m)
	run := PublishRunIdentity{Hostname: "route.example", PublicURLID: certificateTestPublicURLID, PublishRunID: "pr_0123456789abcdefghijkl", Number: 1}
	proof, err := NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	forwarded := 0
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: run.Hostname, PublicURLID: run.PublicURLID, PublishRunNumber: run.Number, ReadinessProof: proof, Limits: ApplicationLimits{Requests: 1}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded++; w.WriteHeader(204) })})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	request := func(path, secret string) int {
		r := permissionRequest().WithContext(ctx)
		r.Host, r.TLS.ServerName, r.URL.Path = run.Hostname, run.Hostname, path
		r.RequestURI = path
		if secret != "" {
			r.Header.Set(publisherproxy.ReadinessProbeHeader, secret)
		}
		w := httptest.NewRecorder()
		serveTestPublicRequest(t, route, w, r)
		return w.Code
	}
	if request("/health", proof.HeaderValue()) != 204 || publicAuthorizationCount(t, m, "tnl_publisher_authorization_decisions_total", nil) != 0 {
		t.Fatal("readiness fabricated ordinary permission or spent application capacity")
	}
	if request("/", "") != 204 || request("/", "") != 503 || forwarded != 2 {
		t.Fatal("application capacity behavior changed", forwarded)
	}
	if publicAuthorizationCount(t, m, "tnl_publisher_authorization_decisions_total", map[string]string{"tnl_state": "admitted", "tnl_outcome": "success"}) != 2 {
		t.Fatal("capacity rejection was confused with a permission denial or nil hook synthesized an event")
	}
}

func TestPublicHTTPAuthorizationObservationRealPromotionKeepsLifetimeParent(t *testing.T) {
	o := newPublicAuthorizationObserver(t)
	var promoted int
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Context: o.ctx, Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"),
		PromoteVisitor: func(_ context.Context, visitor Visitor) error {
			if visitor.Readiness || visitor.Source.Addr().String() != "192.0.2.10" {
				t.Error("promotion lost its real visitor/source binding")
			}
			promoted++
			return nil
		}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if promoted != 1 {
				t.Error("target reached before the shared promotion completed exactly once")
			}
			w.WriteHeader(http.StatusNoContent)
		})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	handled := make(chan struct{})
	var dialed atomic.Bool
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, *route.certificate.Load())},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("test attempted to replace its visitor connection")
			}
			return openHTTPTestRouteServer(route, handled)
		}}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = route.Close()
		if dialed.Load() {
			awaitPublisherTest(t, handled)
		}
	})
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for range 2 {
		response, err := client.Get("https://route.example/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("promoted request failed", response.StatusCode)
		}
	}
	client.CloseIdleConnections()
	if err := route.Close(); err != nil {
		t.Fatal(err)
	}
	awaitPublisherTest(t, handled)
	spans := o.snapshot(t)
	parents := map[string]*tracepb.Span{}
	for _, span := range spans {
		parents[string(span.SpanId)] = span
	}
	var requests, lifetimes int
	for _, span := range spans {
		if span.Name != "publisher.authorization" {
			continue
		}
		operation := parents[string(span.ParentSpanId)]
		if operation == nil || operation.Name != "publisher.visitor_authorization" || !bytes.Equal(span.TraceId, operation.TraceId) {
			t.Fatal("promotion/result lost exact parentage")
		}
		parent := parents[string(operation.ParentSpanId)]
		if parent == nil || !bytes.Equal(parent.TraceId, span.TraceId) {
			t.Fatal("authorization lost its real visitor trace")
		}
		switch parent.Name {
		case "publisher.http":
			requests++
		case "publisher.visitor":
			lifetimes++
		default:
			t.Fatal("authorization was reparented away from its request/lifetime owner", parent.Name)
		}
	}
	if requests != 2 || lifetimes != 1 || promoted != 1 {
		t.Fatal("local permission and actual shared promotion were conflated", requests, lifetimes, promoted)
	}
}
