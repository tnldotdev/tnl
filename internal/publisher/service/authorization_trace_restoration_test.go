package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/testutil/workerobservation"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// keep the existing collector and its cleanup, but record publisher instruments
// with a publisher owner; the control owner's sdk view deliberately drops them.
func observationPublisher(t *testing.T) (context.Context, *workerobservation.Recorder) {
	t.Helper()
	ctx, recorder := workerobservation.Start(t)
	ctx, owner, err := observability.StartProcess(ctx, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	recorder.Owner = owner
	t.Cleanup(func() {
		if err := owner.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return ctx, recorder
}

func observationMetricCount(t *testing.T, owner *observability.Metrics, name string, want map[string]string) uint64 {
	t.Helper()
	families, err := owner.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, point := range family.Metric {
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

func observationHTTPContext(ctx context.Context) context.Context {
	return observability.WithFields(ctx, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "public_endpoint", Exposure: "public"})
}

// borrow the existing HTTP fixture's policy, frontend and target; only supply
// the process observation context that its ordinary caller does not need.
func observationHTTPFixture(t *testing.T, owner context.Context, handler http.Handler, h2, inline bool, configure func(*HTTP)) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token, func()) {
	t.Helper()
	var frontend HTTP
	var target servicestream.HTTPTarget
	_, policy, update, token := serviceHTTPConfiguredFixture(t, handler, h2, inline, func(f *HTTP) {
		if configure != nil {
			configure(f)
		}
		frontend = *f
	}, func(application *servicestream.HTTPTarget) { target = *application })
	certificate := visitorfixture.Certificate(t, frontend.Hostname)
	type connection struct {
		raw  net.Conn
		done <-chan error
	}
	var mu sync.Mutex
	var connections []connection
	transport := &http.Transport{ForceAttemptHTTP2: h2, MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			visitor, raw := net.Pipe()
			server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
			done := make(chan error, 1)
			mu.Lock()
			connections = append(connections, connection{visitor, done})
			mu.Unlock()
			go func() {
				defer server.Close()
				done <- frontend.Forward(owner, server, target)
			}()
			return visitor, nil
		}}
	stop := sync.OnceFunc(func() {
		transport.CloseIdleConnections()
		mu.Lock()
		all := append([]connection(nil), connections...)
		mu.Unlock()
		for _, c := range all {
			_ = c.raw.Close()
			claimedAwait(t, c.done)
		}
	})
	t.Cleanup(stop)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, policy, update, token, stop
}

func assertObservationAuthorization(t *testing.T, recorder *workerobservation.Recorder, state, outcome, code string) {
	t.Helper()
	requests := recorder.Attempts(t, "publisher.http")
	operations := recorder.Attempts(t, "publisher.visitor_authorization")
	decisions := recorder.Attempts(t, "publisher.authorization")
	if len(requests) != 1 || len(operations) != 1 || len(decisions) != 1 {
		t.Fatal("authorization did not finish exactly once per HTTP request", len(requests), len(operations), len(decisions))
	}
	request, operation, decision := requests[0], operations[0], decisions[0]
	if !bytes.Equal(operation.TraceId, request.TraceId) || !bytes.Equal(operation.ParentSpanId, request.SpanId) ||
		!bytes.Equal(decision.TraceId, operation.TraceId) || !bytes.Equal(decision.ParentSpanId, operation.SpanId) ||
		operation.EndTimeUnixNano > request.EndTimeUnixNano || decision.EndTimeUnixNano > operation.EndTimeUnixNano {
		t.Fatal("permission/bind lost HTTP -> operation -> result parentage or completion order")
	}
	for _, span := range []*tracepb.Span{operation, decision} {
		want := map[string]string{"tnl.component": "publisher", "tnl.service_protocol": "http", "tnl.access_path": "public_endpoint",
			"tnl.exposure": "public", "tnl.outcome": outcome, "tnl.operation": span.Name}
		if span == decision {
			want["tnl.state"] = state
		}
		if code != "" {
			want["error.type"] = code
		}
		for _, attr := range span.Attributes {
			value, ok := want[attr.Key]
			if !ok || attr.Value.GetStringValue() != value {
				t.Fatal("permission observation exported an unapproved field/value", attr.Key)
			}
			delete(want, attr.Key)
		}
		wantStatus := tracepb.Status_STATUS_CODE_UNSET
		if outcome != "success" && outcome != "canceled" {
			wantStatus = tracepb.Status_STATUS_CODE_ERROR
		}
		if len(want) != 0 || len(span.Events) != 0 || span.Status.GetCode() != wantStatus ||
			span.Status.GetMessage() != "" && span.Status.GetMessage() != outcome {
			t.Fatal("permission observation lost safe fields/status or retained private cause context", span)
		}
	}
}

func TestServiceAuthorizationTraceRestorationRealPermissionAndBind(t *testing.T) {
	for _, scenario := range []string{"anonymous", "signed", "bad credential", "ambiguous credential", "IP denied", "expired", "revoked", "revoked key", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, recorder := observationPublisher(t)
			ctx = observationHTTPContext(ctx)
			var parent trace.SpanContext
			var unguarded <-chan struct{}
			var forwarded atomic.Int32
			client, policy, update, token, stop := observationHTTPFixture(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				if !trace.SpanContextFromContext(r.Context()).Equal(parent) || r.Context().Done() == unguarded ||
					r.Header.Get(httpaccess.VisitorTokenHeader) != "" || r.Header.Get("Authorization") != "private-application-credential" {
					t.Error("binding changed the HTTP parent, guarded cancellation, or application credentials")
				}
				if observationMetricCount(t, recorder.Owner, "tnl_publisher_operation_duration_seconds", map[string]string{"tnl_operation": "visitor_authorization"}) != 1 {
					t.Error("authorization operation remained open during target handling")
				}
				w.WriteHeader(http.StatusNoContent)
			}), false, true, func(f *HTTP) {
				f.AdmitRequest = func(r *http.Request) error {
					parent, unguarded = trace.SpanContextFromContext(r.Context()), r.Context().Done()
					if scenario == "canceled" {
						canceled, cancel := context.WithCancel(r.Context())
						cancel()
						*r = *r.WithContext(canceled)
					}
					return nil
				}
			})
			update.Anonymous = true
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/private-request-path?token=private-query", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "private-application-credential")
			if scenario != "anonymous" {
				request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
			}
			switch scenario {
			case "bad credential":
				request.Header.Set(httpaccess.VisitorTokenHeader, "private-invalid-visitor-token")
			case "ambiguous credential":
				request.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: token.Reveal()})
			case "IP denied":
				ip, err := ippolicy.New([32]byte{1}, nil)
				if err != nil {
					t.Fatal(err)
				}
				update.IP = &ip
			case "expired":
				issued := time.Now().Add(-2 * time.Minute)
				key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
				expired, err := visitortoken.Sign(update.View.Issuer, "http", key, visitortoken.Permission{
					Scope: update.View.Scope, Hostname: update.View.Hostname, Port: 443, VisitorPolicyRevision: 1,
					Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22)}, ExpiresAt: issued.Add(time.Minute)}, issued)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set(httpaccess.VisitorTokenHeader, expired.Reveal())
			case "revoked":
				update.View.VisitorPolicyRevision++
			case "revoked key":
				update.KeyRevision++
				key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
				update.View = update.View.WithVerificationKeys(map[string]ed25519.PublicKey{"replacement": key.Public().(ed25519.PublicKey)})
			}
			if err := policy.Apply(policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
			state, outcome, code, status := "admitted", "success", "", http.StatusNoContent
			if scenario != "anonymous" && scenario != "signed" {
				state, outcome, code, status = "denied", "denied", string(diagnostic.VisitorAccessDenied), http.StatusForbidden
			}
			if scenario == "revoked key" {
				state, outcome, code, status = "failed", "error", string(diagnostic.ServerUnavailable), http.StatusServiceUnavailable
			}
			if scenario == "canceled" {
				state, outcome, code = "failed", "canceled", observability.FailureCode(context.Canceled)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("permission did not return its HTTP decision", err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			stop()
			wantForwarded := int32(0)
			if status == http.StatusNoContent {
				wantForwarded = 1
			}
			if response.StatusCode != status || forwarded.Load() != wantForwarded {
				t.Fatal("permission result or target reachability changed", response.StatusCode, forwarded.Load())
			}
			assertObservationAuthorization(t, recorder, state, outcome, code)
			if observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", map[string]string{"tnl_state": state, "tnl_outcome": outcome}) != 1 ||
				observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", nil) != 1 {
				t.Fatal("permission count/classification changed")
			}
		})
	}
}

func TestServiceAuthorizationTraceRestorationBindExpiryRetainsVerifiedFacts(t *testing.T) {
	ctx, recorder := observationPublisher(t)
	base, armed, checks := time.Now(), false, 0
	policy, _, token := visitorfixture.PolicyClock(t, false, func() time.Time {
		if armed {
			checks++
			if checks > 1 {
				return base.Add(time.Minute)
			}
		}
		return base
	})
	request := visitorfixture.Request().WithContext(observationHTTPContext(ctx))
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	armed = true
	var authorization httpaccess.Authorization
	var decisionErr error
	observability.PublisherHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var guard *httpaccess.Guard
		var guarded *http.Request
		authorization, guard, guarded, decisionErr = httpaccess.AuthorizeRequest(w, r, policy, nil)
		if guard != nil || guarded != nil {
			t.Error("expired bind created a request guard")
		}
	})).ServeHTTP(httptest.NewRecorder(), request)
	if bearer, ok := authorization.BearerToken(); !authorization.Permission().Valid() || !errors.Is(decisionErr, visitortoken.ErrPolicy) || ok || bearer != "" {
		t.Fatal("bind expiry lost verified facts/cause or exposed an accepted credential", decisionErr)
	}
	assertObservationAuthorization(t, recorder, "denied", "denied", string(diagnostic.VisitorAccessDenied))
}

func TestServiceAuthorizationTraceRestorationReadinessAndCapacityStaySeparate(t *testing.T) {
	ctx, recorder := observationPublisher(t)
	var proof *httpaccess.ReadinessProof
	var forwarded atomic.Int32
	client, _, _, token, stop := observationHTTPFixture(t, observationHTTPContext(ctx), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
			t.Error("readiness secret reached the application")
		}
		w.WriteHeader(http.StatusNoContent)
	}), false, true, func(f *HTTP) {
		var err error
		proof, err = httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: f.Subject, ID: f.RunID, Number: uint64(f.Number), Hostname: f.Hostname}, "/health")
		if err != nil {
			t.Fatal(err)
		}
		f.ReadinessProof = proof
		f.probes, err = requestlimit.NewHTTP(nil)
		if err != nil {
			t.Fatal(err)
		}
		f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1)})
		if err != nil {
			t.Fatal(err)
		}
	})
	visit := func(path, secret string, want int) {
		t.Helper()
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
		if secret != "" {
			request.Header.Set(httpstream.ReadinessProbeHeader, secret)
		} else {
			request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatal("readiness/application capacity response changed", response.StatusCode, want)
		}
	}
	visit("/health", proof.HeaderValue(), http.StatusNoContent)
	if observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", nil) != 0 {
		t.Fatal("owner readiness fabricated ordinary authorization")
	}
	visit("/", "", http.StatusNoContent)
	visit("/", "", http.StatusServiceUnavailable)
	stop()
	if forwarded.Load() != 2 ||
		observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", nil) != 2 ||
		observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", map[string]string{"tnl_state": "admitted", "tnl_outcome": "success"}) != 2 {
		t.Fatal("capacity rejection became a permission denial or readiness spent the application budget")
	}
	if len(recorder.Attempts(t, "publisher.visitor_authorization")) != 2 || len(recorder.Attempts(t, "publisher.authorization")) != 2 {
		t.Fatal("readiness or a nil admission hook synthesized an authorization")
	}
}

func TestServiceAuthorizationTraceRestorationTwoRequestsKeepSeparateParentsAndOneCapacityOwner(t *testing.T) {
	ctx, recorder := observationPublisher(t)
	f := newSourceForwardingFixture(t)
	ctx = observationHTTPContext(ctx)
	ctx, finish := observability.Start(ctx, "fixture.capacity_owner")
	defer finish(nil)
	ownerSpan := trace.SpanContextFromContext(ctx)
	var requests, capacity atomic.Int32
	capacityContext := make(chan context.Context, 1)
	f.prepared.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		number := requests.Add(1)
		if capacity.Load() != 1 || observationMetricCount(t, recorder.Owner, "tnl_publisher_operation_duration_seconds",
			map[string]string{"tnl_operation": "visitor_authorization"}) != uint64(number) {
			t.Error("target overtook its completed authorization or shared capacity decision")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	visitor, server := net.Pipe()
	header := f.header
	ref := f.prepared.connectionRef(f.bound.connections[0])
	owned, code := f.bound.reserveHTTP(ctx, ref, server, header)
	if owned == nil {
		t.Fatal("real public HTTP owner did not register its pending stream", code)
	}
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		err := f.bound.serveBody(owned.http.ctx, ref, owned, header, nil, func(call context.Context) error {
			capacity.Add(1)
			capacityContext <- call
			return nil
		}, owned)
		done <- errors.Join(err, owned.http.retire())
	}()
	var dialed atomic.Int32
	transport := &http.Transport{MaxConnsPerHost: 1, TLSClientConfig: f.verification.Clone(),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Add(1) != 1 {
				return nil, errors.New("test attempted to replace its registered TLS visitor")
			}
			if err := visitor.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return nil, err
			}
			if _, err := visitor.Write(f.metadata); err != nil {
				return nil, err
			}
			return visitor, nil
		}}
	stop := sync.OnceFunc(func() {
		transport.CloseIdleConnections()
		_ = visitor.Close()
		claimedAwait(t, done)
	})
	t.Cleanup(stop)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for range 2 {
		response, err := client.Get("https://" + f.prepared.managedHostname + "/")
		if err != nil {
			t.Fatal("registered HTTP visitor could not reach its inline application", err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent {
			t.Fatal("shared visitor changed an application response", response.Status, readErr, closeErr)
		}
	}
	stop()
	call := claimedAwait(t, capacityContext)
	if capacity.Load() != 1 || requests.Load() != 2 || dialed.Load() != 1 ||
		!trace.SpanContextFromContext(call).Equal(ownerSpan) || observability.FromContext(call) != recorder.Owner {
		t.Fatal("capacity borrowed a request's lifetime or ran more than once")
	}
	operations := recorder.Attempts(t, "publisher.visitor_authorization")
	decisions := recorder.Attempts(t, "publisher.authorization")
	httpRequests := recorder.Attempts(t, "publisher.http")
	visitors := recorder.Attempts(t, "publisher.visitor")
	if len(operations) != 2 || len(decisions) != 2 || len(httpRequests) != 2 || len(visitors) != 1 {
		t.Fatal("two request authorizations and one registered visitor lifetime were conflated",
			len(operations), len(decisions), len(httpRequests), len(visitors))
	}
	parents := map[string]*tracepb.Span{}
	for _, span := range append(append(operations, decisions...), httpRequests...) {
		parents[string(span.SpanId)] = span
	}
	seen := map[string]bool{}
	for _, decision := range decisions {
		operation := parents[string(decision.ParentSpanId)]
		if operation == nil || operation.Name != "publisher.visitor_authorization" || !bytes.Equal(decision.TraceId, operation.TraceId) {
			t.Fatal("request decision lost its exact authorization parent")
		}
		request := parents[string(operation.ParentSpanId)]
		if request == nil || request.Name != "publisher.http" || !bytes.Equal(request.TraceId, operation.TraceId) || seen[string(request.SpanId)] {
			t.Fatal("two request decisions shared or lost their HTTP parent")
		}
		seen[string(request.SpanId)] = true
	}
	// the current capacity owner is not an authority decision. it retains the
	// registered connection's original context rather than inventing a third
	// authorization span beneath either request.
	if observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", nil) != 2 {
		t.Fatal("connection capacity fabricated an extra permission decision")
	}
	f.bound.mu.Lock()
	defer f.bound.mu.Unlock()
	if f.bound.reservedStreams != 0 || len(f.bound.active) != 0 || f.bound.httpPending != 0 ||
		len(f.bound.httpPendingSources) != 0 || len(f.bound.httpPendingRelays) != 0 {
		t.Fatal("joined registered visitor retained its physical capacity or pending source")
	}
}
