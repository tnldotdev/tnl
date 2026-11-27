package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// preserve the configured frontend and its real policy/capacity owners. callers
// change only the HTTP facts explicitly under test, before any visitor opens.
func compositionHTTPFrontend(t *testing.T, f *pendingHTTPFixture, change func(*HTTP)) {
	t.Helper()
	original := f.source.prepared.managedVisitor
	f.source.prepared.managedVisitor = func(header tunnelv1.ServiceForwardingHeader, source netip.AddrPort, reserve func(context.Context) error) servicestream.Authentication {
		visitor, ok := original(header, source, reserve).(servicestream.HTTPVisitor)
		if !ok {
			t.Error("composition fixture lost its configured HTTP visitor")
			return nil
		}
		frontend, ok := visitor.Frontend.(HTTP)
		if !ok {
			t.Error("composition fixture lost its service HTTP frontend")
			return nil
		}
		change(&frontend)
		visitor.Frontend = frontend
		return visitor
	}
}

type compositionHTTPClient struct {
	visitor   *pendingHTTPVisitor
	roundTrip func(*http.Request) (*http.Response, error)
}

// hand the verified socket to the standard client's single-connection API.
// neither setup nor later requests may dial or substitute another connection.
func compositionHTTP2Connection(t *testing.T, ctx context.Context, socket *tls.Conn, hostname string) *http.ClientConn {
	t.Helper()
	address := net.JoinHostPort(hostname, "443")
	var handedOff atomic.Bool
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		Protocols: protocols,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Error("same-socket HTTP/2 fixture attempted a new dial")
			return nil, errors.New("same-socket HTTP/2 fixture cannot dial")
		},
		DialTLSContext: func(call context.Context, network, requested string) (net.Conn, error) {
			if network != "tcp" || requested != address || !handedOff.CompareAndSwap(false, true) {
				t.Error("same-socket HTTP/2 fixture changed or repeated its socket handoff")
				return nil, errors.New("same-socket HTTP/2 socket handoff is invalid")
			}
			if err := context.Cause(call); err != nil {
				return nil, err
			}
			return socket, nil
		},
	}
	connection, err := transport.NewClientConn(ctx, "https", address)
	if err != nil {
		t.Fatal(err)
	}
	if !handedOff.Load() {
		t.Fatal("HTTP/2 client did not take the verified fixture socket")
	}
	return connection
}

func newCompositionHTTPClient(t *testing.T, f *pendingHTTPFixture, slot uint8, h2 bool, change ...func(*tunnelv1.ServiceForwardingHeader)) *compositionHTTPClient {
	t.Helper()
	v, err := f.open(t, slot, pendingHTTPSource(int(slot)), func(header *tunnelv1.ServiceForwardingHeader) {
		for _, apply := range change {
			apply(header)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("set original HTTP visitor wire bound", err)
	}
	if _, err := v.raw.Write(f.metadata(t, v.header, v.source, false)); err != nil {
		t.Fatal(err)
	}
	verification := f.source.verification.Clone()
	verification.NextProtos = []string{"http/1.1"}
	if h2 {
		verification.NextProtos = []string{"h2"}
	}
	v.secure = tls.Client(v.raw, verification)
	if err := v.secure.HandshakeContext(f.ctx); err != nil {
		t.Fatal("composition fixture lost verified visitor TLS", err)
	}
	if v.secure.ConnectionState().NegotiatedProtocol != verification.NextProtos[0] {
		t.Fatal("composition fixture negotiated the wrong HTTP protocol")
	}
	client := &compositionHTTPClient{visitor: v}
	if h2 {
		connection := compositionHTTP2Connection(t, f.ctx, v.secure, f.source.prepared.managedHostname)
		// this client owns exactly this TLS socket, with no replacement dial.
		client.roundTrip = connection.RoundTrip
		t.Cleanup(func() { v.close(); _ = connection.Close() })
	} else {
		v.reader = bufio.NewReader(v.secure)
		client.roundTrip = func(request *http.Request) (*http.Response, error) {
			if err := request.Write(v.secure); err != nil {
				return nil, err
			}
			return http.ReadResponse(v.reader, request)
		}
	}
	return client
}

func (c *compositionHTTPClient) request(t *testing.T, method, path, authority, permission, proof string) *http.Response {
	t.Helper()
	f := c.visitor.fixture
	request, err := http.NewRequestWithContext(f.ctx, method, "https://"+f.source.prepared.managedHostname+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authority != "" {
		request.Host = authority
	}
	request.Header.Set("Authorization", "Bearer unchanged-application")
	request.Header.Set("Accept", "text/html")
	if permission != "" {
		request.Header.Set(httpaccess.VisitorTokenHeader, permission)
	}
	if proof != "" {
		request.Header.Set(httpstream.ReadinessProbeHeader, proof)
	}
	response, err := c.roundTrip(request)
	if err != nil {
		t.Fatal("same-socket composition request failed", err)
	}
	return response
}

func TestServiceHTTPCompositionMisdirectedHTTP2RetryKeepsConnection(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	client := newCompositionHTTPClient(t, f, 0, true)
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/", "", "", ""), http.StatusNoContent)
	response := client.request(t, http.MethodGet, "/", "sibling.example.test", "", "")
	body, err := io.ReadAll(response.Body)
	err = errors.Join(err, response.Body.Close())
	if err != nil || response.ProtoMajor != 2 || response.StatusCode != http.StatusMisdirectedRequest ||
		response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_MISDIRECTED" ||
		!strings.Contains(string(body), "retry on a new connection") || response.Close {
		t.Fatal("misdirected HTTP/2 response lost its retry contract", response.Status, response.Header, string(body), err)
	}
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("misdirected stream reached the app or repeated ingress capacity")
	}
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/after-misdirection", "", "", ""), http.StatusNoContent)
	if f.calls.Load() != 2 || f.capacity.Load() != 1 {
		t.Fatal("misdirection retired or re-admitted the original HTTP/2 connection")
	}
	assertHTTPAdmissionCharges(t, client.visitor.admission, 0, 0, 1)
}

func TestServiceHTTPAdmissionSurvivesCanceledFirstRequestPastSetupDeadline(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	entered, released, waiterLeft := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	f.ingressMu.Lock()
	f.ingress = func(call context.Context) error {
		close(entered)
		select {
		case <-released:
			return nil
		case <-call.Done():
			return context.Cause(call)
		}
	}
	f.ingressMu.Unlock()
	compositionHTTPFrontend(t, f, func(frontend *HTTP) {
		reserve := frontend.ReserveCapacity
		left := sync.OnceFunc(func() { close(waiterLeft) })
		frontend.ReserveCapacity = func(call context.Context) error {
			err := reserve(call)
			if call.Err() != nil {
				left()
			}
			return err
		}
	})
	client := newCompositionHTTPClient(t, f, 0, true, func(header *tunnelv1.ServiceForwardingHeader) {
		header.ExpiresAt = time.Now().Add(2 * time.Second)
	})
	before := f.current[0].wire.openings.Load()
	first, cancel := context.WithCancel(f.ctx)
	defer cancel()
	request, _ := http.NewRequestWithContext(first, http.MethodGet, "https://"+f.source.prepared.managedHostname+"/canceled", nil)
	request.Header.Set("Authorization", "Bearer unchanged-application")
	finished := make(chan error, 1)
	go func() {
		response, err := client.roundTrip(request)
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		finished <- err
	}()
	claimedAwait(t, entered)
	cancel()
	if err := claimedAwait(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatal("first HTTP/2 request did not leave independently", err)
	}
	claimedAwait(t, waiterLeft)
	release()
	a := client.visitor.admission
	a.bound.mu.Lock()
	decision := a.decision
	a.bound.mu.Unlock()
	claimedAwait(t, decision.done)
	if decision.result != nil {
		t.Fatal("request cancellation damaged connection admission", decision.result)
	}
	assertHTTPAdmissionCharges(t, a, 0, 0, 1)
	// the connection was admitted on time, but no request observed that success.
	// its next request must reuse the decision after the setup deadline passes.
	timer := time.NewTimer(time.Until(client.visitor.header.ExpiresAt))
	defer timer.Stop()
	claimedAwait(t, timer.C)
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/after-setup", "", "", ""), http.StatusNoContent)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 || f.current[0].wire.openings.Load()-before != 1 {
		t.Fatal("later HTTP/2 request repeated admission or lost the original socket")
	}
	client.visitor.close()
	client.visitor.join(t)
	assertHTTPAdmissionCharges(t, a, 0, 0, 0)
}

func TestServiceHTTPFailedAdmissionRetiresHTTP2Connection(t *testing.T) {
	for _, code := range []tunnelv1.ErrorCode{tunnelv1.CapacityExceeded, tunnelv1.Unavailable} {
		t.Run(string(code), func(t *testing.T) {
			f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			f.ingressMu.Lock()
			f.ingress = func(context.Context) error { return &tunnel.ProtocolError{Code: code} }
			f.ingressMu.Unlock()
			client := newCompositionHTTPClient(t, f, 0, true)
			response := client.request(t, http.MethodGet, "/rejected", "", "", "")
			pendingHTTPResponse(t, response, http.StatusServiceUnavailable)
			client.visitor.join(t)
			assertHTTPAdmissionCharges(t, client.visitor.admission, 0, 0, 0)
			f.ingressMu.Lock()
			f.ingress = nil
			f.ingressMu.Unlock()
			request, _ := http.NewRequestWithContext(f.ctx, http.MethodGet, "https://"+f.source.prepared.managedHostname+"/old", nil)
			if response, err := client.roundTrip(request); err == nil {
				_ = response.Body.Close()
				t.Fatal("failed HTTP/2 admission left a reusable connection")
			}
			if f.calls.Load() != 0 || f.capacity.Load() != 1 {
				t.Fatal("failed connection retried admission or reached the application")
			}
			fresh := newCompositionHTTPClient(t, f, 0, true)
			pendingHTTPResponse(t, fresh.request(t, http.MethodGet, "/fresh", "", "", ""), http.StatusNoContent)
			if f.calls.Load() != 1 || f.capacity.Load() != 2 {
				t.Fatal("retired connection did not release capacity for a fresh visitor")
			}
		})
	}
}

func TestServiceHTTPCompositionVerifiedTLSGetThenHeadDenial(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1-closes", true: "http2-same-socket"}[h2], func(t *testing.T) {
			f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("denied visitor reached the application")
			}))
			update := f.source.update
			update.Anonymous = false
			update.View.VisitorPolicyRevision++
			now := time.Now()
			update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
			if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
			client := newCompositionHTTPClient(t, f, 0, h2)
			for index, method := range []string{http.MethodGet, http.MethodHead} {
				if index != 0 && !h2 {
					// the current HTTP/1 denial deliberately closes its socket.
					client.visitor.join(t)
					client = newCompositionHTTPClient(t, f, 0, false)
				}
				response := client.request(t, method, "/", "", "", "")
				body, err := io.ReadAll(response.Body)
				err = errors.Join(err, response.Body.Close())
				protocol := 1
				if h2 {
					protocol = 2
				}
				if err != nil || response.StatusCode != http.StatusForbidden ||
					response.Header.Get("Tnl-Error-Code") != "TNL_VISITOR_ACCESS_DENIED" ||
					!strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") ||
					response.Close == h2 || response.ProtoMajor != protocol {
					t.Fatal("verified TLS denial changed its representation or connection policy", response.Status, response.Header, err)
				}
				if method == http.MethodGet && !strings.Contains(string(body), "ask its owner for a link") ||
					method == http.MethodHead && len(body) != 0 {
					t.Fatal("GET/HEAD denial body changed", method, string(body))
				}
			}
			if f.calls.Load() != 0 || f.capacity.Load() != 0 {
				t.Fatal("denied TLS requests spent application or ingress capacity")
			}
		})
	}
}

func compositionHTTPProof(t *testing.T, f *pendingHTTPFixture) (*httpaccess.ReadinessProof, *requestlimit.HTTP) {
	t.Helper()
	p := f.source.prepared
	view, _, _ := p.policy.Current()
	proof, err := httpaccess.NewReadinessProof(httpaccess.ReadinessRun{
		Subject: view.Scope, ID: p.Preparation.ServiceRunId, Number: uint64(p.Preparation.RunNumber), Hostname: p.managedHostname,
	}, "/health")
	if err != nil {
		t.Fatal(err)
	}
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{
		Total: new(1), Concurrency: new(1), Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	probes, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
	if err != nil {
		t.Fatal(err)
	}
	compositionHTTPFrontend(t, f, func(frontend *HTTP) {
		frontend.ReadinessProof, frontend.probes, frontend.Requests = proof, probes, budget
	})
	return proof, budget
}

func TestServiceHTTPCompositionOwnerProbeDoesNotWaitForHeldOrdinaryAdmission(t *testing.T) {
	var probes, applications atomic.Int32
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if httpstream.IsReadinessProbe(r) {
			probes.Add(1)
		} else {
			applications.Add(1)
		}
		if r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
			t.Error("owner proof reached the application")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	proof, budget := compositionHTTPProof(t, f)
	entered, released := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	f.ingressMu.Lock()
	f.ingress = func(call context.Context) error {
		close(entered)
		select {
		case <-released:
			return nil
		case <-call.Done():
			return context.Cause(call)
		}
	}
	f.ingressMu.Unlock()
	client := newCompositionHTTPClient(t, f, 0, true)
	request, _ := http.NewRequestWithContext(f.ctx, http.MethodGet, "https://"+f.source.prepared.managedHostname+"/app", nil)
	request.Header.Set("Authorization", "Bearer unchanged-application")
	type reply struct {
		response *http.Response
		err      error
	}
	ordinary := make(chan reply, 1)
	go func() { response, err := client.roundTrip(request); ordinary <- reply{response, err} }()
	joinOrdinary := sync.OnceValue(func() reply { return claimedAwait(t, ordinary) })
	t.Cleanup(func() {
		release()
		outcome := joinOrdinary()
		if outcome.response != nil {
			_ = outcome.response.Body.Close()
		}
	})
	claimedAwait(t, entered)
	secret := proof.HeaderValue()
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/health", "", "", secret), http.StatusNoContent)
	if probes.Load() != 1 || applications.Load() != 0 || f.capacity.Load() != 1 || proof.HeaderValue() != "" {
		t.Fatal("owner probe borrowed or repeated the held ordinary admission")
	}
	select {
	case <-budget.Completed():
		t.Fatal("owner probe spent the held application's one-request budget")
	case <-released:
		t.Fatal("probe fixture released ordinary capacity before the probe finished")
	default:
	}
	release()
	// the cleanup owns the ordinary result even if the probe assertion fails.
	outcome := joinOrdinary()
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	pendingHTTPResponse(t, outcome.response, http.StatusNoContent)
	serviceHTTPAwait(t, budget.Completed())
	if applications.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("ordinary request did not finish its original admission")
	}
}

func TestServiceHTTPCompositionProbeThenCachedApplicationRejection(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1-closes", true: "http2-closes"}[h2], func(t *testing.T) {
			f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !httpstream.IsReadinessProbe(r) {
					t.Error("ordinary request bypassed the relay's capacity rejection")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			proof, _ := compositionHTTPProof(t, f)
			f.ingressMu.Lock()
			f.ingress = func(context.Context) error { return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded} }
			f.ingressMu.Unlock()
			client := newCompositionHTTPClient(t, f, 0, h2)
			before := f.current[0].wire.openings.Load()
			pendingHTTPResponse(t, client.request(t, http.MethodGet, "/health", "", "", proof.HeaderValue()), http.StatusNoContent)
			if f.calls.Load() != 1 || f.capacity.Load() != 0 || f.current[0].wire.openings.Load() != before {
				t.Fatal("owner probe spent ordinary connection admission")
			}
			for attempt := range 2 {
				if attempt != 0 {
					client.visitor.join(t)
					// the old connection retains its rejection, so the next
					// request must get a new connection-owned decision.
					client = newCompositionHTTPClient(t, f, 0, h2)
				}
				response := client.request(t, http.MethodGet, "/app", "", "", "")
				if response.Close == h2 {
					t.Fatal("capacity rejection changed its protocol-specific connection policy")
				}
				pendingHTTPResponse(t, response, http.StatusServiceUnavailable)
			}
			client.visitor.join(t)
			exchanges := int32(2)
			if f.calls.Load() != 1 || f.capacity.Load() != exchanges ||
				f.current[0].wire.openings.Load()-before != exchanges {
				t.Fatal("application rejection was not owned by its exact visitor connection")
			}
		})
	}
}

func TestServiceHTTPCompositionVerifiedHTTPSPreflightAndPrivateOneUseProbe(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.TLS == nil || r.Header.Get("Authorization") != "Bearer unchanged-application" ||
			r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
			t.Error("HTTPS owner probe lost target TLS/authentication or exposed its proof")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	options := proxy.TargetOptions{RootCAs: target.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	if err := proxy.PreflightWithOptions(t.Context(), target.URL, options); err != nil {
		t.Fatal("verified HTTPS target preflight failed", err)
	}
	if forwarded.Load() != 0 {
		t.Fatal("target preflight sent an application HTTP request")
	}
	f := newPendingHTTPFixture(t, 1, http.NotFoundHandler())
	forwarder, err := proxy.New(proxy.Config{Target: target.URL, Hostname: f.source.prepared.managedHostname, MaxConnsPerHost: 1, TargetOptions: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := forwarder.Close(); err != nil {
			t.Error(err)
		}
	})
	// the fixture's inline handler is the existing HTTPS proxy, not an
	// unverified target callback or a substitute ingress-capacity operation.
	f.source.prepared.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		forwarder.ServeHTTP(w, r)
	})
	update := f.source.update
	update.Anonymous = false
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
	if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	proof, _ := compositionHTTPProof(t, f)
	secret := proof.HeaderValue()
	client := newCompositionHTTPClient(t, f, 0, true)
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/health", "", "", secret), http.StatusNoContent)
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/health", "", "", secret), http.StatusForbidden)
	if forwarded.Load() != 1 || f.calls.Load() != 1 || proof.HeaderValue() != "" {
		t.Fatal("verified HTTPS owner proof was not private and single-use")
	}
}

func TestServiceHTTPCompositionMalformedProxyClosesOnlyVisitor(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	v := f.mustOpen(t, 0, pendingHTTPSource(0))
	if _, err := v.raw.Write([]byte("not-a-proxy-head")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-v.admission.completed:
	case <-time.After(time.Second):
		t.Fatal("malformed PROXY framing did not join its visitor within the original one-second bound")
	}
	_ = v.raw.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := v.raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("malformed PROXY stream remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("malformed PROXY stream only timed out instead of closing", err)
	}
	if f.calls.Load() != 0 || f.capacity.Load() != 0 {
		t.Fatal("malformed framing reached application or ingress capacity")
	}
	healthy := f.mustOpen(t, 0, pendingHTTPSource(1))
	pendingHTTPResponse(t, healthy.request(t, "/healthy"), http.StatusNoContent)
	if f.current[0].claimed.session.Err() != nil || f.current[0].relay.Err() != nil {
		t.Fatal("malformed PROXY framing retired the publisher/relay session")
	}
}

func TestServiceHTTPCompositionMalformedSiblingKeepsClaimedSession(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "192.0.2.1:40000" {
			t.Error("same-session HTTP sibling lost its signed source")
		}
		_, _ = io.WriteString(w, "local response")
	}))
	slot := f.current[0]
	outer, err := slot.relay.BorrowServicePublisherTransport()
	if err != nil {
		t.Fatal(err)
	}
	stalled, err := outer.OpenStream(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	claimedAwait(t, slot.wire.accepted)
	started := time.Now()
	healthy := f.mustOpen(t, 0, pendingHTTPSource(0))
	if time.Since(started) >= 2*time.Second {
		t.Fatal("a header-stalled sibling delayed the healthy opening beyond its original two-second bound")
	}
	_ = stalled.Close()
	malformed, err := outer.OpenStream(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer malformed.Close()
	claimedAwait(t, slot.wire.accepted)
	if err := malformed.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := malformed.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rejection, err := tunnelv1.ReadReturnFrame(malformed)
	if err != nil || rejection.Kind != tunnelv1.ReturnRejected || rejection.Code != tunnelv1.InvalidMessage {
		t.Fatal("malformed same-session sibling lost its stream-local rejection", rejection, err)
	}
	if err := healthy.raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response := healthy.request(t, "/")
	body, err := io.ReadAll(response.Body)
	err = errors.Join(err, response.Body.Close())
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "local response" ||
		f.calls.Load() != 1 || f.capacity.Load() != 1 || slot.claimed.session.Err() != nil || slot.relay.Err() != nil {
		t.Fatal("malformed sibling damaged healthy HTTP on the same claimed session", response.Status, string(body), err)
	}
}
