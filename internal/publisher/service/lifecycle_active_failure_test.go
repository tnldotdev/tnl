package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceRunStaleHeartbeatClosesActiveHTTPVisitor(t *testing.T) {
	assertActiveHTTPFailure(t, activeHTTPFailureOptions{heartbeat: clientcontrol.ErrStatusConflict})
}

func TestServiceRunUnauthenticatedHeartbeatClosesActiveHTTPVisitor(t *testing.T) {
	assertActiveHTTPFailure(t, activeHTTPFailureOptions{heartbeat: clientcontrol.ErrUnauthenticated})
}

func TestServiceRunCertificateExpirationClosesActiveHTTPVisitor(t *testing.T) {
	assertActiveHTTPFailure(t, activeHTTPFailureOptions{expire: true})
}

func TestServiceRunCertificateExpirationInterruptsActiveHTTPDrain(t *testing.T) {
	assertActiveHTTPFailure(t, activeHTTPFailureOptions{expire: true, drain: true})
}

func TestServiceRunActiveHTTPFailureKeepsIndependentFailuresDuringCancellation(t *testing.T) {
	assertActiveHTTPFailure(t, activeHTTPFailureOptions{
		heartbeat: errors.New("active visitor heartbeat failed while canceled"), cancelHeartbeat: true,
		slotCleanup: errors.New("active visitor slot cleanup failed"), runCleanup: errors.New("active visitor run cleanup failed"),
	})
}

func TestServiceRunActiveHTTPFailureFixtureDrainsCompleteResponse(t *testing.T) {
	f := newActiveHTTPFailureFixture(t, activeHTTPFailureOptions{})
	response := f.startVisitor()
	f.cancel()
	activeHTTPFailureAwait(t, f.ctx, f.draining)
	f.assertAdmissionRejected()
	f.unblock()
	if err := activeHTTPFailureAwait(t, f.ctx, response); err != nil {
		t.Fatal("admitted visitor lost its complete response during ordinary drain", err)
	}
	if err := activeHTTPFailureAwait(t, f.ctx, f.published); err != nil {
		t.Fatal("ordinary drain became a terminal run failure", err)
	}
	f.assertJoined()
}

type activeHTTPFailureOptions struct {
	heartbeat               error
	expire, drain           bool
	cancelHeartbeat         bool
	slotCleanup, runCleanup error
	observe                 func(RunStatus)
}

func assertActiveHTTPFailure(t *testing.T, options activeHTTPFailureOptions) {
	t.Helper()
	f := newActiveHTTPFailureFixture(t, options)
	response := f.startVisitor()
	if options.heartbeat != nil {
		f.control.failHeartbeat.Store(true)
		if options.cancelHeartbeat {
			activeHTTPFailureAwait(t, f.ctx, f.control.heartbeatEntered)
			f.cancel()
		}
	}
	var drainDeadline time.Time
	if options.drain {
		before := time.Now()
		f.cancel()
		activeHTTPFailureAwait(t, f.ctx, f.draining)
		f.bound.mu.Lock()
		drainDeadline = f.bound.drainUntil
		f.bound.mu.Unlock()
		if drainDeadline.Before(before.Add(5*time.Second)) || !f.notAfter.Before(drainDeadline) {
			t.Fatal("certificate fixture did not expire inside the original five-second drain", f.notAfter, drainDeadline)
		}
		for _, slot := range f.slots {
			select {
			case <-slot.closed:
				t.Fatal("graceful drain closed its transport before certificate expiry")
			default:
			}
		}
		f.assertAdmissionRejected()
	}
	if err := activeHTTPFailureAwait(t, f.ctx, response); err == nil {
		t.Fatal("active visitor completed after terminal run failure")
	}
	err := activeHTTPFailureAwait(t, f.ctx, f.published)
	want := options.heartbeat
	if options.expire {
		want = errCertificateExpired
	}
	if !errors.Is(err, want) {
		t.Fatal("publication discarded its exact terminal failure", err, want)
	}
	for _, cleanup := range []error{options.slotCleanup, options.runCleanup} {
		if cleanup != nil && !errors.Is(err, cleanup) {
			t.Error("terminal publication discarded an independent cleanup failure", err, cleanup)
		}
	}
	if options.expire && time.Now().Before(f.notAfter) {
		t.Error("publication stopped before the actual serving certificate expired")
	}
	if !drainDeadline.IsZero() && !time.Now().Before(drainDeadline) {
		t.Error("certificate expiry waited for the rest of the drain window")
	}
	f.assertAdmissionRejected()
	f.assertJoined()
}

type activeHTTPFailureControl struct {
	*certificateRecoveryControl
	options          activeHTTPFailureOptions
	failHeartbeat    atomic.Bool
	heartbeatEntered chan struct{}
}

func (c *activeHTTPFailureControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return (sourceForwardingControl{c.lifecycleControl}).ReadPublisherVisitorPolicy(ctx, request, token)
}

func (c *activeHTTPFailureControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, heartbeat controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	state, err := c.lifecycleControl.HeartbeatServiceRun(ctx, service, run, token, heartbeat)
	if err != nil || !c.failHeartbeat.Load() {
		return state, err
	}
	if c.options.cancelHeartbeat {
		close(c.heartbeatEntered)
		<-ctx.Done()
		return controlv1.ServiceRunState{}, errors.Join(ctx.Err(), c.options.heartbeat)
	}
	return controlv1.ServiceRunState{}, c.options.heartbeat
}

func (c *activeHTTPFailureControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	err := c.lifecycleControl.CloseServiceRun(ctx, service, run, token)
	if c.options.runCleanup != nil {
		err = errors.Join(err, context.Canceled, c.options.runCleanup)
	}
	return err
}

type activeHTTPFailureSlot struct {
	*Claimed
	served, closed chan struct{}
	cleanup        error
	closeOnce      sync.Once
	closeErr       error
}

func (s *activeHTTPFailureSlot) Serve(ctx context.Context) error {
	defer close(s.served)
	return s.Claimed.Serve(ctx)
}

func (s *activeHTTPFailureSlot) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.Claimed.Close()
		if s.cleanup != nil {
			s.closeErr = errors.Join(s.closeErr, context.Canceled, s.cleanup)
		}
		close(s.closed)
	})
	return s.closeErr
}

type activeHTTPFailureFixture struct {
	t                            *testing.T
	ctx                          context.Context
	cancel                       context.CancelFunc
	control                      *activeHTTPFailureControl
	bound                        *Bound
	slots                        [2]*activeHTTPFailureSlot
	relays                       [2]*tunnel.Session
	transports                   [2]muxsession.Session
	relayReady                   [2]chan struct{}
	relayJoined                  [2]chan struct{}
	draining, entered, appJoined chan struct{}
	published                    chan error
	publishJoined, visitorJoined chan struct{}
	unblock                      func()
	verification                 *tls.Config
	notAfter                     time.Time
	body                         string
	appCalls, capacityCalls      atomic.Int32
}

func newActiveHTTPFailureFixture(t *testing.T, options activeHTTPFailureOptions) *activeHTTPFailureFixture {
	t.Helper()
	ctx, finish := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(finish)
	f := &activeHTTPFailureFixture{
		t: t, ctx: ctx, draining: make(chan struct{}), entered: make(chan struct{}), appJoined: make(chan struct{}),
		published: make(chan error, 1), publishJoined: make(chan struct{}),
		body: strings.Repeat("complete visitor response\n", 32768),
	}
	release := make(chan struct{})
	f.unblock = sync.OnceFunc(func() { close(release) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.appCalls.Add(1) != 1 {
			t.Error("terminal lifecycle replayed the target request")
			return
		}
		defer close(f.appJoined)
		close(f.entered)
		select {
		case <-release:
			_, _ = io.WriteString(w, f.body)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { f.unblock(); upstream.Close() })
	cfg, base := lifecycleFixture(t)
	approved, err := base.GetPublisherService(ctx, cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port, approved.Endpoint.Public = controlv1.ServiceProtocolHTTP, 443, true
	base.approved = &approved
	control := &activeHTTPFailureControl{
		certificateRecoveryControl: &certificateRecoveryControl{lifecycleControl: base, store: cfg.State},
		options:                    options, heartbeatEntered: make(chan struct{}),
	}
	f.control = control
	issued := make(chan controlv1.ServiceCertificateIssuance, 1)
	first := true
	control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
		if !first {
			return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrUnavailable
		}
		first = false
		certificate, err := certificateFixtureIssuance(base, csr, func(leaf *x509.Certificate) {
			if options.expire {
				leaf.NotAfter = time.Now().Add(4 * time.Second).UTC().Truncate(time.Second)
			}
		})
		if err == nil {
			issued <- certificate
		}
		return certificate, err
	}
	cfg.Control, cfg.Target, cfg.Metadata.Protocol = control, upstream.Listener.Addr().String(), controlv1.ServiceProtocolHTTP
	cfg.HeartbeatInterval, cfg.DrainTime = 20*time.Millisecond, 5*time.Second
	cfg.Connectivity.DisableDirect = true
	// only the dial location and failure injection are test-owned. Publish owns
	// real certificates, ConnectSlot claims, dispatchers, visitors, and cleanup.
	serverTLS, roots := privateTransportTLS(t)
	cfg.TransportTLS = roots
	cfg.RelayQUIC = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("active HTTP failure fixture requires TLS/yamux")
	})
	var listeners [2]net.Listener
	for slot := range 2 {
		listeners[slot], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener := listeners[slot]
		t.Cleanup(func() { _ = listener.Close() })
		base.setup.PublisherConnections[slot].RelayAddress = listener.Addr().String()
		base.setup.PublisherConnections[slot].TlsServerName = "relay.test"
		f.relayReady[slot] = make(chan struct{})
		f.relayJoined[slot] = make(chan struct{})
	}
	type connected struct {
		slot    uint8
		claimed *activeHTTPFailureSlot
	}
	claims := make(chan connected, 2)
	var relayOnce [2]sync.Once
	var relayStarted [2]bool
	cfg.Connect = func(ctx context.Context, bound *Bound, slot uint8, connectionOptions ConnectOptions) (SlotSession, error) {
		bound.mu.Lock()
		ref := bound.prepared.connectionRef(bound.connections[slot])
		credential := bound.connections[slot].PublisherConnectionCredential
		bound.mu.Unlock()
		relayOnce[slot].Do(func() {
			relayStarted[slot] = true
			go f.serveRelay(slot, listeners[slot], serverTLS, ref, credential)
		})
		connectionOptions.PreferTCP = true
		tcp := connectionOptions.TCP
		connectionOptions.TCP = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
			outer, err := tcp.Connect(ctx, endpoint)
			if err == nil {
				f.transports[slot] = outer
			}
			return outer, err
		})
		claimed, err := bound.ConnectSlot(ctx, slot, connectionOptions)
		if err != nil {
			return nil, err
		}
		session := &activeHTTPFailureSlot{Claimed: claimed, served: make(chan struct{}), closed: make(chan struct{})}
		if slot == 0 {
			session.cleanup = options.slotCleanup
		}
		claims <- connected{slot, session}
		return session, nil
	}
	ready := make(chan struct{})
	cfg.Ready = func() error { close(ready); return nil }
	var draining sync.Once
	cfg.ObserveReadiness = func(status RunStatus) {
		if options.observe != nil {
			options.observe(status)
		}
		if status.Draining {
			draining.Do(func() { close(f.draining) })
		}
	}
	publishCtx, cancel := context.WithCancel(ctx)
	f.cancel = cancel
	go func() { defer close(f.publishJoined); f.published <- Publish(publishCtx, cfg) }()
	t.Cleanup(func() {
		cancel()
		f.unblock()
		finish()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		serviceHTTPAwait(t, f.publishJoined)
		for slot, joined := range f.relayJoined {
			if relayStarted[slot] {
				serviceHTTPAwait(t, joined)
			}
		}
	})
	select {
	case <-ready:
	case err := <-f.published:
		t.Fatal("active HTTP fixture stopped before readiness", err)
	case <-ctx.Done():
		t.Fatal("active HTTP fixture did not become ready", ctx.Err())
	}
	for range 2 {
		current := activeHTTPFailureAwait(t, ctx, claims)
		f.slots[current.slot] = current.claimed
	}
	for _, ready := range f.relayReady {
		activeHTTPFailureAwait(t, ctx, ready)
	}
	f.bound = f.slots[0].bound
	certificate := activeHTTPFailureAwait(t, ctx, issued)
	f.notAfter = *certificate.NotAfter
	_, remaining := pem.Decode([]byte(*certificate.CertificatePem))
	root, _ := pem.Decode(remaining)
	if root == nil {
		t.Fatal("issued certificate has no trust root")
	}
	parsed, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AddCert(parsed)
	f.verification = &tls.Config{ServerName: base.prep.Hostname, RootCAs: trust}
	return f
}

func (f *activeHTTPFailureFixture) serveRelay(slot uint8, listener net.Listener, config *tls.Config, ref tunnelv1.ServicePublisherConnectionRef, credential string) {
	defer close(f.relayJoined[slot])
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	outer, err := muxsession.AcceptTLSYamux(f.ctx, conn, config, muxsession.TLSYamuxConfig{})
	if err != nil {
		return
	}
	defer outer.Close()
	relay, _, err := tunnel.Accept(f.ctx, outer, func(_ context.Context, hello tunnelv1.Message) error {
		if hello.ServiceConnection == nil || *hello.ServiceConnection != ref || hello.Credential != credential {
			return ErrPrivateStream
		}
		return nil
	})
	if err != nil {
		return
	}
	defer relay.Close()
	f.relays[slot] = relay
	close(f.relayReady[slot])
	capacityJoined := make(chan struct{})
	go func() { defer close(capacityJoined); _ = relay.ServeServiceCapacity(f.ctx) }()
	defer func() { _ = relay.Close(); <-capacityJoined }()
	if err := relay.HandlePublisherDrain(f.ctx, func(context.Context) error { return nil }); err == nil {
		// writing the ACKs is not proof the publisher consumed them. retain the
		// transport until its owner closes it after the drain exchange joins.
		select {
		case <-outer.Done():
		case <-f.ctx.Done():
		}
	}
}

func (f *activeHTTPFailureFixture) header(slot int) tunnelv1.ServiceForwardingHeader {
	f.t.Helper()
	header := privateHeader(f.t, f.slots[slot].ref)
	header.PublicService.DestinationPort = 443
	return header
}

func (f *activeHTTPFailureFixture) startVisitor() <-chan error {
	f.t.Helper()
	header := f.header(0)
	releaseCapacity, err := f.relays[0].RegisterServiceCapacity(f.ctx, header, func(context.Context) error {
		f.capacityCalls.Add(1)
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(releaseCapacity)
	stream, err := f.relays[0].OpenServiceForwardingStream(f.ctx, header)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = stream.Close() })
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	view, enabled, _ := f.bound.prepared.policy.Current()
	if !enabled {
		f.t.Fatal("active visitor needs current serving policy")
	}
	now := view.AuthorityTime(time.Now())
	// sign with the actual setup key without replacing any run-owned state.
	authority, key, err := visitortoken.IssueVisitorSourceAuthority(f.bound.prepared.sourceKey, tunnelv1.VisitorSourceAuthority{
		ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber, EndpointRevision: 1,
		IngressID: header.PublicService.IngressID, IngressRunID: header.PublicService.IngressRunID,
		IngressLeaseRevision: header.PublicService.IngressLeaseRevision, VisitorPolicyRevision: view.VisitorPolicyRevision,
		ValidUntil: now.Add(visitortoken.PolicyLifetime).Unix(),
	}, now)
	if err != nil {
		f.t.Fatal(err)
	}
	metadata := proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	proof, err := visitortoken.SignVisitorSource(key, authority, 1, tunnelv1.VisitorSourceBinding{
		ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber,
		VisitorConnectionID: header.VisitorConnectionID, Source: metadata.Source, Destination: metadata.Destination,
	}, now)
	if err != nil {
		f.t.Fatal(err)
	}
	wire, err := proof.MarshalBinary()
	if err != nil {
		f.t.Fatal(err)
	}
	metadata.VisitorSourceProof = string(wire)
	encoded, err := proxyproto.Encode(metadata)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := stream.Write(encoded); err != nil {
		f.t.Fatal(err)
	}
	visitor := tls.Client(stream, f.verification)
	f.t.Cleanup(func() { _ = visitor.Close() })
	if err := visitor.HandshakeContext(f.ctx); err != nil {
		f.t.Fatal("active visitor did not verify the run-managed serving certificate", err)
	}
	if _, err := fmt.Fprintf(visitor, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", f.control.prep.Hostname); err != nil {
		f.t.Fatal(err)
	}
	response := make(chan error, 1)
	f.visitorJoined = make(chan struct{})
	go func() {
		defer close(f.visitorJoined)
		defer visitor.Close()
		reply, err := http.ReadResponse(bufio.NewReader(visitor), nil)
		if err == nil {
			var body []byte
			body, err = io.ReadAll(reply.Body)
			_ = reply.Body.Close()
			if err == nil && (reply.StatusCode != http.StatusOK || string(body) != f.body) {
				err = fmt.Errorf("incomplete active visitor response: status=%d bytes=%d", reply.StatusCode, len(body))
			}
		}
		response <- err
	}()
	f.t.Cleanup(func() { _ = visitor.Close(); serviceHTTPAwait(f.t, f.visitorJoined) })
	select {
	case <-f.entered:
	case err := <-response:
		f.t.Fatal("visitor completed before reaching the target", err)
	case <-f.ctx.Done():
		f.t.Fatal("visitor did not reach the target", f.ctx.Err())
	}
	return response
}

func (f *activeHTTPFailureFixture) assertAdmissionRejected() {
	f.t.Helper()
	for slot, relay := range f.relays {
		stream, err := relay.OpenServiceForwardingStream(f.ctx, f.header(slot))
		if err == nil {
			_ = stream.Close()
			f.t.Fatal("terminal or draining publication admitted a new visitor", slot)
		}
	}
}

func (f *activeHTTPFailureFixture) assertJoined() {
	f.t.Helper()
	activeHTTPFailureAwait(f.t, f.ctx, f.publishJoined)
	activeHTTPFailureAwait(f.t, f.ctx, f.visitorJoined)
	activeHTTPFailureAwait(f.t, f.ctx, f.appJoined)
	for slot, session := range f.slots {
		for _, joined := range []<-chan struct{}{session.served, session.closed, session.packets.Done(), f.transports[slot].Done()} {
			select {
			case <-joined:
			default:
				f.t.Error("publication returned before its claimed slot and transport joined", slot)
			}
		}
		activeHTTPFailureAwait(f.t, f.ctx, f.relayJoined[slot])
	}
	f.bound.mu.Lock()
	if !f.bound.closed || f.bound.reservedStreams != 0 || len(f.bound.active) != 0 || f.bound.packetSlots != [2]*Claimed{} {
		f.t.Error("terminal publication retained admission, visitor capacity, or packet slots", f.bound.closed, f.bound.reservedStreams, len(f.bound.active))
	}
	f.bound.mu.Unlock()
	if f.appCalls.Load() != 1 || f.capacityCalls.Load() != 1 {
		f.t.Error("terminal publication replayed target or capacity authorization", f.appCalls.Load(), f.capacityCalls.Load())
	}
	f.control.mu.Lock()
	defer f.control.mu.Unlock()
	if f.control.closes != 1 || f.control.bad != nil {
		f.t.Error("terminal publication did not close the exact run once", f.control.closes, f.control.bad)
	}
}

func activeHTTPFailureAwait[T any](t *testing.T, ctx context.Context, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-ctx.Done():
		t.Fatal("active HTTP lifecycle exceeded its fifteen-second fixture bound", ctx.Err())
		var zero T
		return zero
	}
}
