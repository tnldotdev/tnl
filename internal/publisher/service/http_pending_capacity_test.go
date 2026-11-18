package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	pendingHTTPRelayAllowance  = 16
	pendingHTTPSourceAllowance = 8
)

// the observer changes no bytes or admission decisions. a held close first
// physically interrupts its real yamux stream, then holds the owner's join.
type pendingHTTPWire struct {
	muxsession.Stream
	once     sync.Once
	mu       sync.Mutex
	hold     <-chan struct{}
	entered  chan struct{}
	done     chan struct{}
	err      error
	physical atomic.Int32
}

func (s *pendingHTTPWire) Close() error {
	s.once.Do(func() {
		s.physical.Add(1)
		err := s.Stream.Close()
		close(s.entered)
		s.mu.Lock()
		hold := s.hold
		s.mu.Unlock()
		if hold != nil {
			<-hold
		}
		s.err = err
		close(s.done)
	})
	return s.err
}

func (s *pendingHTTPWire) holdCleanup(release <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hold = release
}

type pendingHTTPTransport struct {
	muxsession.Session
	accepted chan *pendingHTTPWire
	openings atomic.Int32
}

func (s *pendingHTTPTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err == nil {
		s.openings.Add(1)
	}
	return stream, err
}

func (s *pendingHTTPTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	wire := &pendingHTTPWire{Stream: stream, entered: make(chan struct{}), done: make(chan struct{})}
	s.accepted <- wire
	return wire, nil
}

type pendingHTTPSlot struct {
	claimed        *Claimed
	relay          *tunnel.Session
	wire           *pendingHTTPTransport
	cancel         context.CancelFunc
	cancelCapacity context.CancelFunc
	served         <-chan error
	capacityDone   <-chan error
	capacityOnce   sync.Once
	once           sync.Once
}

func (s *pendingHTTPSlot) stopCapacity(t *testing.T) {
	t.Helper()
	s.capacityOnce.Do(func() {
		// a reply can reach the publisher before the relay worker's physical
		// close returns. retain both transports until that worker joins.
		s.cancelCapacity()
		s.join(t, s.capacityDone)
	})
}

func (s *pendingHTTPSlot) join(t *testing.T, result <-chan error) {
	t.Helper()
	err := claimedAwait(t, result)
	if err != nil && !failure.Only(err, context.Canceled) &&
		!failure.Only(err, net.ErrClosed) && !failure.Only(err, muxsession.ErrClosed) {
		t.Error("pending HTTP owner lost joined shutdown", err)
	}
}

func (s *pendingHTTPSlot) stop(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		s.stopCapacity(t)
		s.cancel()
		s.join(t, s.served)
		if err := s.relay.Close(); err != nil {
			t.Error("close pending HTTP relay", err)
		}
		if err := s.claimed.Close(); err != nil {
			t.Error("close pending HTTP claimed slot", err)
		}
	})
}

type pendingHTTPFixture struct {
	source    *sourceForwardingFixture
	ctx       context.Context
	cancel    context.CancelFunc
	current   [2]*pendingHTTPSlot
	slots     []*pendingHTTPSlot
	sequence  atomic.Uint64
	capacity  atomic.Int32
	calls     atomic.Int32
	ingressMu sync.Mutex
	ingress   func(context.Context) error
	wrapRelay []func(muxsession.Session) muxsession.Session
}

func newPendingHTTPFixture(t *testing.T, capacity int, handler http.Handler, wrapRelay ...func(muxsession.Session) muxsession.Session) *pendingHTTPFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 15*time.Second)
	f := &pendingHTTPFixture{source: newSourceForwardingFixture(t), ctx: ctx, cancel: cancel, wrapRelay: wrapRelay}
	// retain the real configured service HTTP frontend and signed source owner;
	// only the inline application and the run's approved physical limit vary.
	f.source.prepared.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer unchanged-application" {
			t.Error("pending HTTP admission changed application authentication")
		}
		handler.ServeHTTP(w, r)
	})
	f.source.bound.streamCapacity = capacity
	for slot := range uint8(2) {
		f.current[slot] = f.connect(t, slot)
	}
	t.Cleanup(func() {
		defer cancel()
		for _, slot := range f.slots {
			slot.stop(t)
		}
		f.source.bound.mu.Lock()
		defer f.source.bound.mu.Unlock()
		if f.source.bound.reservedStreams != 0 || len(f.source.bound.active) != 0 ||
			f.source.bound.httpPending != 0 || len(f.source.bound.httpPendingRelays) != 0 || len(f.source.bound.httpPendingSources) != 0 {
			t.Error("joined pending HTTP fixture retained final capacity, setup accounting, or physical visitors",
				f.source.bound.reservedStreams, len(f.source.bound.active), f.source.bound.httpPending,
				f.source.bound.httpPendingRelays, f.source.bound.httpPendingSources)
		}
	})
	return f
}

func (f *pendingHTTPFixture) connect(t *testing.T, index uint8) *pendingHTTPSlot {
	t.Helper()
	s := &pendingHTTPSlot{}
	s.claimed, s.relay = newClaimedTestPair(t, f.source.bound, index, func(outer muxsession.Session) muxsession.Session {
		s.wire = &pendingHTTPTransport{Session: outer, accepted: make(chan *pendingHTTPWire, 128)}
		return s.wire
	}, f.wrapRelay...)
	ctx, cancel := context.WithCancel(f.ctx)
	s.cancel = cancel
	served, capacity := make(chan error, 1), make(chan error, 1)
	s.served, s.capacityDone = served, capacity
	go func() { served <- s.claimed.Serve(ctx) }()
	// this is the existing authenticated capacity exchange, not a supplied
	// no-op replacement for the publisher's reservation callback.
	capacityContext, cancelCapacity := context.WithCancel(f.ctx)
	s.cancelCapacity = cancelCapacity
	go func() { capacity <- s.relay.ServeServiceCapacity(capacityContext) }()
	f.slots = append(f.slots, s)
	return s
}

func (f *pendingHTTPFixture) header(t *testing.T, index uint8, source netip.Addr) tunnelv1.ServiceForwardingHeader {
	t.Helper()
	header := privateHeader(t, f.current[index].claimed.ref)
	header.SourceIP = source.Unmap().String()
	header.PublicService.DestinationPort = 443
	header.PublicService.IngressRunID = f.source.header.PublicService.IngressRunID
	return header
}

func (f *pendingHTTPFixture) metadata(t *testing.T, header tunnelv1.ServiceForwardingHeader, source netip.Addr, mutate bool) []byte {
	t.Helper()
	view, enabled, _ := f.source.prepared.policy.Current()
	if !enabled {
		t.Fatal("pending HTTP fixture lost its current run policy")
	}
	now := view.AuthorityTime(time.Now())
	authority, key, err := visitortoken.IssueVisitorSourceAuthority(f.source.prepared.sourceKey, tunnelv1.VisitorSourceAuthority{
		ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber,
		EndpointRevision: 1, IngressID: header.PublicService.IngressID,
		IngressRunID: header.PublicService.IngressRunID, IngressLeaseRevision: header.PublicService.IngressLeaseRevision,
		VisitorPolicyRevision: view.VisitorPolicyRevision, ValidUntil: now.Add(visitortoken.PolicyLifetime).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddr("203.0.113.1")
	if source.Unmap().Is6() {
		destination = netip.MustParseAddr("2001:db8:ffff::1")
	}
	metadata := proxyproto.Header{Source: netip.AddrPortFrom(source.Unmap(), 40000),
		Destination: netip.AddrPortFrom(destination, 443)}
	proof, err := visitortoken.SignVisitorSource(key, authority, f.sequence.Add(1), tunnelv1.VisitorSourceBinding{
		ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber,
		VisitorConnectionID: header.VisitorConnectionID, Source: metadata.Source, Destination: metadata.Destination,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if mutate {
		proof.MAC[0] ^= 1
	}
	wire, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	metadata.VisitorSourceProof = string(wire)
	encoded, err := proxyproto.Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type pendingHTTPVisitor struct {
	fixture    *pendingHTTPFixture
	header     tunnelv1.ServiceForwardingHeader
	source     netip.Addr
	raw        muxsession.Stream
	wire       *pendingHTTPWire
	secure     *tls.Conn
	reader     *bufio.Reader
	admission  *httpAdmission
	unregister func()
	once       sync.Once
}

func (v *pendingHTTPVisitor) close() {
	v.once.Do(func() {
		// close the physical stream rather than waiting for TLS close_notify
		// while the publisher may itself be in a deliberately held cleanup.
		_ = v.raw.Close()
		v.unregister()
	})
}

func (v *pendingHTTPVisitor) join(t *testing.T) {
	t.Helper()
	claimedAwait(t, v.admission.completed)
}

func (f *pendingHTTPFixture) open(t *testing.T, index uint8, source netip.Addr, change func(*tunnelv1.ServiceForwardingHeader)) (*pendingHTTPVisitor, error) {
	t.Helper()
	header := f.header(t, index, source)
	if change != nil {
		change(&header)
	}
	slot := f.current[index]
	// opens in this fixture are serial. borrow the one new entry from the
	// existing run registry to observe its actual retirement, not merely the
	// client's close or the start of the publisher's physical cleanup.
	bound := f.source.bound
	bound.mu.Lock()
	before := make(map[*httpAdmission]struct{}, len(bound.active))
	for _, visitor := range bound.active {
		if visitor.http != nil {
			before[visitor.http] = struct{}{}
		}
	}
	bound.mu.Unlock()
	raw, err := slot.relay.OpenServiceForwardingStream(f.ctx, header)
	wire := claimedAwait(t, slot.wire.accepted)
	if err != nil {
		return nil, err
	}
	bound.mu.Lock()
	var admission *httpAdmission
	for _, visitor := range bound.active {
		if a := visitor.http; a != nil && a.ref == slot.claimed.ref {
			if _, existed := before[a]; !existed {
				if admission != nil {
					bound.mu.Unlock()
					_ = raw.Close()
					t.Fatal("serial HTTP opening acquired more than one owned admission")
				}
				admission = a
			}
		}
	}
	bound.mu.Unlock()
	if admission == nil {
		_ = raw.Close()
		t.Fatal("accepted HTTP opening has no run-owned admission")
	}
	if until, ok := f.ctx.Deadline(); ok {
		if err := raw.SetDeadline(until); err != nil {
			_ = raw.Close()
			t.Fatal("set original pending HTTP fixture bound", err)
		}
	}
	unregister, err := slot.relay.RegisterServiceCapacity(f.ctx, header, func(call context.Context) error {
		f.capacity.Add(1)
		f.ingressMu.Lock()
		admit := f.ingress
		f.ingressMu.Unlock()
		if admit != nil {
			return admit(call)
		}
		return nil
	})
	if err != nil {
		_ = raw.Close()
		t.Fatal("register exact pending HTTP ingress capacity", err)
	}
	v := &pendingHTTPVisitor{fixture: f, header: header, source: source, raw: raw, wire: wire, admission: admission, unregister: unregister}
	t.Cleanup(v.close)
	return v, nil
}

func (f *pendingHTTPFixture) mustOpen(t *testing.T, index uint8, source netip.Addr) *pendingHTTPVisitor {
	t.Helper()
	v, err := f.open(t, index, source, nil)
	if err != nil {
		t.Fatal("pending setup spent final visitor capacity or another relay's pending allowance", err)
	}
	return v
}

func (v *pendingHTTPVisitor) handshake(t *testing.T, mutate bool) error {
	t.Helper()
	if _, err := v.raw.Write(v.fixture.metadata(t, v.header, v.source, mutate)); err != nil {
		return err
	}
	v.secure = tls.Client(v.raw, v.fixture.source.verification.Clone())
	if err := v.secure.HandshakeContext(v.fixture.ctx); err != nil {
		return err
	}
	v.reader = bufio.NewReader(v.secure)
	return nil
}

func (v *pendingHTTPVisitor) request(t *testing.T, path string) *http.Response {
	t.Helper()
	if v.secure == nil {
		if err := v.handshake(t, false); err != nil {
			t.Fatal("healthy pending HTTP visitor could not finish verified TLS", err)
		}
	}
	request, err := http.NewRequestWithContext(v.fixture.ctx, http.MethodGet,
		"https://"+v.fixture.source.prepared.managedHostname+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer unchanged-application")
	if err := request.Write(v.secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(v.reader, request)
	if err != nil {
		t.Fatal("pending HTTP request did not receive its response", err)
	}
	return response
}

func pendingHTTPResponse(t *testing.T, response *http.Response, status int) {
	t.Helper()
	_, readErr := io.Copy(io.Discard, response.Body)
	err := errors.Join(readErr, response.Body.Close())
	if err != nil || response.StatusCode != status {
		t.Fatal("pending HTTP admission changed the response", response.StatusCode, status, err)
	}
}

func pendingHTTPSource(index int) netip.Addr {
	return netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)})
}

func TestServiceHTTPPendingMetadataDoesNotConsumeFinalVisitorCapacity(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// real claimed-stream acceptance proves the first setup is reserved before
	// opening the healthy sibling; no source metadata or TLS byte has arrived.
	f.mustOpen(t, 0, pendingHTTPSource(0))
	healthy, err := f.open(t, 1, netip.MustParseAddr("198.51.100.1"), nil)
	if err != nil {
		t.Fatal("one metadata-stalled HTTP setup consumed the final visitor slot and starved the healthy relay", err)
	}
	pendingHTTPResponse(t, healthy.request(t, "/healthy"), http.StatusNoContent)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("metadata-only work reached the application or spent ingress capacity", f.calls.Load(), f.capacity.Load())
	}
}

type pendingHTTPStalledTLS struct {
	net.Conn
	reading chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *pendingHTTPStalledTLS) Read([]byte) (int, error) {
	var first [1]byte
	if _, err := io.ReadFull(c.Conn, first[:]); err != nil {
		return 0, err
	}
	// a publisher TLS byte proves signed source admission already ran. keep
	// the rest unread so its handshake and pending source charge stay owned.
	c.once.Do(func() { close(c.reading) })
	<-c.release
	return 0, net.ErrClosed
}

func (v *pendingHTTPVisitor) stallTLS(t *testing.T) {
	t.Helper()
	if _, err := v.raw.Write(v.fixture.metadata(t, v.header, v.source, false)); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	stalled := &pendingHTTPStalledTLS{Conn: v.raw, reading: make(chan struct{}), release: released}
	done := make(chan error, 1)
	go func() {
		done <- tls.Client(stalled, v.fixture.source.verification.Clone()).HandshakeContext(v.fixture.ctx)
	}()
	t.Cleanup(func() { release(); v.close(); _ = claimedAwait(t, done) })
	claimedAwait(t, stalled.reading)
}

func TestServiceHTTPPendingRelayFairnessAndTrustedIdentity(t *testing.T) {
	for _, stage := range []string{"metadata", "tls", "headers"} {
		t.Run(stage, func(t *testing.T) {
			f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			for index := range pendingHTTPRelayAllowance {
				v := f.mustOpen(t, 0, pendingHTTPSource(index))
				switch stage {
				case "tls":
					v.stallTLS(t)
				case "headers":
					if err := v.handshake(t, false); err != nil {
						t.Fatal("pending HTTP header allowance rejected verified TLS", err)
					}
					if _, err := fmt.Fprintf(v.secure, "GET /incomplete HTTP/1.1\r\nHost: %s\r\n",
						f.source.prepared.managedHostname); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, spoof := range []bool{false, true} {
				change := func(header *tunnelv1.ServiceForwardingHeader) {
					if spoof {
						header.ConnectionSlot = 1
					}
				}
				excess, err := f.open(t, 0, pendingHTTPSource(40), change)
				if err == nil {
					excess.close()
					t.Fatal("full pending relay or substituted claim was admitted", spoof)
				}
				want := tunnelv1.CapacityExceeded
				if spoof {
					want = tunnelv1.StaleConnectionAssignment
				}
				var rejected *tunnel.ProtocolError
				if !errors.As(err, &rejected) || rejected.Code != want {
					t.Fatal("pending accounting replaced the trusted-identity rejection", spoof, err, want)
				}
			}
			healthy := f.mustOpen(t, 1, netip.MustParseAddr("198.51.100.1"))
			pendingHTTPResponse(t, healthy.request(t, "/healthy"), http.StatusNoContent)
			if f.calls.Load() != 1 || f.capacity.Load() != 1 {
				t.Fatal("pending work reached the application or evicted the healthy relay", f.calls.Load(), f.capacity.Load())
			}
		})
	}
}

func TestServiceHTTPPendingSetupsRemainIndependentOfTwoFullRuns(t *testing.T) {
	const capacity = 10
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	var active atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		_, _ = io.WriteString(w, "prefix")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-released:
			_, _ = io.WriteString(w, "finished")
		case <-r.Context().Done():
		}
	})
	runs := []*pendingHTTPFixture{newPendingHTTPFixture(t, capacity, handler), newPendingHTTPFixture(t, capacity, handler)}
	var held []*http.Response
	for runIndex, f := range runs {
		for index := range capacity {
			slot := uint8(index % 2)
			if runIndex == 1 {
				slot = 1 // one surviving relay can spend all ten final slots.
			}
			v := f.mustOpen(t, slot, pendingHTTPSource(index))
			response := v.request(t, "/hold")
			prefix := make([]byte, len("prefix"))
			if response.StatusCode != http.StatusOK {
				t.Fatal("authorized run capacity was unavailable", response.StatusCode)
			}
			if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
				t.Fatal("admitted target did not stream", string(prefix), err)
			}
			held = append(held, response)
		}
		for slot := range uint8(2) {
			excess := f.mustOpen(t, slot, netip.MustParseAddr("198.51.100.1"))
			pendingHTTPResponse(t, excess.request(t, "/overflow"), http.StatusServiceUnavailable)
			excess.close()
			excess.join(t)
		}
	}
	var pending []*pendingHTTPVisitor
	for index := range pendingHTTPRelayAllowance {
		pending = append(pending, runs[1].mustOpen(t, 0, pendingHTTPSource(40+index)))
	}
	if active.Load() != 2*capacity || runs[0].calls.Load() != capacity || runs[1].calls.Load() != capacity {
		t.Fatal("pending work displaced the two cap-ten runs", active.Load(), runs[0].calls.Load(), runs[1].calls.Load())
	}
	for _, v := range pending {
		v.close()
	}
	release()
	for _, response := range held {
		body, err := io.ReadAll(response.Body)
		err = errors.Join(err, response.Body.Close())
		if err != nil || string(body) != "finished" {
			t.Fatal("pending overload evicted admitted final response bytes", string(body), err)
		}
	}
	if runs[0].capacity.Load() != capacity || runs[1].capacity.Load() != capacity {
		t.Fatal("pending or excess connections spent ingress capacity", runs[0].capacity.Load(), runs[1].capacity.Load())
	}
}

func TestServiceHTTPPendingSourceAllowanceSpansRelaysAndReleasesOnAuthorization(t *testing.T) {
	for _, addresses := range [][2]string{
		{"192.0.2.1", "::ffff:192.0.2.1"},
		{"2001:db8::1", "2001:db8::ffff"},
	} {
		t.Run(addresses[0], func(t *testing.T) {
			f := newPendingHTTPFixture(t, 32, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			var held []*pendingHTTPVisitor
			for index := range pendingHTTPSourceAllowance {
				v := f.mustOpen(t, uint8(index%2), netip.MustParseAddr(addresses[index%2]))
				if err := v.handshake(t, false); err != nil {
					t.Fatal("original eight-connection browser burst was rejected", err)
				}
				held = append(held, v)
			}
			for slot := range uint8(2) {
				excess := f.mustOpen(t, slot, netip.MustParseAddr(addresses[slot]))
				if err := excess.handshake(t, false); err == nil {
					t.Fatal("source overflow passed verified TLS through a sibling relay", slot)
				}
				excess.close()
				excess.join(t)
			}
			for _, v := range held {
				pendingHTTPResponse(t, v.request(t, "/burst"), http.StatusNoContent)
			}
			next := f.mustOpen(t, 1, netip.MustParseAddr(addresses[0]))
			pendingHTTPResponse(t, next.request(t, "/next"), http.StatusNoContent)
			if f.calls.Load() != pendingHTTPSourceAllowance+1 || f.capacity.Load() != pendingHTTPSourceAllowance+1 {
				t.Fatal("pending source allowance became final request capacity or spent admission", f.calls.Load(), f.capacity.Load())
			}
		})
	}
}

func TestServiceHTTPSlowPendingSourcesLeaveRoomForHealthyVisitors(t *testing.T) {
	for _, sources := range []int{1, 2} {
		t.Run(fmt.Sprint(sources), func(t *testing.T) {
			f := newPendingHTTPFixture(t, 32, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			for source := range sources {
				for index := range pendingHTTPSourceAllowance {
					f.mustOpen(t, uint8(index%2), pendingHTTPSource(source)).stallTLS(t)
				}
			}
			for slot := range uint8(2) {
				healthy := f.mustOpen(t, slot, netip.MustParseAddr("198.51.100.1"))
				pendingHTTPResponse(t, healthy.request(t, "/healthy"), http.StatusNoContent)
			}
			if f.calls.Load() != 2 || f.capacity.Load() != 2 {
				t.Fatal("slow source performed application work or blocked a healthy source", f.calls.Load(), f.capacity.Load())
			}
		})
	}
}

func TestServiceHTTPPendingSourceRequiresVerifiedMetadataBeforeCharge(t *testing.T) {
	f := newPendingHTTPFixture(t, 32, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	source := netip.MustParseAddr("192.0.2.1")
	invalid := f.mustOpen(t, 0, source)
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	invalid.wire.holdCleanup(released)
	if err := invalid.handshake(t, true); err == nil {
		t.Fatal("mutated source proof passed visitor TLS")
	}
	invalid.close()
	claimedAwait(t, invalid.wire.entered)
	for index := range pendingHTTPSourceAllowance {
		v := f.mustOpen(t, uint8(index%2), source)
		if err := v.handshake(t, false); err != nil {
			t.Fatal("unverified metadata spent a valid source's setup allowance", index, err)
		}
	}
	f.source.bound.mu.Lock()
	_, unverified := invalid.admission.chargedStateLocked().(unverifiedHTTPAdmission)
	pending, final := f.source.bound.httpPending, f.source.bound.reservedStreams
	var chargedSources int
	for _, count := range f.source.bound.httpPendingSources {
		chargedSources += count
	}
	f.source.bound.mu.Unlock()
	if !unverified || pending != pendingHTTPSourceAllowance+1 || chargedSources != pendingHTTPSourceAllowance || final != 0 {
		t.Fatal("bad-MAC cleanup charged a source or released its physical setup early", unverified, pending, chargedSources, final)
	}
	select {
	case <-invalid.wire.done:
		t.Fatal("invalid evidence was not held in physical cleanup during the valid burst")
	default:
	}
	if f.calls.Load() != 0 || f.capacity.Load() != 0 {
		t.Fatal("source verification granted application access", f.calls.Load(), f.capacity.Load())
	}
}

func TestServiceHTTPPendingSourceChargeSurvivesBlockedCleanupAndRelayReplacement(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	source := netip.MustParseAddr("192.0.2.1")
	held := f.mustOpen(t, 0, source)
	if err := held.handshake(t, false); err != nil {
		t.Fatal(err)
	}
	for range pendingHTTPSourceAllowance - 1 {
		v := f.mustOpen(t, 1, source)
		if err := v.handshake(t, false); err != nil {
			t.Fatal(err)
		}
	}
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	t.Cleanup(release)
	held.wire.holdCleanup(released)
	held.close()
	claimedAwait(t, held.wire.entered)
	old := f.current[0]
	next := f.source.bound.connections
	id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	next[0].PublisherConnectionId = id
	next[0].ConnectionAssignmentRevision++
	// the same relay service's retiring connection keeps its own accounting;
	// the replacement carries a new exact claim, not a fresh source allowance.
	state := controlv1.ServiceRunState{ServiceId: f.source.prepared.Preparation.ServiceId,
		ServiceRunId: f.source.prepared.Preparation.ServiceRunId, RunNumber: f.source.prepared.Preparation.RunNumber,
		State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute),
		PublisherConnections: []controlv1.ConnectionAssignment{next[0], next[1]}}
	if err := f.source.bound.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	f.current[0] = f.connect(t, 0)
	for slot := range uint8(2) {
		excess := f.mustOpen(t, slot, source)
		if err := excess.handshake(t, false); err == nil {
			t.Fatal("relay replacement borrowed a retiring source charge before physical cleanup joined", slot)
		}
		excess.close()
		excess.join(t)
	}
	for index := range pendingHTTPRelayAllowance - 1 {
		f.mustOpen(t, 0, pendingHTTPSource(40+index))
	}
	if excess, err := f.open(t, 0, pendingHTTPSource(80), nil); err == nil {
		excess.close()
		t.Fatal("replacement relay borrowed its predecessor's unjoined pending relay charge")
	} else {
		var rejected *tunnel.ProtocolError
		if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
			t.Fatal("retiring relay capacity lost its rejection classification", err)
		}
	}
	select {
	case <-held.wire.done:
		t.Fatal("held physical cleanup was not actually held")
	default:
	}
	release()
	// only this predecessor carried one setup. joining it is the actual
	// retirement barrier; the other seven stay pending on the healthy slot.
	old.stop(t)
	if held.wire.physical.Load() != 1 {
		t.Fatal("joined retirement physically closed the predecessor more than once", held.wire.physical.Load())
	}
	reused := f.mustOpen(t, 0, source)
	if err := reused.handshake(t, false); err != nil {
		t.Fatal("one joined cleanup did not free its exact pending source slot", err)
	}
	excess := f.mustOpen(t, 1, source)
	if err := excess.handshake(t, false); err == nil {
		t.Fatal("one joined cleanup freed more than one pending source slot")
	}
	excess.close()
	excess.join(t)
	pendingHTTPResponse(t, reused.request(t, "/after-cleanup"), http.StatusNoContent)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("cleanup reuse replayed work or spent another visitor's capacity", f.calls.Load(), f.capacity.Load())
	}
}

func TestServiceHTTPPendingDeadlineDoesNotRestartAfterMetadataTLSOrHeaders(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.NotFoundHandler())
	started := time.Now()
	v := f.mustOpen(t, 0, pendingHTTPSource(0))
	until := started.Add(10 * time.Second)
	waitUntil := func(at time.Time) {
		t.Helper()
		timer := time.NewTimer(max(0, time.Until(at)))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-f.ctx.Done():
			t.Fatal("pending HTTP fixture ended before its original setup observation", context.Cause(f.ctx))
		}
	}
	// these timers spend the original setup budget, not readiness guesses.
	// metadata arrives late and TLS completes before the original ten seconds;
	// neither may give the partial HTTP header a fresh setup window.
	waitUntil(started.Add(3 * time.Second))
	if err := v.handshake(t, false); err != nil {
		t.Fatal("current pending HTTP setup expired before its original deadline", err)
	}
	waitUntil(started.Add(6 * time.Second))
	if _, err := fmt.Fprintf(v.secure, "GET /incomplete HTTP/1.1\r\nHost: %s\r\n",
		f.source.prepared.managedHostname); err != nil {
		t.Fatal(err)
	}
	waitUntil(until.Add(-time.Second))
	select {
	case <-v.wire.entered:
		t.Fatal("pending setup closed before its original deadline")
	default:
	}
	// allow only local scheduler/transport delivery after the original fence,
	// not the extra three or six seconds a restarted phase deadline would add.
	timer := time.NewTimer(max(0, time.Until(until.Add(time.Second))))
	defer timer.Stop()
	select {
	case <-v.wire.entered:
	case <-timer.C:
		t.Fatal("metadata, TLS or HTTP headers restarted the original ten-second setup deadline")
	}
	if f.calls.Load() != 0 || f.capacity.Load() != 0 {
		t.Fatal("expired incomplete setup reached the application or reserved ingress", f.calls.Load(), f.capacity.Load())
	}
}

func TestServiceHTTPPendingAuthorizationPrecedesFinalAndIngressCapacity(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	update := f.source.update
	update.Anonymous = false
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
	if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	denied := f.mustOpen(t, 0, pendingHTTPSource(0))
	released := make(chan struct{})
	releaseCleanup := sync.OnceFunc(func() { close(released) })
	defer releaseCleanup()
	denied.wire.holdCleanup(released)
	pendingHTTPResponse(t, denied.request(t, "/denied"), http.StatusForbidden)
	claimedAwait(t, denied.wire.entered)
	f.source.bound.mu.Lock()
	pending, final := f.source.bound.httpPending, f.source.bound.reservedStreams
	sources := len(f.source.bound.httpPendingSources)
	f.source.bound.mu.Unlock()
	if f.calls.Load() != 0 || f.capacity.Load() != 0 || pending != 1 || sources != 1 || final != 0 {
		t.Fatal("denied request acquired final/application capacity or lost its setup charge",
			f.calls.Load(), f.capacity.Load(), pending, sources, final)
	}
	update.Anonymous = true
	update.View.VisitorPolicyRevision++
	now = time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
	if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	healthy := f.mustOpen(t, 1, netip.MustParseAddr("198.51.100.1"))
	pendingHTTPResponse(t, healthy.request(t, "/healthy"), http.StatusNoContent)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("denied setup consumed the healthy sibling's only final slot", f.calls.Load(), f.capacity.Load())
	}
}

func TestServiceHTTP2PendingCapacityHasOneConnectionOwnedExchange(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	firstServerRequest := make(chan context.Context, 1)
	var captured atomic.Bool
	compositionHTTPFrontend(t, f, func(frontend *HTTP) {
		admit := frontend.AdmitRequest
		frontend.AdmitRequest = func(r *http.Request) error {
			if admit != nil {
				if err := admit(r); err != nil {
					return err
				}
			}
			if captured.CompareAndSwap(false, true) {
				firstServerRequest <- r.Context()
			}
			return nil
		}
	})
	entered, release := make(chan struct{}), make(chan struct{})
	releaseIngress := sync.OnceFunc(func() { close(release) })
	defer releaseIngress()
	f.ingressMu.Lock()
	f.ingress = func(call context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-call.Done():
			return context.Cause(call)
		}
	}
	f.ingressMu.Unlock()
	v := f.mustOpen(t, 0, pendingHTTPSource(0))
	before := f.current[0].wire.openings.Load()
	if _, err := v.raw.Write(f.metadata(t, v.header, v.source, false)); err != nil {
		t.Fatal(err)
	}
	verification := f.source.verification.Clone()
	verification.NextProtos = []string{"h2"}
	v.secure = tls.Client(v.raw, verification)
	if err := v.secure.HandshakeContext(f.ctx); err != nil {
		t.Fatal(err)
	}
	if v.secure.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("concurrent capacity fixture did not negotiate HTTP/2")
	}
	client := compositionHTTP2Connection(t, f.ctx, v.secure, f.source.prepared.managedHostname)
	defer func() { v.close(); _ = client.Close() }()
	request := func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+f.source.prepared.managedHostname+"/concurrent", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer unchanged-application")
		return client.RoundTrip(req)
	}
	first, cancelFirst := context.WithCancel(f.ctx)
	defer cancelFirst()
	firstResult := make(chan error, 1)
	go func() {
		response, err := request(first)
		if response != nil {
			_ = response.Body.Close()
		}
		firstResult <- err
	}()
	claimedAwait(t, entered)
	const siblings = 8
	type result struct {
		response *http.Response
		err      error
	}
	results := make(chan result, siblings)
	for range siblings {
		go func() { response, err := request(f.ctx); results <- result{response, err} }()
	}
	cancelFirst()
	if err := claimedAwait(t, firstResult); !errors.Is(err, context.Canceled) {
		t.Fatal("one canceled HTTP/2 waiter did not leave its stream", err)
	}
	// RoundTrip can return before the peer processes RST_STREAM. wait for the
	// actual server request cancellation before releasing shared capacity.
	claimedAwait(t, claimedAwait(t, firstServerRequest).Done())
	if f.calls.Load() != 0 {
		t.Fatal("application work preceded the connection's ingress decision", f.calls.Load())
	}
	releaseIngress()
	for range siblings {
		outcome := claimedAwait(t, results)
		if outcome.err != nil {
			t.Fatal("a sibling HTTP/2 request lost shared capacity after another waiter canceled", outcome.err)
		}
		pendingHTTPResponse(t, outcome.response, http.StatusNoContent)
	}
	opened := f.current[0].wire.openings.Load() - before
	if f.calls.Load() != siblings || f.capacity.Load() != 1 || opened != 1 {
		t.Fatal("HTTP/2 requests duplicated final admission, ingress debit, or the actual capacity exchange",
			f.calls.Load(), f.capacity.Load(), opened)
	}
	f.source.bound.mu.Lock()
	pending, final := f.source.bound.httpPending, f.source.bound.reservedStreams
	f.source.bound.mu.Unlock()
	if pending != 0 || final != 1 {
		t.Fatal("concurrent HTTP/2 requests did not share one physical visitor charge", pending, final)
	}
}
