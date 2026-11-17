package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type directShutdownDecision struct {
	sender               uint8
	kind                 tunnelv1.PeerPacketKind
	allowed, packetAlive bool
	beforeCap            bool
	selected             int
}

// only the public envelope is inspected. ICE, consent, both authentication
// layers, path selection, and terminal framing remain production operations.
type directShutdownUDP struct {
	net.PacketConn
	sent, read atomic.Int64
}

func directShutdownData(packet []byte) bool {
	const header, tag = tunnelv1.ConnectorPeerDirectHeaderBytes, tunnelv1.ConnectorPeerDirectTagBytes
	if len(packet) <= header+tag || stun.IsMessage(packet) || packet[0] != tunnelv1.Version {
		return false
	}
	frame, err := tunnelv1.ParsePeerPacket(packet[header : len(packet)-tag])
	return err == nil && frame.Path == peer.Direct && frame.Kind == tunnelv1.PeerData
}

func (p *directShutdownUDP) WriteTo(packet []byte, addr net.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(packet, addr)
	if err == nil && directShutdownData(packet) {
		p.sent.Add(1)
	}
	return n, err
}

func (p *directShutdownUDP) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(packet)
	if err == nil && directShutdownData(packet[:n]) {
		p.read.Add(1)
	}
	return n, addr, err
}

type directShutdownResult struct {
	result tunnelv1.ConnectorVisitorTerminalResult
	joined bool
}

type directShutdownControlStream struct {
	muxsession.Stream
	joined   <-chan struct{}
	results  chan directShutdownResult
	observed chan tunnelv1.ConnectorVisitorTerminalObserved
	input    []byte
	pending  *tunnelv1.ConnectorVisitorTerminalObserved
	session  muxsession.Session
	closing  *atomic.Bool
	retire   func()
}

// entering the next read proves the previous message's actual handler returned
// successfully. a decoded Observed alone is not treated as that dispatch join.
func (s *directShutdownControlStream) Read(p []byte) (int, error) {
	if s.pending != nil {
		s.observed <- *s.pending
		s.pending = nil
	}
	n, err := s.Stream.Read(p)
	if s.session != nil && s.closing != nil && s.closing.Load() && s.retire != nil &&
		muxsession.NormalSessionCloseOnly(err) {
		// only the exact normal end from this fixture's owned session stops its
		// decoder. transport loss and independently failed reads stay failures.
		var application, ended *quic.ApplicationError
		select {
		case <-s.session.Done():
			sessionErr := s.session.Err()
			if muxsession.NormalSessionCloseOnly(sessionErr) &&
				errors.As(err, &application) && errors.As(sessionErr, &ended) && application == ended {
				s.retire()
			}
		default:
		}
	}
	s.input = append(s.input, p[:n]...)
	for len(s.input) >= 4 {
		size := int(binary.BigEndian.Uint32(s.input[:4]))
		if size > tunnelv1.MaxConnectorPermissionBytes {
			s.input = nil
			break
		}
		if len(s.input) < 4+size {
			break
		}
		message, decodeErr := tunnelv1.ReadConnectorControlMessage(bytes.NewReader(s.input[:4+size]))
		if observed, ok := message.(tunnelv1.ConnectorVisitorTerminalObserved); decodeErr == nil && ok {
			s.pending = &observed
		}
		s.input = s.input[4+size:]
	}
	return n, err
}

func directShutdownLifetime(ctx context.Context, until time.Time) (context.Context, context.CancelFunc) {
	// test cancellation is a stop request, not proof that borrowed sessions or
	// control readers joined. fixture cleanup owns this unchanged packet bound.
	return context.WithDeadline(context.WithoutCancel(ctx), until)
}

func (s *directShutdownControlStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	var result tunnelv1.ConnectorVisitorTerminalResult
	if err == nil && n == len(p) && json.Unmarshal(p, &result) == nil && result.Kind == tunnelv1.ConnectorVisitorTerminalResultKind {
		joined := false
		select {
		case <-s.joined:
			joined = true
		default:
		}
		s.results <- directShutdownResult{result: result, joined: joined}
	}
	return n, err
}

type directShutdownSession struct {
	muxsession.Session
	opened atomic.Int64
	resets *directShutdownResets
}

func (s *directShutdownSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	number := s.opened.Add(1)
	stream, err := s.Session.OpenStream(ctx)
	if err == nil && number == 2 {
		// permission control is client stream 0; this sole application is 4.
		return &directShutdownApplicationStream{Stream: stream, resets: s.resets, remote: true}, nil
	}
	return stream, err
}

// retain actual reset objects from the application boundary. matching a code
// somewhere in a joined error is not sufficient to accept its other causes.
type directShutdownResets struct {
	mu     sync.Mutex
	causes map[*quic.StreamError]struct{}
	first  *quic.StreamError
}

func (r *directShutdownResets) record(err error, remote bool) {
	var reset *quic.StreamError
	if !errors.As(err, &reset) || reset == nil || reset.Remote != remote || reset.StreamID != 4 || reset.ErrorCode != 7 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.causes == nil {
		r.causes = make(map[*quic.StreamError]struct{})
	}
	r.causes[reset] = struct{}{}
	if remote && r.first == nil {
		r.first = reset
	}
}

func (r *directShutdownResets) contains(reset *quic.StreamError, remote bool) bool {
	if reset == nil || reset.Remote != remote || reset.StreamID != 4 || reset.ErrorCode != 7 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.causes[reset]
	return ok
}

func (r *directShutdownResets) firstRemote() *quic.StreamError {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.first
}

type directShutdownApplicationStream struct {
	muxsession.Stream
	resets *directShutdownResets
	remote bool
}

func (s *directShutdownApplicationStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	s.resets.record(err, s.remote)
	return n, err
}

func (s *directShutdownApplicationStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	s.resets.record(err, s.remote)
	return n, err
}

func (s *directShutdownApplicationStream) Close() error {
	err := s.Stream.Close()
	s.resets.record(err, s.remote)
	return err
}

func (s *directShutdownApplicationStream) CloseWrite() error {
	err := s.Stream.CloseWrite()
	s.resets.record(err, s.remote)
	return err
}

type directShutdownExpected struct {
	resets         *directShutdownResets
	local          *directShutdownLocal
	resetSent      bool
	allowReset     bool
	remote         bool
	ownedCancel    bool
	observedFailed bool
}

// inspect every branch but report the original aggregate unchanged. uncaptured
// session/control closes, net.ErrClosed, EOF, deadlines, and unknown leaves
// deliberately remain failures until an actual capture establishes provenance.
func (e directShutdownExpected) only(err error) bool {
	if err == nil {
		return true
	}
	if err == context.Canceled {
		return e.ownedCancel
	}
	if err == tunnel.ErrConnectorTerminalFailed {
		return e.observedFailed
	}
	switch cause := err.(type) {
	case *directShutdownLocalInterruption:
		return cause != nil && cause.local == e.local && cause.joinedLocalClose()
	case *quic.StreamError:
		return e.allowReset && e.resetSent && e.resets != nil && e.resets.contains(cause, e.remote)
	case *muxsession.QUICTransportCloseError, *tunnel.SessionCleanupError, *tunnel.ConnectorControlFailure,
		*peer.ConnectivityError, *quic.ApplicationError, *quic.TransportError,
		*quic.IdleTimeoutError, *quic.HandshakeTimeoutError, *quic.StatelessResetError,
		*quic.VersionNegotiationError:
		return false
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return false
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !e.only(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		child := cause.Unwrap()
		return child != nil && e.only(child)
	default:
		return false
	}
}

func directShutdownCheck(t *testing.T, operation string, err error, expected directShutdownExpected) {
	t.Helper()
	if !expected.only(err) {
		t.Errorf("unexpected %s failure, retaining the complete joined error: %v", operation, err)
	}
}

type directShutdownLocal struct {
	net.Conn
	closed       chan struct{}
	peerClosed   *atomic.Bool
	closing      atomic.Bool
	interruption atomic.Pointer[directShutdownLocalInterruption]
	once         sync.Once
	err          error
}

// this private witness preserves the exact error while identifying only I/O
// entered before this connection's successful Close, with its peer still open.
type directShutdownLocalInterruption struct {
	local     *directShutdownLocal
	operation string
	err       error
	peerOpen  bool
}

func (e *directShutdownLocalInterruption) Error() string {
	return "fixture local " + e.operation + " interrupted by its joined Close: " + e.err.Error()
}

func (e *directShutdownLocalInterruption) Unwrap() error { return e.err }

func (e *directShutdownLocalInterruption) joinedLocalClose() bool {
	if e.local == nil || e.err != io.ErrClosedPipe || !e.peerOpen || e.operation != "read" && e.operation != "write" {
		return false
	}
	select {
	case <-e.local.closed:
		return e.local.err == nil
	default:
		return false
	}
}

func (c *directShutdownLocal) enteredOpen() bool {
	return !c.closing.Load() && c.peerClosed != nil && !c.peerClosed.Load()
}

func (c *directShutdownLocal) interrupted(operation string, err error, entered bool) error {
	if err != io.ErrClosedPipe || !entered || !c.closing.Load() || c.peerClosed.Load() {
		return err
	}
	// the copy owner already joins this Close before its second copy result.
	// retain that same physical join, rather than inferring it from cancellation.
	<-c.closed
	if c.err != nil || c.peerClosed.Load() {
		return err
	}
	witness := &directShutdownLocalInterruption{local: c, operation: operation, err: err, peerOpen: true}
	c.interruption.CompareAndSwap(nil, witness)
	return witness
}

func (c *directShutdownLocal) Read(p []byte) (int, error) {
	entered := c.enteredOpen()
	n, err := c.Conn.Read(p)
	return n, c.interrupted("read", err, entered)
}

func (c *directShutdownLocal) Write(p []byte) (int, error) {
	entered := c.enteredOpen()
	n, err := c.Conn.Write(p)
	return n, c.interrupted("write", err, entered)
}

func (c *directShutdownLocal) Close() error {
	c.once.Do(func() {
		c.closing.Store(true)
		c.err = c.Conn.Close()
		close(c.closed)
	})
	return c.err
}

type directShutdownReadStartConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *directShutdownReadStartConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(p)
}

func testDirectShutdownLocalCloseProvenance(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, right := net.Pipe()
	entered := make(chan struct{})
	var peerClosed atomic.Bool
	local := &directShutdownLocal{
		Conn:   &directShutdownReadStartConn{Conn: left, entered: entered},
		closed: make(chan struct{}), peerClosed: &peerClosed,
	}
	var readErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		var one [1]byte
		_, readErr = local.Read(one[:])
	}()
	t.Cleanup(func() {
		if err := local.Close(); err != nil {
			t.Errorf("witness local cleanup: %v", err)
		}
		peerClosed.Store(true)
		if err := right.Close(); err != nil {
			t.Errorf("witness peer cleanup: %v", err)
		}
		<-done
	})
	ownerTeardownAwait(t, ctx, entered)
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	ownerTeardownAwait(t, ctx, done)
	expected := directShutdownExpected{local: local}
	witness := local.interruption.Load()
	if witness == nil || !errors.Is(readErr, witness) || !errors.Is(readErr, io.ErrClosedPipe) || !expected.only(readErr) {
		t.Fatal("actual locally interrupted read lost its private Close witness or original cause", readErr)
	}
	if (directShutdownExpected{local: &directShutdownLocal{}}).only(readErr) {
		t.Fatal("a different local connection borrowed the interruption witness")
	}
	for _, independent := range []error{
		io.ErrClosedPipe, net.ErrClosed, context.Canceled, context.DeadlineExceeded,
		errors.New("independent local cleanup failure"),
		&muxsession.QUICTransportCloseError{Err: readErr},
		&quic.StreamError{StreamID: 0, Remote: true, ErrorCode: 0},
	} {
		joined := errors.Join(readErr, independent)
		if expected.only(joined) {
			t.Errorf("local Close witness hid an independent joined cause: %v", joined)
		}
	}
}

func directShutdownPackets(t *testing.T, ctx context.Context, binding peer.BindingRevision, key [32]byte) [2]*peer.Endpoint {
	t.Helper()
	var paths [2][2]peer.Carrier
	for slot := range 2 {
		left, right := make(chan []byte, 64), make(chan []byte, 64)
		a, closeA := context.WithCancel(ctx)
		b, closeB := context.WithCancel(ctx)
		paths[0][slot] = &ownerTeardownCarrier{ctx: a, cancel: closeA, input: left, output: right, key: key}
		paths[1][slot] = &ownerTeardownCarrier{ctx: b, cancel: closeB, input: right, output: left, key: key}
	}
	var endpoints [2]*peer.Endpoint
	for side := range endpoints {
		var err error
		endpoints[side], err = peer.New(ctx, peer.Config{
			Key: key, Role: uint8(side), Binding: binding, Paths: paths[side], Direct: peer.NewCarrierSlot(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := endpoints[side].Close(); err != nil {
				t.Errorf("packet endpoint cleanup: %v", err)
			}
		})
	}
	return endpoints
}

func directShutdownOwner(ctx context.Context, endpoint *peer.Endpoint) *connectorConnection {
	until, _ := ctx.Deadline()
	scope := connectorTestControlScope()
	serving, stopServing := context.WithCancelCause(context.WithoutCancel(ctx))
	packets, stopPackets := context.WithCancelCause(ctx)
	p := &connectorConnection{
		ctx: serving, packetCtx: packets, packetCancel: stopPackets, endpoint: endpoint,
		cleanup: newConnectorCleanup(ctx, func() context.Context { return ctx }),
		until:   until, preparedUntil: until,
		run: Run{ServiceID: scope.ServiceID, ServiceRunID: scope.ServiceRunID, RunNumber: scope.RunNumber,
			ValidUntil: until, Protocol: "tcp", TrustRevision: 1,
			Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example", Port: 25443}},
		pair: controlv1.ConnectorPeerPair{PairId: scope.PairID, DeliveryGeneration: 1,
			ServiceId: scope.ServiceID, ServiceRunId: scope.ServiceRunID, RunNumber: int64(scope.RunNumber),
			PublisherIdentityId: scope.PublisherIdentityID, BindingState: controlv1.ConnectorPeerPairBindingActive},
		permission: controlv1.VisitorTokenResponse{ExpiresAt: until},
		config:     Config{Protocol: "tcp", MaxConnections: 2},
		active:     make(map[*connectorUse]struct{}), refill: make(chan struct{}, 1),
	}
	p.cleanup.observe(until)
	p.cancel = func(cause error) { p.cleanup.begin(); stopServing(cause) }
	return p
}

// discovery supplies only actual socket addresses. it grants no pair, visitor,
// binding, consent, or terminal authority.
func directShutdownDiscovery(t *testing.T) net.Addr {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buffer [2048]byte
		for {
			n, addr, err := packet.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			message := &stun.Message{Raw: buffer[:n]}
			if message.Decode() != nil || message.Type != stun.BindingRequest {
				continue
			}
			udp, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			response, err := stun.Build(stun.NewTransactionIDSetter(message.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: udp.IP, Port: udp.Port}, stun.Fingerprint)
			if err == nil {
				_, _ = packet.WriteTo(response.Raw, addr)
			}
		}
	}()
	t.Cleanup(func() {
		if err := packet.Close(); err != nil {
			t.Errorf("discovery socket cleanup: %v", err)
		}
		<-done
	})
	return packet.LocalAddr()
}

func TestConnectorDirectTerminalCleanup(t *testing.T) {
	t.Run("real direct packets after serving cancellation", func(t *testing.T) {
		budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
		defer finish()
		until, _ := budget.Deadline()
		ctx, cancel := directShutdownLifetime(budget, until)
		t.Cleanup(cancel)
		scope := connectorTestControlScope()
		binding := peer.BindingRevision{PairID: scope.PairID, Generation: 1}
		key := [32]byte{7, 11, 19}
		endpoints := directShutdownPackets(t, ctx, binding, key)
		p := directShutdownOwner(ctx, endpoints[0])
		var workers sync.WaitGroup
		joinRelease, applicationStop, remoteJoined := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseJoin := sync.OnceFunc(func() { close(joinRelease) })
		stopApplication := sync.OnceFunc(func() { close(applicationStop) })
		var serverSession muxsession.Session
		var serverTransport *quic.Transport
		var listener *quic.Listener
		var control *connectorfixture.JoinedControl
		var sockets [2]*peer.Socket
		var controlDone chan error
		var connectivityDone [2]chan error
		resets := new(directShutdownResets)
		var resetSent atomic.Bool
		var forwarded chan struct{}
		var forwardErr error
		var localConnection *directShutdownLocal
		forwardChecked, observedFailed := false, false
		var remoteCleanupDone chan error
		var closing atomic.Bool
		t.Cleanup(func() {
			closing.Store(true)
			releaseJoin()
			stopApplication()
			p.cancel(context.Canceled)
			if cause := context.Cause(p.packetCtx); cause != nil && ctx.Err() == nil {
				t.Errorf("fixture stopped packets before connector session cleanup: %v", cause)
			}
			closeErr := p.Close(context.WithoutCancel(ctx))
			if serverSession != nil {
				if err := serverSession.Close(); err != nil {
					t.Errorf("server session cleanup: %v", err)
				}
			}
			if control != nil {
				control.Retire()
			}
			cancel()
			if listener != nil {
				if err := listener.Close(); err != nil {
					t.Errorf("inner listener cleanup: %v", err)
				}
			}
			if serverTransport != nil {
				if err := serverTransport.Close(); err != nil {
					t.Errorf("server transport cleanup: %v", err)
				}
			}
			workers.Wait()
			ownedCancel := context.Cause(ctx) == context.Canceled
			application := directShutdownExpected{resets: resets, resetSent: resetSent.Load(),
				allowReset: true, remote: true, ownedCancel: ownedCancel}
			directShutdownCheck(t, "joined connector cleanup", closeErr, application)
			if forwarded != nil && !forwardChecked {
				operation := application
				operation.local = localConnection
				operation.observedFailed = observedFailed
				directShutdownCheck(t, "joined visitor operation after fixture cancellation", forwardErr, operation)
				if localConnection != nil {
					if witness := localConnection.interruption.Load(); witness != nil && !errors.Is(forwardErr, witness) {
						t.Errorf("joined visitor operation lost its witnessed local interruption: %v", forwardErr)
					}
				}
				if resetSent.Load() {
					reset := resets.firstRemote()
					if reset == nil || !errors.Is(forwardErr, reset) {
						t.Errorf("joined visitor operation lost its actual application reset: %v", forwardErr)
					}
				}
			}
			if remoteCleanupDone != nil {
				remote := application
				remote.remote = false
				directShutdownCheck(t, "joined remote application cleanup", <-remoteCleanupDone, remote)
			}
			cancellation := directShutdownExpected{ownedCancel: ownedCancel}
			if controlDone != nil {
				directShutdownCheck(t, "joined terminal control", <-controlDone, cancellation)
			}
			for _, done := range connectivityDone {
				if done != nil {
					directShutdownCheck(t, "joined direct connectivity", <-done, cancellation)
				}
			}
			for _, socket := range sockets {
				if socket != nil {
					if err := socket.Close(); err != nil {
						t.Errorf("physical direct socket cleanup: %v", err)
					}
				}
			}
		})

		root, certificate := providerCertificate(t)
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(root) {
			t.Fatal("fixture certificate root")
		}
		serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, Certificates: []tls.Certificate{certificate}}
		trust := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, RootCAs: roots, ServerName: "db.example"}
		p.run.ServiceTLS = trust
		p.transport, serverTransport = &quic.Transport{Conn: endpoints[0]}, &quic.Transport{Conn: endpoints[1]}
		var err error
		listener, err = serverTransport.Listen(serverTLS, tunnel.ConnectorQUICConfig())
		if err != nil {
			t.Fatal(err)
		}
		p.connection, err = p.transport.Dial(ctx, endpoints[0].RemoteAddr(), trust, tunnel.ConnectorQUICConfig())
		if err != nil {
			t.Fatal(err)
		}
		serverConnection, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		clientSession, err := muxsession.AdoptQUIC(p.connection)
		if err != nil {
			t.Fatal(err)
		}
		counted := &directShutdownSession{Session: clientSession, resets: resets}
		p.session = counted
		serverSession, err = muxsession.AdoptQUIC(serverConnection)
		if err != nil {
			t.Fatal(err)
		}

		var visitorMu sync.Mutex
		var visitor *connectorfixture.JoinedVisitor
		entered := make(chan tunnelv1.ConnectorVisitorTerminalRequest, 1)
		results := make(chan directShutdownResult, 1)
		observed := make(chan tunnelv1.ConnectorVisitorTerminalObserved, 1)
		control = connectorfixture.NewJoinedControl(ctx, scope,
			func(key tunnelv1.ConnectorVisitorTerminalKey) *connectorfixture.JoinedVisitor {
				visitorMu.Lock()
				defer visitorMu.Unlock()
				if visitor != nil && visitor.Key == key {
					return visitor
				}
				return nil
			})
		control.Entered = func(request tunnelv1.ConnectorVisitorTerminalRequest) { entered <- request }
		control.Permission = func(tunnelv1.ConnectorPermissionUpdate, *tunnel.ConnectorPermissionResponder) {
			t.Error("terminal cleanup attempted permission renewal")
		}
		controlDone = make(chan error, 1)
		workers.Go(func() {
			stream, err := tunnel.AcceptConnectorPermissionControl(ctx, serverSession)
			if err == nil {
				var gate tunnel.ConnectorPermissionGate
				err = control.Serve(&directShutdownControlStream{
					Stream: stream, joined: remoteJoined, results: results, observed: observed,
					session: serverSession, closing: &closing, retire: control.Retire,
				}, &gate)
			}
			controlDone <- err
		})
		p.permissions, err = tunnel.OpenConnectorPermissionControl(p.packetCtx, ctx, counted, scope)
		if err != nil {
			t.Fatal(err)
		}
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
		signer := Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice,
			DeviceID: "vdev_aaaaaaaaaaaaaaaaaaaaaa", IdentityID: "ident_aaaaaaaaaaaaaaaaaaaaaa"},
			PublicKey: private.Public().(ed25519.PublicKey), Sign: func(message []byte) []byte { return ed25519.Sign(private, message) }}
		// this is the existing connector preparation fixture boundary, not a
		// substitute authority. production policy/claims remain integration tests.
		entry, err := connectorOpening(signer, tunnelv1.ConnectorPeerVisitorEntry{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
			PairID: scope.PairID, DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1,
			ServiceID: scope.ServiceID, ServiceRunID: scope.ServiceRunID, RunNumber: scope.RunNumber,
			Subject: signer.Subject, SourceIP: "127.0.0.1", VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", MetadataRevision: 1,
		}, "signed-fixture-visitor-permission")
		if err != nil {
			t.Fatal(err)
		}
		unused := entry
		unused.VisitorConnectionID = "vc_bbbbbbbbbbbbbbbbbbbbbb"
		unused, err = connectorOpening(signer, unused, entry.Permission.Token)
		if err != nil {
			t.Fatal(err)
		}
		p.openings = []preparedOpening{{entry: unused, until: until}}
		payload := bytes.Repeat([]byte{0x5a}, 180224)
		ready, echoed := make(chan error, 1), make(chan error, 1)
		var applicationWork atomic.Int64
		remoteCleanupDone = make(chan error, 1)
		workers.Go(func() {
			var cleanupErr error
			defer func() { remoteCleanupDone <- cleanupErr }()
			raw, err := serverSession.AcceptStream(ctx)
			if err != nil {
				cleanupErr = err
				ready <- err
				return
			}
			raw = &directShutdownApplicationStream{Stream: raw, resets: resets}
			if err := raw.SetDeadline(until); err != nil {
				cleanupErr = errors.Join(err, raw.Close())
				ready <- cleanupErr
				return
			}
			got, initial, err := tunnelv1.ReadConnectorPeerVisitorOpening(raw)
			if err != nil || len(initial) != 0 || connectorTerminalKey(got) != connectorTerminalKey(entry) {
				ready <- errors.Join(errors.New("fixture opening changed"), err)
				cleanupErr = errors.Join(err, raw.Close())
				return
			}
			if err = tunnelv1.WriteConnectorPeerVisitorAccepted(raw, got.VisitorConnectionID); err != nil {
				ready <- err
				cleanupErr = errors.Join(err, raw.Close())
				return
			}
			v := connectorfixture.NewJoinedVisitor(ctx, got, until, raw.Close)
			visitorMu.Lock()
			visitor = v
			visitorMu.Unlock()
			remote := tls.Server(raw, serverTLS)
			if err = remote.HandshakeContext(ctx); err != nil {
				ready <- err
				cleanupErr = errors.Join(err, remote.Close())
				v.Join(err)
				return
			}
			ready <- nil
			received := make([]byte, len(payload))
			_, readErr := io.ReadFull(remote, received)
			if readErr == nil && !bytes.Equal(received, payload) {
				readErr = errors.New("direct application transcript changed")
			}
			if readErr == nil {
				applicationWork.Add(1)
				_, readErr = remote.Write(received)
			}
			echoed <- readErr
			select {
			case <-applicationStop:
			case <-ctx.Done():
			}
			// a real application reset enters Abort without ending permission
			// control. the actual remote cleanup callback remains held below.
			resetErr := raw.Reset(7)
			if resetErr == nil {
				resetSent.Store(true)
			}
			closeErr := errors.Join(readErr, resetErr, remote.Close())
			select {
			case <-joinRelease:
			case <-ctx.Done():
				closeErr = errors.Join(closeErr, context.Cause(ctx))
			}
			close(remoteJoined)
			v.Join(closeErr)
			cleanupErr = closeErr
		})
		prepared, err := PrepareConnector(p.ctx, ctx, counted, p.run, entry)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			directShutdownCheck(t, "prepared application cleanup", prepared.Close(), directShutdownExpected{
				resets: resets, resetSent: resetSent.Load(), allowReset: true, remote: true,
				ownedCancel: context.Cause(ctx) == context.Canceled,
			})
		})
		if err := ownerTeardownAwait(t, ctx, ready); err != nil {
			t.Fatal(err)
		}
		p.warm = &connectorUse{entry: entry, prepared: prepared, until: until, terminalKey: connectorTerminalKey(entry), admitted: true}
		p.active[p.warm] = struct{}{}

		discovery := directShutdownDiscovery(t).String()
		connectivityBinding := peer.ConnectivityBinding{Revision: binding, DeliveryID: entry.DeliveryID,
			RelayAddresses: [2]string{discovery, discovery}}
		var udp [2]*directShutdownUDP
		connections := [2]*quic.Conn{p.connection, serverConnection}
		var direct [2]chan struct{}
		outbound, inboundData := make(chan directShutdownDecision, 1), make(chan directShutdownDecision, 1)
		for side := range 2 {
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			udp[side] = &directShutdownUDP{PacketConn: packet}
			socket, err := peer.ListenSocketPacket(ctx, udp[side])
			if err != nil {
				t.Fatal(err)
			}
			sockets[side] = socket
			direct[side] = make(chan struct{})
			var observed sync.Once
			var admit func(tunnelv1.PeerPacket) bool
			if side == 0 {
				admit = func(packet tunnelv1.PeerPacket) bool {
					stopped := p.ctx.Err() != nil
					allowed := p.admitDirectPacket(packet)
					if stopped {
						event := directShutdownDecision{sender: packet.Sender, kind: packet.Kind, allowed: allowed,
							packetAlive: p.packetCtx.Err() == nil, beforeCap: time.Now().Before(p.cleanup.bound(until)),
							selected: endpoints[0].ActivePath()}
						var output chan directShutdownDecision
						if packet.Sender == 0 {
							output = outbound
						} else if packet.Kind == tunnelv1.PeerData {
							output = inboundData
						}
						if output != nil {
							select {
							case output <- event:
							default:
							}
						}
					}
					return allowed
				}
			}
			connectivity := peer.NewConnectivity(socket, connections[side], endpoints[side], side == 0,
				peer.ConnectivityOptions{IncludeLoopback: true, Observe: func(state peer.ConnectivityState) {
					if state == peer.ConnectivityDirect {
						observed.Do(func() { close(direct[side]) })
					}
				}}, admit)
			connectivity.SetBinding(connectivityBinding)
			connectivityDone[side] = make(chan error, 1)
			workers.Go(func() { connectivityDone[side] <- connectivity.Serve(ctx) })
		}
		for side := range 2 {
			ownerTeardownAwait(t, ctx, direct[side])
			if endpoints[side].ActivePath() != peer.Direct || !endpoints[side].PathHealthy(peer.Direct) {
				t.Fatal("connectivity observation did not select an actual healthy direct path", side)
			}
		}
		local, input := net.Pipe()
		var inputClosed atomic.Bool
		t.Cleanup(func() {
			inputClosed.Store(true)
			if err := input.Close(); err != nil {
				t.Errorf("local application input cleanup: %v", err)
			}
		})
		if err := input.SetDeadline(until); err != nil {
			t.Fatal(err)
		}
		closed := &directShutdownLocal{Conn: local, closed: make(chan struct{}), peerClosed: &inputClosed}
		localConnection = closed
		forwarded = make(chan struct{})
		workers.Go(func() { defer close(forwarded); forwardErr = p.Forward(ctx, closed) })
		if _, err := input.Write(payload); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(input, response); err != nil || !bytes.Equal(response, payload) {
			t.Fatal("real direct application delivery failed", err)
		}
		if err := ownerTeardownAwait(t, ctx, echoed); err != nil {
			t.Fatal(err)
		}
		for side := range 2 {
			if udp[side].sent.Load() == 0 || udp[side].read.Load() == 0 || endpoints[side].ActivePath() != peer.Direct {
				t.Fatal("direct selection had no actual bidirectional data evidence", side)
			}
		}
		stopApplication()
		request := ownerTeardownAwait(t, ctx, entered)
		ownerTeardownAwait(t, ctx, closed.closed)
		if request.Key != connectorTerminalKey(entry) || request.Purpose != tunnelv1.ConnectorTerminalAbort || request.TerminalNumber == 0 {
			t.Fatal("real application stop did not enter its exact numbered Abort", request)
		}
		ownerTeardownPending(t, results, "Result preceded the real remote admission join")
		ownerTeardownPending(t, observed, "Observed preceded the real remote admission join")
		ownerTeardownPending(t, forwarded, "visitor returned before the remote admission joined")
		p.cancel(context.Canceled)
		cleanup := p.cleanup.context()
		deadline, _ := cleanup.Deadline()
		if p.packetCtx.Err() != nil || !deadline.After(time.Now()) || deadline.After(until) {
			t.Fatal("serving cancellation lost or enlarged the original packet cleanup interval")
		}
		probe, other := net.Pipe()
		if err := p.Forward(ctx, probe); err != ErrServiceConnection {
			t.Error("stopped serving admitted another application", err)
		}
		if err := probe.Close(); err != nil {
			t.Errorf("rejected local application cleanup: %v", err)
		}
		if err := other.Close(); err != nil {
			t.Errorf("rejected local application peer cleanup: %v", err)
		}
		opened := counted.opened.Load()
		if opened != 2 || applicationWork.Load() != 1 {
			t.Fatal("terminal cleanup opened another stream or repeated application work", opened, applicationWork.Load())
		}
		releaseJoin()
		written := ownerTeardownAwait(t, ctx, results)
		if !written.joined || written.result.TerminalRequest() != request {
			t.Fatal("Result did not follow the actual joined admission or changed its request", written)
		}
		out, in := ownerTeardownAwait(t, ctx, outbound), ownerTeardownAwait(t, ctx, inboundData)
		t.Logf("direct cleanup evidence: selected=%d/%d data_sent=%d/%d data_read=%d/%d outgoing={sender:%d kind:%d allowed:%t path:%d packet_alive:%t before_cap:%t} incoming={sender:%d kind:%d allowed:%t path:%d packet_alive:%t before_cap:%t} original_until=%s",
			endpoints[0].ActivePath(), endpoints[1].ActivePath(), udp[0].sent.Load(), udp[1].sent.Load(), udp[0].read.Load(), udp[1].read.Load(),
			out.sender, out.kind, out.allowed, out.selected, out.packetAlive, out.beforeCap,
			in.sender, in.kind, in.allowed, in.selected, in.packetAlive, in.beforeCap, deadline.Format(time.RFC3339Nano))
		if out.sender != 0 || in.sender != 1 || in.kind != tunnelv1.PeerData {
			t.Fatal("packet decisions did not retain the actual direction and incoming data evidence")
		}
		if !out.packetAlive || !in.packetAlive || !out.beforeCap || !in.beforeCap || out.selected != peer.Direct || in.selected != peer.Direct {
			t.Fatal("packet decisions lack direct-path evidence within the original cleanup cap")
		}
		if !out.allowed {
			t.Errorf("actual outgoing direct packet kind %d was rejected within the retained cleanup interval; this may be a probe, not a terminal message", out.kind)
		}
		if !in.allowed {
			t.Errorf("actual incoming direct PeerData was rejected after the joined Result write while packet cleanup retained its original interval")
		}
		if !out.allowed || !in.allowed {
			return
		}
		observation := ownerTeardownAwait(t, cleanup, observed)
		if observation.TerminalRequest() != request || observation.Outcome != written.result.Outcome ||
			observation.Outcome == tunnelv1.ConnectorTerminalRejected {
			t.Fatal("actual Observed did not match the joined Result", observation)
		}
		observedFailed = observation.Outcome == tunnelv1.ConnectorTerminalFailed
		ownerTeardownAwait(t, cleanup, forwarded)
		forwardChecked = true
		directShutdownCheck(t, "visitor operation", forwardErr, directShutdownExpected{
			resets: resets, local: closed, resetSent: resetSent.Load(), allowReset: true, remote: true,
			observedFailed: observedFailed,
		})
		reset := resets.firstRemote()
		if reset == nil || !errors.Is(forwardErr, reset) {
			t.Errorf("visitor operation lost the actual application reset: %v", forwardErr)
		}
		if errors.Is(forwardErr, tunnel.ErrConnectorTerminalFailed) != observedFailed {
			t.Errorf("visitor operation did not retain its actual observed Result outcome: %v", forwardErr)
		}
		if witness := closed.interruption.Load(); witness != nil && !errors.Is(forwardErr, witness) {
			t.Errorf("visitor operation lost its witnessed local interruption: %v", forwardErr)
		}
		if next, _ := p.cleanup.context().Deadline(); next != deadline || counted.opened.Load() != opened || applicationWork.Load() != 1 {
			t.Fatal("terminal exchange enlarged its interval or restarted application work")
		}
		// cleanup owns cancellation and joins. neither retirement nor fixture
		// cancellation substitutes for the Observed asserted above.
	})

	t.Run("independent fences without a deadline watcher", func(t *testing.T) {
		for _, fence := range []string{"wrong generation", "suspended binding", "expired pair", "expired run", "expired permission", "pending installation", "stale identity", "unstarted cleanup cap", "spent cleanup cap", "canceled cleanup", "canceled packets"} {
			t.Run(fence, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				scope := connectorTestControlScope()
				endpoints := directShutdownPackets(t, ctx, peer.BindingRevision{PairID: scope.PairID, Generation: 1}, [32]byte{3})
				p := directShutdownOwner(ctx, endpoints[0])
				defer p.packetCancel(context.Canceled)
				defer p.cleanup.close()
				packet := tunnelv1.PeerPacket{BindingGeneration: 1, Kind: tunnelv1.PeerData}
				if !p.admitDirectPacket(packet) {
					t.Fatal("live independent-fence fixture rejected its original packet")
				}
				p.cancel(context.Canceled)
				past := time.Now().Add(-time.Second)
				switch fence {
				case "wrong generation":
					packet.BindingGeneration++
				case "suspended binding":
					p.recoveryState = connectorRebinding
					endpoints[0].SuspendBinding()
				case "expired pair":
					p.until = past
				case "expired run":
					p.run.ValidUntil = past
				case "expired permission":
					p.permission.ExpiresAt = past
				case "pending installation":
					p.preparedUntil = time.Time{}
				case "stale identity":
					p.pair.PairId = "cpp_bbbbbbbbbbbbbbbbbbbbbb"
				case "unstarted cleanup cap":
					p.cleanup.mu.Lock()
					p.cleanup.until = time.Time{}
					p.cleanup.mu.Unlock()
				case "spent cleanup cap":
					p.cleanup.mu.Lock()
					p.cleanup.until = past
					p.cleanup.mu.Unlock()
				case "canceled packets":
					p.packetCancel(context.Canceled)
				case "canceled cleanup":
					_ = p.cleanup.context()
					p.cleanup.close()
				}
				if p.admitDirectPacket(packet) {
					t.Fatalf("stopped packet delivery bypassed %s without a watcher", fence)
				}
			})
		}
	})
	t.Run("local interruption provenance", testDirectShutdownLocalCloseProvenance)
}
