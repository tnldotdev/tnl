package peer

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorConnectivityRegressionSignalResetKeepsReaderAndApplication(t *testing.T) {
	f := newConnectivityFixture(t)
	exchange := f.exchange(t)
	exchange()
	ctx, cancel := context.WithCancel(f.ctx)
	signals := make(chan connectivitySignal, 1)
	done := make(chan struct{})
	go func() { defer close(done); readConnectivitySignals(ctx, f.connections[1], signals) }()
	defer func() { cancel(); <-done }()

	for attempt := uint64(1); attempt <= 3; attempt++ {
		out, err := f.connections[0].OpenUniStreamSync(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], 100)
		if _, err := out.Write(append(header[:], '{')); err != nil {
			t.Fatal(err)
		}
		out.CancelWrite(7)
		interrupted := connectivityRegressionSignal(t, f.ctx, signals)
		if !connectivityWasInterrupted(interrupted.err) {
			t.Fatalf("a canceled signaling attempt became terminal: %v", interrupted.err)
		}
		exchange()

		// each replacement must traverse the same reader, including reclaimed
		// unidirectional stream credit, without opening another application stream.
		message := connectivityRegressionMessage(f.binding, attempt)
		if err := writeConnectivitySignal(f.ctx, f.connections[0], message); err != nil {
			t.Fatal(err)
		}
		next := connectivityRegressionSignal(t, f.ctx, signals)
		if next.err != nil || next.message.Attempt != attempt || !connectivityMatches(f.binding, next.message) {
			t.Fatalf("the retained reader did not accept its replacement attempt: %+v, %v", next.message, next.err)
		}
		exchange()
	}
	for _, connection := range f.connections {
		if err := context.Cause(connection.Context()); err != nil {
			t.Fatalf("signaling reset closed the retained connection: %v", err)
		}
	}
}

// the AfterFunc registration occurs after AcceptUniStream. hiding the parent's
// cancellation shortcut makes this a barrier for accepted input, not a sleep or
// a cancellation that might only interrupt an idle accept.
type connectivityRegressionReadContext struct {
	context.Context
	registered chan struct{}
	once       sync.Once
}

func (*connectivityRegressionReadContext) Value(any) any { return nil }

func (c *connectivityRegressionReadContext) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(c.Context, f)
	c.once.Do(func() { close(c.registered) })
	return stop
}

func TestConnectorConnectivityRegressionReadCancellationRetainsApplication(t *testing.T) {
	f := newConnectivityFixture(t)
	exchange := f.exchange(t)
	exchange()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	read := &connectivityRegressionReadContext{Context: ctx, registered: make(chan struct{})}
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := readConnectivitySignal(read, f.connections[1])
		result <- err
	}()
	defer func() { cancel(); <-done }()
	out, err := f.connections[0].OpenUniStreamSync(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer out.CancelWrite(0)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 100)
	if _, err := out.Write(append(header[:], '{')); err != nil {
		t.Fatal(err)
	}
	select {
	case <-read.registered:
	case <-time.After(2 * time.Second):
		t.Fatal("signal reader did not accept the partial stream")
	}
	cancel()
	select {
	case err := <-result:
		if !connectivityWasInterrupted(err) {
			t.Fatalf("canceling an accepted read became terminal: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled signal reader did not join")
	}
	exchange()

	// cancellation owns only the partial read. another signaling read and the
	// original application exchange both remain usable on the retained connection.
	nextCtx, finish := context.WithCancel(f.ctx)
	signals := make(chan connectivitySignal, 1)
	nextDone := make(chan struct{})
	go func() {
		defer close(nextDone)
		message, err := readConnectivitySignal(nextCtx, f.connections[1])
		signals <- connectivitySignal{message: message, err: err}
	}()
	defer func() { finish(); <-nextDone }()
	message := connectivityRegressionMessage(f.binding, 2)
	if err := writeConnectivitySignal(f.ctx, f.connections[0], message); err != nil {
		t.Fatal(err)
	}
	next := connectivityRegressionSignal(t, f.ctx, signals)
	if next.err != nil || next.message.Attempt != message.Attempt {
		t.Fatalf("read cancellation damaged subsequent signaling: %v", next.err)
	}
	exchange()
}

func TestConnectorConnectivityRegressionSelectiveSTUNLossFallsBackAndRecovers(t *testing.T) {
	f := newConnectivityFixture(t)
	exchange := f.exchange(t)
	exchange()
	f.start(t)
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
	exchange()
	connections := f.connections
	var revisions [2]carrierRevision
	var received [2]uint64
	var checks [2]int32
	for side := range 2 {
		revisions[side] = f.endpoints[side].config.Direct.Generation()
		received[side] = f.endpoints[side].Stats(Direct).ReceivedFrames
		checks[side] = f.checks[side].Load()
	}
	for _, gate := range f.gates {
		// discovery and authenticated payload/probe envelopes still pass. blocking
		// requests at both ends also prevents successful consent responses.
		gate.dropChecks.Store(true)
	}
	blocked := time.Now()
	limit := connectivityConsentTimeout + 1500*time.Millisecond
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var continued [2]bool
	for {
		exchange()
		retired := true
		for side := range 2 {
			endpoint := f.endpoints[side]
			next := endpoint.Stats(Direct).ReceivedFrames
			if time.Since(blocked) >= connectivityConsentTimeout/3 && next > received[side] {
				continued[side] = true
			}
			received[side] = next
			retired = retired && endpoint.config.Direct.Generation() != revisions[side] && endpoint.ActivePath() != Direct
		}
		if retired {
			if time.Since(blocked) > limit {
				t.Fatal("direct delivery exceeded its bounded consent expiry")
			}
			break
		}
		select {
		case <-f.ctx.Done():
			t.Fatal(context.Cause(f.ctx))
		case <-deadline.C:
			t.Fatal("direct delivery retained expired STUN consent while payload and packet probes continued")
		case <-ticker.C:
		}
	}
	for side := range 2 {
		if !continued[side] || f.gates[side].dropDirect.Load() {
			t.Fatalf("the consent fault also stopped authenticated packet delivery on side %d", side)
		}
		if !f.endpoints[side].PathHealthy(RelayA) || f.endpoints[side].PathHealthy(Direct) {
			t.Fatalf("side %d did not retain a healthy relay after consent expired", side)
		}
	}
	exchange() // fallback works before consent traffic is restored.
	for _, gate := range f.gates {
		gate.dropChecks.Store(false)
	}
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
	exchange()
	for side := range 2 {
		if f.connections[side] != connections[side] || f.connections[side].Context().Err() != nil || f.checks[side].Load() <= checks[side] {
			t.Fatalf("side %d did not recover with a fresh attempt on the retained connection", side)
		}
		if revision, active := f.endpoints[side].CurrentBinding(); !active || revision != f.binding.Revision {
			t.Fatalf("consent recovery changed binding authority on side %d", side)
		}
	}
}

func TestConnectorConnectivityRegressionConsentDeadlineFencesWithoutWatcher(t *testing.T) {
	local, remote := memoryPair()
	defer remote.Close()
	consent := new(connectivityConsent)
	binding := connectivityPacketBinding{key: [32]byte{3}, generation: 1, attempt: 1, role: 1}
	carrier := connectivityCarrier{Carrier: local, binding: binding, consent: consent}
	slot := NewCarrierSlot()
	defer slot.Close()
	if err := slot.Install(carrier); err != nil {
		t.Fatal(err)
	}
	endpoint := &Endpoint{ctx: t.Context(), config: Config{Direct: slot, PathTimeout: time.Minute}, bindingActive: true}
	for index := range pathCount {
		endpoint.paths[index] = new(path)
	}
	endpoint.paths[Direct] = &path{carrier: slot, revision: slot.Generation(), alive: true, ack: time.Now()}
	until := time.Now().Add(200 * time.Millisecond)
	consent.until.Store(&until)
	if !carrier.DirectConsent() || endpoint.ActivePath() != Direct {
		t.Fatal("fresh consent and packet proof did not permit direct delivery")
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	<-timer.C
	// there is no owner, ICE agent, or deadline watcher in this test. the stored
	// evidence and healthy packet proof are unchanged when the deadline passes.
	if consent.lost.Load() || consent.until.Load() != &until {
		t.Fatal("consent evidence changed without a worker")
	}
	if carrier.DirectConsent() || endpoint.ActivePath() == Direct || endpoint.PathHealthy(Direct) {
		t.Fatal("expired consent remained eligible until a watcher ran")
	}
	if err := carrier.Send(t.Context(), []byte("expired consent")); err != nil || len(remote.in) != 0 {
		t.Fatalf("expired consent reached the physical carrier: %v", err)
	}
	frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{BindingGeneration: 1, Kind: tunnelv1.PeerData, Sender: 0, Path: Direct, Sequence: 1, Total: 3, Payload: []byte("old")}, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := binding.seal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Send(t.Context(), packet); err != nil {
		t.Fatal(err)
	}
	read, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if frame, err := carrier.Receive(read); len(frame) != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("an authenticated packet passed expired consent before worker cleanup: %v", err)
	}
	late := time.Now().Add(time.Minute)
	consent.until.Store(&late)
	if carrier.DirectConsent() || endpoint.ActivePath() == Direct {
		t.Fatal("a late response revived expired consent on the old attempt")
	}
}

func connectivityRegressionMessage(binding ConnectivityBinding, attempt uint64) tunnelv1.ConnectorPeerConnectivity {
	return tunnelv1.ConnectorPeerConnectivity{
		ProtocolVersion: tunnelv1.Version, Kind: "connector_peer_connectivity",
		PairID: binding.Revision.PairID, DeliveryID: binding.DeliveryID, DeliveryGeneration: binding.Revision.Generation,
		Attempt: attempt, UsernameFragment: "test", Password: "abcdefghijklmnopqrstuv",
		Candidates: []string{"1 1 udp 1 127.0.0.1 1234 typ host"},
	}
}

func connectivityRegressionSignal(t *testing.T, ctx context.Context, signals <-chan connectivitySignal) connectivitySignal {
	t.Helper()
	select {
	case signal := <-signals:
		return signal
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	case <-time.After(2 * time.Second):
		t.Fatal("signaling reader did not complete its bounded input")
	}
	return connectivitySignal{}
}
