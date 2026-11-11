package peer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type droppingDirectCarrier struct {
	Carrier
	drop *atomic.Bool
}

func testDirectConsent() bool { return true }

func (c droppingDirectCarrier) Send(ctx context.Context, b []byte) error {
	if c.drop.Load() {
		return nil
	}
	return c.Carrier.Send(ctx, b)
}

func directEndpoints(t *testing.T, ctx context.Context) [2]*Endpoint {
	t.Helper()
	var ends [2]*Endpoint
	for side := range ends {
		e, err := New(ctx, Config{Key: [32]byte{7}, Role: uint8(side), Binding: testBinding(1),
			Paths: [2]Carrier{NewCarrierSlot(), NewCarrierSlot()}, Direct: NewCarrierSlot(),
			ProbeInterval: 5 * time.Millisecond, PathTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		ends[side] = e
		t.Cleanup(func() { _ = e.Close() })
	}
	for index := range pathCount {
		a, b := memoryPair()
		for side, carrier := range []Carrier{a, b} {
			if err := ends[side].config.Paths[index].(*CarrierSlot).Install(carrier); err != nil {
				t.Fatal(err)
			}
		}
	}
	awaitPath(t, ctx, ends[0], ends[1], RelayA)
	return ends
}

func awaitDirectCondition(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("direct delivery condition did not complete", ctx.Err())
		case <-ticker.C:
		}
	}
}

func directFrame(t *testing.T, e *Endpoint, kind tunnelv1.PeerPacketKind, sequence uint64, data []byte) []byte {
	t.Helper()
	binding, _ := e.CurrentBinding()
	frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{BindingGeneration: uint64(binding.Generation),
		Kind: kind, Sender: 1 - e.config.Role, Path: Direct, Sequence: sequence, Total: uint16(len(data)), Payload: data}, e.config.Key)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func directProbe(t *testing.T, ctx context.Context, e *Endpoint, remote Carrier) tunnelv1.PeerPacket {
	t.Helper()
	for {
		frame, err := remote.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := tunnelv1.VerifyPeerPacketFrame(frame, e.config.Key)
		if err != nil || packet.Path != Direct || packet.Sender != e.config.Role {
			t.Fatal("invalid direct probe", err)
		}
		if packet.Kind == tunnelv1.PeerProbe {
			return packet
		}
		if packet.Kind == tunnelv1.PeerData {
			t.Fatal("unexpected direct data", string(packet.Payload))
		}
	}
}

func proveDirect(t *testing.T, ctx context.Context, e *Endpoint, remote Carrier) {
	t.Helper()
	packet := directProbe(t, ctx, e, remote)
	if err := remote.Send(ctx, directFrame(t, e, tunnelv1.PeerProbeReply, packet.Sequence, packet.Payload)); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.PathHealthy(Direct) })
}

func directRead(t *testing.T, e *Endpoint, want string) {
	t.Helper()
	_ = e.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [tunnelv1.MaxPeerPacketBytes]byte
	if n, _, err := e.ReadFrom(buffer[:]); err != nil || string(buffer[:n]) != want {
		t.Fatal("unexpected packet delivery", string(buffer[:n]), err)
	}
}

func TestPeerDirectUpgradeAndFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ends := directEndpoints(t, ctx)
	left, right := ends[0], ends[1]
	before := awaitBindingProofs(t, ctx, left, testBinding(1))
	var drop atomic.Bool
	drop.Store(true)
	a, b := memoryPair()
	for side, carrier := range []Carrier{a, b} {
		if err := ends[side].InstallDirect(testBinding(1), droppingDirectCarrier{Carrier: carrier, drop: &drop}, testDirectConsent); err != nil {
			t.Fatal(err)
		}
	}
	// valid unsolicited data and an unchallenged reply cannot enable direct.
	for _, frame := range [][]byte{
		directFrame(t, left, tunnelv1.PeerData, 42, []byte("unproved")),
		directFrame(t, left, tunnelv1.PeerProbeReply, 43, make([]byte, 16)),
	} {
		if err := b.Send(ctx, frame); err != nil {
			t.Fatal(err)
		}
	}
	awaitDirectCondition(t, ctx, func() bool { return left.Stats(Direct).ReceivedFrames >= 2 })
	if left.PathHealthy(Direct) || left.ActivePath() != RelayA || len(left.input) != 0 {
		t.Fatal("unproved direct traffic enabled packet delivery")
	}
	awaitDirectCondition(t, ctx, func() bool {
		left.mu.Lock()
		defer left.mu.Unlock()
		p := left.paths[Direct]
		return p.challenge != [16]byte{} && p.challenge == p.nonce
	})
	drop.Store(false)
	awaitPath(t, ctx, left, right, Direct)
	for side, sender := range ends {
		if _, err := sender.WriteTo([]byte("direct packet"), sender.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		directRead(t, ends[1-side], "direct packet")
	}
	proofs, ok := left.BindingProofs(testBinding(1))
	if !ok || len(proofs) != 2 || proofs[0].ConnectionSlot != RelayA || proofs[1].ConnectionSlot != RelayB || before[0].ReplyFrame == "" {
		t.Fatal("direct delivery changed the two-relay authorization contract")
	}
	left.mu.Lock()
	directProof := left.paths[Direct].proof
	left.mu.Unlock()
	if directProof != (BindingPathProof{}) {
		t.Fatal("direct probes produced relay authorization evidence")
	}
	// physical removal is visible immediately, without a probe-loop tick.
	if err := left.config.Direct.Install(nil); err != nil {
		t.Fatal(err)
	}
	if left.PathHealthy(Direct) || left.ActivePath() != RelayA {
		t.Fatal("removed direct carrier remained selected")
	}
	if err := right.InstallDirect(testBinding(1), nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := left.WriteTo([]byte("relay after removal"), left.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	directRead(t, right, "relay after removal")
	// a live but blackholed carrier also falls back using timestamp freshness.
	a, b = memoryPair()
	for side, carrier := range []Carrier{a, b} {
		if err := ends[side].InstallDirect(testBinding(1), droppingDirectCarrier{Carrier: carrier, drop: &drop}, testDirectConsent); err != nil {
			t.Fatal(err)
		}
	}
	awaitPath(t, ctx, left, right, Direct)
	drop.Store(true)
	awaitPath(t, ctx, left, right, RelayA)
	if _, err := left.WriteTo([]byte("relay after timeout"), left.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	directRead(t, right, "relay after timeout")
}

func TestPeerDirectSelectionRequiresFreshCurrentCarrier(t *testing.T) {
	slot := NewCarrierSlot()
	defer slot.Close()
	a, b := memoryPair()
	defer b.Close()
	if err := slot.install(a, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	e := &Endpoint{ctx: t.Context(), config: Config{Key: [32]byte{7}, Direct: slot, PathTimeout: time.Second},
		binding: testBinding(1), bindingActive: true, input: make(chan queuedPacket, packetQueue)}
	for index := range pathCount {
		e.paths[index] = &path{queue: make(chan queuedFrame, packetQueue)}
	}
	p := &path{carrier: slot, revision: slot.Generation(), queue: make(chan queuedFrame, packetQueue), alive: true, ack: time.Now()}
	e.paths[Direct] = p
	if e.ActivePath() != Direct {
		t.Fatal("fresh current direct carrier was not preferred")
	}
	packet := tunnelv1.PeerPacket{BindingGeneration: 1, Kind: tunnelv1.PeerData, Sequence: 42, Total: 5, Payload: []byte("fresh")}
	e.assemble(p, packet, slot.Generation())
	var candidate queuedPacket
	select {
	case candidate = <-e.input:
	default:
		t.Fatal("fresh direct data did not reach the input queue")
	}
	// there is no ticker in this test: the stale alive flag stays true.
	p.ack = time.Now().Add(-2 * time.Second)
	if !p.alive || e.PathHealthy(Direct) || e.ActivePath() != RelayA {
		t.Fatal("selection relied on an unexpired alive flag instead of time")
	}
	buffer := []byte("unchanged")
	if n, ok := candidate.copyTo(buffer); n != 0 || ok || string(buffer) != "unchanged" {
		t.Fatal("queued direct data committed after its own probe expired")
	}
	packet.Sequence++
	e.assemble(p, packet, slot.Generation())
	if len(e.input) != 0 || p.highest != 42 {
		t.Fatal("incoming direct data bypassed expired round-trip evidence")
	}
	if _, err := e.WriteTo([]byte("relay fallback"), e.RemoteAddr()); err != nil || len(p.queue) != 0 || len(e.paths[RelayA].queue) != 1 {
		t.Fatal("unproved direct was used as speculative fallback", err)
	}
	e.paths[RelayA].failed, e.paths[RelayB].failed = true, true
	e.active = Direct
	if e.ActivePath() == Direct {
		t.Fatal("direct remained fallback after both relays failed")
	}
	p.ack = time.Now()
	if e.ActivePath() != Direct {
		t.Fatal("fresh direct evidence did not restore delivery")
	}
	if err := slot.Install(nil); err != nil {
		t.Fatal(err)
	}
	if e.PathHealthy(Direct) || e.ActivePath() == Direct || p.alive {
		t.Fatal("slot removal waited for the health ticker")
	}
}

func TestPeerDirectRequiresTimelyOwnProbeReply(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	slot := NewCarrierSlot()
	defer slot.Close()
	a, remote := memoryPair()
	defer remote.Close()
	if err := slot.install(a, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	e := &Endpoint{ctx: ctx, cancel: cancel, config: Config{Key: [32]byte{7}, Role: 1, Direct: slot, PathTimeout: time.Second},
		binding: testBinding(1), bindingActive: true}
	for index := range pathCount {
		e.paths[index] = new(path)
	}
	p := &path{carrier: slot, revision: slot.Generation(), challenge: [16]byte{1}, nonce: [16]byte{1}, sent: time.Now().Add(-2 * time.Second)}
	e.paths[Direct] = p
	// only the receiver runs, so no ticker can rotate the deliberately old nonce.
	e.wait.Go(func() { e.receiveLoop(Direct, p) })
	defer e.Close()
	e.mu.Lock()
	challenge := p.challenge
	e.mu.Unlock()
	old := directFrame(t, e, tunnelv1.PeerProbeReply, 1, challenge[:])
	if err := remote.Send(ctx, old); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.Stats(Direct).ReceivedFrames == 1 })
	if e.PathHealthy(Direct) {
		t.Fatal("a matching but expired challenge enabled direct delivery")
	}
	challenge = [16]byte{2}
	e.mu.Lock()
	p.challenge, p.nonce, p.sent = challenge, challenge, time.Now()
	e.mu.Unlock()
	if err := remote.Send(ctx, old); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.Stats(Direct).ReceivedFrames == 2 })
	if e.PathHealthy(Direct) {
		t.Fatal("an old own-probe reply enabled a newer challenge")
	}
	packet := tunnelv1.PeerPacket{BindingGeneration: 1, Kind: tunnelv1.PeerProbeReply, Path: Direct, Sequence: 3, Total: 16, Payload: challenge[:]}
	for _, mutate := range []func(*tunnelv1.PeerPacket, *[32]byte){
		func(_ *tunnelv1.PeerPacket, key *[32]byte) { key[0]++ },
		func(p *tunnelv1.PeerPacket, _ *[32]byte) { p.Sender = 1 },
		func(p *tunnelv1.PeerPacket, _ *[32]byte) { p.Path = RelayA },
		func(p *tunnelv1.PeerPacket, _ *[32]byte) { p.BindingGeneration++ },
	} {
		invalid, key := packet, e.config.Key
		mutate(&invalid, &key)
		frame, err := tunnelv1.SignPeerPacketFrame(invalid, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Send(ctx, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := remote.Send(ctx, directFrame(t, e, tunnelv1.PeerProbeReply, 4, challenge[:])); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.PathHealthy(Direct) })
	if stats := e.Stats(Direct); stats.ReceivedFrames != 3 {
		t.Fatal("forged direct replies changed authenticated counters", stats)
	}
}

func TestPeerDirectBindingStagesAndSuspends(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ends := directEndpoints(t, ctx)
	a, b := memoryPair()
	for side, carrier := range []Carrier{a, b} {
		if err := ends[side].InstallDirect(testBinding(1), carrier, testDirectConsent); err != nil {
			t.Fatal(err)
		}
	}
	awaitPath(t, ctx, ends[0], ends[1], Direct)
	if _, err := ends[0].WriteTo([]byte("before stage"), ends[0].RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	var stale queuedPacket
	select {
	case stale = <-ends[1].input:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sequence := ends[0].seq.Load()
	next := testBinding(2)
	for _, e := range ends {
		if binding, active := e.CurrentBinding(); binding != testBinding(1) || !active {
			t.Fatal("initial active binding was not exposed")
		}
		if err := e.StageBinding(next); err != nil {
			t.Fatal(err)
		}
		if binding, active := e.CurrentBinding(); binding != next || active || e.PathHealthy(Direct) {
			t.Fatal("staging retained active direct authority")
		}
		e.config.Direct.mu.Lock()
		present := e.config.Direct.current != nil
		e.config.Direct.mu.Unlock()
		if present {
			t.Fatal("staging retained its old direct carrier")
		}
		rejected, remote := memoryPair()
		defer remote.Close()
		if err := e.InstallDirect(next, rejected, testDirectConsent); !errors.Is(err, ErrConfiguration) {
			t.Fatal("pending binding accepted direct installation", err)
		}
		awaitEndpointSignal(t, ctx, rejected.stop)
	}
	buffer := []byte("unchanged")
	if n, ok := stale.copyTo(buffer); n != 0 || ok || string(buffer) != "unchanged" {
		t.Fatal("old direct input committed after staging")
	}
	for index := range pathCount {
		a, b := memoryPair()
		for side, carrier := range []Carrier{a, b} {
			if err := ends[side].InstallBindingCarrier(next, index, carrier); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, e := range ends {
		var proofs [2]BindingPathProof = awaitBindingProofs(t, ctx, e, next)
		if len(proofs) != 2 {
			t.Fatal("activation demanded a direct authorization proof")
		}
		if err := e.ActivateBinding(next); err != nil {
			t.Fatal(err)
		}
		if binding, active := e.CurrentBinding(); binding != next || !active {
			t.Fatal("activated binding snapshot was not current")
		}
	}
	ends[1].mu.Lock()
	highest := ends[1].paths[Direct].highest
	ends[1].mu.Unlock()
	if ends[0].seq.Load() < sequence || highest == 0 {
		t.Fatal("binding stage reset direct replay or sender counters")
	}
	a, b = memoryPair()
	for side, carrier := range []Carrier{a, b} {
		if err := ends[side].InstallDirect(next, carrier, testDirectConsent); err != nil {
			t.Fatal(err)
		}
	}
	awaitPath(t, ctx, ends[0], ends[1], Direct)
	// even with a current authenticated envelope, old packet counters stay spent.
	if err := a.Send(ctx, directFrame(t, ends[1], tunnelv1.PeerData, highest, []byte("replayed after stage"))); err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, directFrame(t, ends[1], tunnelv1.PeerData, highest+1, []byte("fresh after stage"))); err != nil {
		t.Fatal(err)
	}
	directRead(t, ends[1], "fresh after stage")
	revision := ends[0].config.Direct.Generation()
	if err := ends[0].InstallDirect(testBinding(1), nil, nil); !errors.Is(err, ErrConfiguration) || ends[0].config.Direct.Generation() != revision {
		t.Fatal("stale owner removed a newer direct installation", err)
	}
	ends[0].SuspendBinding()
	if binding, active := ends[0].CurrentBinding(); binding != next || active || ends[0].PathHealthy(Direct) {
		t.Fatal("suspension retained direct authority")
	}
	select {
	case <-a.stop:
		t.Fatal("suspension performed physical cleanup under the role lock")
	default:
	}
	rejected, remote := memoryPair()
	defer remote.Close()
	if err := ends[0].InstallDirect(next, rejected, testDirectConsent); !errors.Is(err, ErrConfiguration) {
		t.Fatal("suspended binding accepted a nonnil direct installation", err)
	}
	awaitEndpointSignal(t, ctx, rejected.stop)
	if err := ends[0].InstallDirect(next, nil, nil); err != nil {
		t.Fatal("exact suspended binding could not remove direct delivery", err)
	}
	awaitEndpointSignal(t, ctx, a.stop)
	if err := ends[0].ActivateBinding(next); !errors.Is(err, ErrConfiguration) {
		t.Fatal("direct evidence resurrected a suspended binding", err)
	}
}

func TestPeerDirectReplacementRetainsReplayAndFencesQueues(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	e := directEndpoints(t, ctx)[0]
	a, remote := memoryPair()
	defer remote.Close()
	if err := e.InstallDirect(testBinding(1), a, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	proveDirect(t, ctx, e, remote)
	if err := remote.Send(ctx, directFrame(t, e, tunnelv1.PeerData, 42, []byte("old input"))); err != nil {
		t.Fatal(err)
	}
	var stale queuedPacket
	select {
	case stale = <-e.input:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	oldProbe := directProbe(t, ctx, e, remote)
	prior := e.config.Direct.Generation()
	sequence, stats := e.seq.Load(), e.Stats(Direct)
	next, successor := memoryPair()
	defer successor.Close()
	if err := e.InstallDirect(testBinding(1), next, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	buffer := []byte("untouched")
	if n, ok := stale.copyTo(buffer); n != 0 || ok || string(buffer) != "untouched" {
		t.Fatal("dequeued input survived direct replacement")
	}
	if err := successor.Send(ctx, directFrame(t, e, tunnelv1.PeerProbeReply, oldProbe.Sequence, oldProbe.Payload)); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.Stats(Direct).ReceivedFrames > stats.ReceivedFrames })
	if e.PathHealthy(Direct) {
		t.Fatal("predecessor's probe enabled its replacement")
	}
	newProbe := directProbe(t, ctx, e, successor)
	if bytes.Equal(oldProbe.Payload, newProbe.Payload) {
		t.Fatal("replacement reused its predecessor's challenge")
	}
	if err := successor.Send(ctx, directFrame(t, e, tunnelv1.PeerProbeReply, newProbe.Sequence, newProbe.Payload)); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.PathHealthy(Direct) })
	for sequence, data := range map[uint64]string{42: "replayed", 43: "fresh input"} {
		if err := successor.Send(ctx, directFrame(t, e, tunnelv1.PeerData, sequence, []byte(data))); err != nil {
			t.Fatal(err)
		}
	}
	directRead(t, e, "fresh input")
	// an already-dequeued output candidate still carries its old slot revision.
	frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{BindingGeneration: 1, Sender: e.config.Role, Path: Direct,
		Kind: tunnelv1.PeerData, Sequence: e.seq.Add(1), Total: 9, Payload: []byte("old queue")}, e.config.Key)
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	epoch := e.bindingEpoch
	e.mu.Unlock()
	e.paths[Direct].queue <- queuedFrame{revision: prior, data: frame, epoch: epoch, kind: tunnelv1.PeerData}
	if _, err := e.WriteTo([]byte("fresh output"), e.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := successor.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := tunnelv1.VerifyPeerPacketFrame(frame, e.config.Key)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Kind == tunnelv1.PeerData {
			if string(packet.Payload) != "fresh output" {
				t.Fatal("old direct queue escaped through its successor", string(packet.Payload))
			}
			break
		}
	}
	_ = e.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := e.ReadFrom(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("replay reached the packet reader", err)
	}
	if e.seq.Load() <= sequence || e.Stats(Direct).ReceivedFrames < stats.ReceivedFrames || e.Stats(Direct).SentFrames < stats.SentFrames {
		t.Fatal("direct replacement reset packet counters")
	}
}

func TestPeerDirectClosedSlotDoesNotBlockRelayBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ends := directEndpoints(t, ctx)
	binding := testBinding(2)
	for _, e := range ends {
		if err := e.config.Direct.Close(); err != nil {
			t.Fatal(err)
		}
		if err := e.StageBinding(binding); err != nil {
			t.Fatal("optional direct failure blocked relay binding", err)
		}
	}
	for index := range pathCount {
		a, b := memoryPair()
		for side, carrier := range []Carrier{a, b} {
			if err := ends[side].InstallBindingCarrier(binding, index, carrier); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, e := range ends {
		awaitBindingProofs(t, ctx, e, binding)
		if err := e.ActivateBinding(binding); err != nil {
			t.Fatal("two current relay proofs could not resume delivery", err)
		}
	}
}

type heldDirectDataCarrier struct{ *heldEndpointCarrier }

func (c heldDirectDataCarrier) Send(ctx context.Context, b []byte) error {
	packet, err := tunnelv1.ParsePeerPacket(b)
	if err == nil && packet.Kind == tunnelv1.PeerData {
		return c.call(ctx)
	}
	return c.Carrier.Send(ctx, b)
}

func TestPeerDirectBoundedQueueAndReplacementSerializesBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ends := directEndpoints(t, ctx)
	e := ends[0]
	a, b := memoryPair()
	held := &heldEndpointCarrier{Carrier: a, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	if err := e.InstallDirect(testBinding(1), heldDirectDataCarrier{held}, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	if err := ends[1].InstallDirect(testBinding(1), b, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	awaitPath(t, ctx, e, ends[1], Direct)
	if _, err := e.WriteTo([]byte("blocked"), e.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	awaitEndpointSignal(t, ctx, held.entered)
	for range 1000 {
		if _, err := e.WriteTo([]byte("bounded"), e.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
	}
	if stats := e.Stats(Direct); stats.PeakQueuedFrames != packetQueue || stats.DroppedFrames == 0 {
		t.Fatal("direct backpressure escaped its bounded queue", stats)
	}
	next, successor := memoryPair()
	defer successor.Close()
	installed := make(chan error, 1)
	go func() { installed <- e.InstallDirect(testBinding(1), next, testDirectConsent) }()
	awaitEndpointSignal(t, ctx, held.canceled)
	awaitEndpointSignal(t, ctx, held.closed)
	// selection and relay delivery do not wait for a physical direct call to join.
	progress := make(chan error, 1)
	go func() {
		if e.PathHealthy(Direct) || e.ActivePath() != RelayA {
			progress <- errors.New("joining direct carrier remained selected")
			return
		}
		_, err := e.WriteTo([]byte("relay while joining"), e.RemoteAddr())
		progress <- err
	}()
	select {
	case err := <-progress:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("direct cleanup held the endpoint state lock", ctx.Err())
	}
	directRead(t, ends[1], "relay while joining")
	staged := make(chan error, 1)
	go func() { staged <- e.StageBinding(testBinding(2)) }()
	select {
	case err := <-installed:
		t.Fatal("replacement did not join entered direct output", err)
	case err := <-staged:
		t.Fatal("binding stage bypassed the in-flight installation", err)
	default:
	}
	release()
	for _, result := range []<-chan error{installed, staged} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("direct replacement or stage did not join", ctx.Err())
		}
	}
	awaitEndpointSignal(t, ctx, next.stop)
	if binding, active := e.CurrentBinding(); binding != testBinding(2) || active || e.PathHealthy(Direct) {
		t.Fatal("old direct installation followed the newer staged binding")
	}
}

func TestPeerDirectBindingCutAndWorkerJoinWithoutEndpointLock(t *testing.T) {
	for _, suspend := range []bool{false, true} {
		t.Run(map[bool]string{false: "stage", true: "suspend"}[suspend], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			e := directEndpoints(t, ctx)[0]
			a, b := memoryPair()
			defer b.Close()
			held := &heldEndpointCarrier{Carrier: a, read: true, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
			release := sync.OnceFunc(func() { close(held.release) })
			defer release()
			if err := e.InstallDirect(testBinding(1), held, testDirectConsent); err != nil {
				t.Fatal(err)
			}
			awaitEndpointSignal(t, ctx, held.entered)
			cut := make(chan error, 1)
			go func() {
				if suspend {
					e.SuspendBinding()
					cut <- nil
					return
				}
				cut <- e.StageBinding(testBinding(2))
			}()
			if suspend {
				select {
				case err := <-cut:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("in-memory suspension waited for physical cleanup", ctx.Err())
				}
				select {
				case <-held.canceled:
					t.Fatal("suspension canceled physical carrier work")
				case <-held.closed:
					t.Fatal("suspension closed its carrier")
				default:
				}
				// the connectivity worker performs teardown outside role locks.
				go func() { cut <- e.InstallDirect(testBinding(1), nil, nil) }()
			}
			awaitEndpointSignal(t, ctx, held.canceled)
			progress := make(chan bool, 1)
			go func() {
				_, active := e.CurrentBinding()
				progress <- !active && !e.PathHealthy(Direct) && e.ActivePath() != Direct
			}()
			select {
			case fenced := <-progress:
				if !fenced {
					t.Fatal("binding cut did not fence direct input before joining")
				}
			case <-ctx.Done():
				t.Fatal("binding cut held endpoint state during its join", ctx.Err())
			}
			select {
			case err := <-cut:
				t.Fatal("binding cut did not join direct input", err)
			default:
			}
			release()
			select {
			case err := <-cut:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("binding cut did not finish", ctx.Err())
			}
		})
	}
}

func TestPeerDirectSuspendDoesNotWaitForInstallation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	e := directEndpoints(t, ctx)[0]
	a, b := memoryPair()
	defer b.Close()
	held := &heldEndpointCarrier{Carrier: a, read: true, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	if err := e.InstallDirect(testBinding(1), held, testDirectConsent); err != nil {
		t.Fatal(err)
	}
	awaitEndpointSignal(t, ctx, held.entered)
	next, successor := memoryPair()
	defer successor.Close()
	installed := make(chan error, 1)
	go func() { installed <- e.InstallDirect(testBinding(1), next, testDirectConsent) }()
	awaitEndpointSignal(t, ctx, held.canceled)
	suspended := make(chan struct{})
	go func() { e.SuspendBinding(); close(suspended) }()
	awaitEndpointSignal(t, ctx, suspended)
	if _, active := e.CurrentBinding(); active || e.PathHealthy(Direct) || e.ActivePath() == Direct {
		t.Fatal("suspension did not immediately fence the in-flight installation")
	}
	select {
	case err := <-installed:
		t.Fatal("installation returned before predecessor joined", err)
	default:
	}
	release()
	select {
	case err := <-installed:
		if !errors.Is(err, ErrConfiguration) {
			t.Fatal("installation ignored concurrent suspension", err)
		}
	case <-ctx.Done():
		t.Fatal("suspended installation did not join", ctx.Err())
	}
	awaitEndpointSignal(t, ctx, next.stop)
	if err := e.InstallDirect(testBinding(1), nil, nil); err != nil {
		t.Fatal("exact-binding worker teardown failed after suspension", err)
	}
}

func TestPeerDirectRejectedInstallTransfersOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	e := directEndpoints(t, ctx)[0]
	for _, binding := range []BindingRevision{testBinding(2), {Generation: 1},
		{PairID: testBinding(1).PairID, Generation: 1, OperationID: "different", Challenge: testBinding(1).Challenge}} {
		a, b := memoryPair()
		defer b.Close()
		if err := e.InstallDirect(binding, a, testDirectConsent); !errors.Is(err, ErrConfiguration) {
			t.Fatal("mismatched binding installed direct delivery", err)
		}
		awaitEndpointSignal(t, ctx, a.stop)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	a, b := memoryPair()
	defer b.Close()
	if err := e.InstallDirect(testBinding(1), a, testDirectConsent); !errors.Is(err, ErrConfiguration) {
		t.Fatal("closed endpoint accepted direct delivery", err)
	}
	awaitEndpointSignal(t, ctx, a.stop)
	if _, active := e.CurrentBinding(); active {
		t.Fatal("closed endpoint exposed active delivery")
	}
	// opting out of direct delivery does not permit an installation to leak.
	left, leftPeer := memoryPair()
	defer leftPeer.Close()
	right, rightPeer := memoryPair()
	defer rightPeer.Close()
	without, err := New(ctx, Config{Key: [32]byte{7}, Paths: [2]Carrier{left, right}})
	if err != nil {
		t.Fatal(err)
	}
	defer without.Close()
	a, b = memoryPair()
	defer b.Close()
	if err := without.InstallDirect(BindingRevision{Generation: 1}, a, testDirectConsent); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unconfigured direct slot accepted an installation", err)
	}
	awaitEndpointSignal(t, ctx, a.stop)
}

type methodConsentCarrier struct{ Carrier }

func (methodConsentCarrier) DirectConsent() bool { return true }

func TestPeerDirectRequiresExplicitConsentAcrossWrappers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	e := directEndpoints(t, ctx)[0]
	for _, exposeMethod := range []bool{true, false} {
		local, remote := memoryPair()
		defer remote.Close()
		var carrier Carrier = methodConsentCarrier{local}
		if !exposeMethod {
			carrier = struct{ Carrier }{carrier}
		}
		if err := e.InstallDirect(testBinding(1), carrier, nil); !errors.Is(err, ErrConfiguration) {
			t.Fatal("carrier methods substituted for explicit consent", err)
		}
		awaitEndpointSignal(t, ctx, local.stop)
	}
	local, remote := memoryPair()
	defer remote.Close()
	var consent atomic.Bool
	// the outer carrier deliberately hides the misleading inner consent method.
	wrapped := struct{ Carrier }{methodConsentCarrier{local}}
	if err := e.InstallDirect(testBinding(1), wrapped, consent.Load); err != nil {
		t.Fatal(err)
	}
	probe := directProbe(t, ctx, e, remote)
	if err := remote.Send(ctx, directFrame(t, e, tunnelv1.PeerProbeReply, probe.Sequence, probe.Payload)); err != nil {
		t.Fatal(err)
	}
	awaitDirectCondition(t, ctx, func() bool { return e.Stats(Direct).RTT > 0 })
	if e.PathHealthy(Direct) || e.ActivePath() == Direct {
		t.Fatal("packet proof enabled direct delivery without consent")
	}
	consent.Store(true)
	awaitDirectCondition(t, ctx, func() bool { return e.PathHealthy(Direct) && e.ActivePath() == Direct })
	consent.Store(false)
	if e.PathHealthy(Direct) || e.ActivePath() == Direct {
		t.Fatal("wrapper hid expired consent")
	}
}
