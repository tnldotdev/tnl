package peer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	RelayA = iota
	RelayB
	Direct

	relayPathCount    = 2
	pathCount         = relayPathCount
	deliveryPathCount = 3
	packetQueue       = 64
	// a fixed ring bounds incomplete fragments independently of sender input.
	reassemblySlots = 64
)

var ErrConfiguration = errors.New("peer packet configuration is invalid")

type Config struct {
	// Key is the stable endpoint-only session key, never a relay envelope key.
	Key   [32]byte
	Role  uint8
	Paths [pathCount]Carrier
	// direct is optional delivery, never evidence of relay authorization.
	Direct *CarrierSlot
	// Binding is the initial active revision. zero defaults to revision one for
	// fixed-carrier users; rebind-capable owners supply the control revision.
	Binding BindingRevision
	// intervals are configurable for network-fault qualification.
	ProbeInterval time.Duration
	PathTimeout   time.Duration
}

type fragment struct {
	sequence uint64
	revision carrierRevision
	total    uint16
	mask     uint8
	data     [tunnelv1.MaxPeerPacketBytes]byte
}

type path struct {
	carrier   Carrier
	queue     chan queuedFrame
	revision  carrierRevision
	closeOnce sync.Once
	closeErr  error
	// health, challenge, and counters are protected by Endpoint.mu.
	alive, failed bool
	ack, sent     time.Time
	challenge     [16]byte
	nonce         [16]byte
	proof         BindingPathProof
	stats         PathStats
	// reassembly and replay history survive binding changes under Endpoint.mu.
	fragments [reassemblySlots]fragment
	highest   uint64
	complete  [reassemblySlots]uint64
}

type queuedFrame struct {
	revision carrierRevision
	data     []byte
	epoch    uint64
	kind     tunnelv1.PeerPacketKind
}

type queuedPacket struct {
	data     []byte
	revision carrierRevision
	endpoint *Endpoint
	epoch    uint64
	direct   bool
}

// caller-buffer copy is the input commit. replacement either follows this
// bounded copy or discards the stale candidate, even after dequeue.
func (p queuedPacket) copyTo(b []byte) (int, bool) {
	if p.endpoint != nil {
		p.endpoint.mu.Lock()
		defer p.endpoint.mu.Unlock()
		if p.endpoint.ctx != nil && p.endpoint.ctx.Err() != nil || !p.endpoint.bindingActive || p.endpoint.bindingEpoch != p.epoch {
			return 0, false
		}
		if p.direct && !p.endpoint.directHealthyLocked(time.Now()) {
			return 0, false
		}
	}
	return p.revision.copyTo(b, p.data)
}

func (p *path) refreshRevisionLocked() {
	if slot, ok := p.carrier.(*CarrierSlot); ok {
		if next := slot.Generation(); next != p.revision {
			p.revision = next
			p.resetHealthLocked()
		}
	}
}

func (p *path) resetHealthLocked() {
	p.alive = false
	p.ack, p.sent = time.Time{}, time.Time{}
	p.challenge, p.nonce = [16]byte{}, [16]byte{}
	p.proof = BindingPathProof{}
	p.stats.RTT = 0
}

func (p *path) close() error {
	p.closeOnce.Do(func() { p.closeErr = p.carrier.Close() })
	return p.closeErr
}

type PathStats struct {
	SentFrames, ReceivedFrames, DroppedFrames uint64
	PeakQueuedFrames                          int
	RTT                                       time.Duration
}

// Endpoint implements net.PacketConn with stable logical addresses. path changes
// only change encrypted packet delivery; QUIC retains every application stream.
// key-bound round trips validate delivery, not target access.
type Endpoint struct {
	config         Config
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	bindingMu      sync.Mutex
	binding        BindingRevision
	bindingEpoch   uint64
	bindingActive  bool
	bindingPending bool
	paths          [deliveryPathCount]*path
	active         int
	seq            atomic.Uint64
	input          chan queuedPacket
	read           deadline
	write          deadline
	wait           sync.WaitGroup
	once           sync.Once
	err            error
}

type logicalAddr struct {
	role uint8
}

func (a logicalAddr) Network() string { return "tnl-peer" }
func (a logicalAddr) String() string {
	if a.role == 0 {
		return "connector"
	}
	return "publisher"
}

func New(parent context.Context, config Config) (*Endpoint, error) {
	if config.Role > 1 || config.Key == [32]byte{} || config.Paths[RelayA] == nil || config.Paths[RelayB] == nil {
		return nil, ErrConfiguration
	}
	if config.ProbeInterval == 0 {
		config.ProbeInterval = time.Second
	}
	if config.PathTimeout == 0 {
		config.PathTimeout = 3 * time.Second
	}
	if config.ProbeInterval < time.Millisecond || config.PathTimeout < 3*config.ProbeInterval {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithCancel(parent)
	if config.Binding == (BindingRevision{}) {
		config.Binding.Generation = 1
	} else if config.Binding.Generation < 1 || !opaqueid.Valid(config.Binding.PairID, "cpp_") ||
		(config.Binding.OperationID != "" || config.Binding.Challenge != "") && !config.Binding.valid() {
		cancel()
		return nil, ErrConfiguration
	}
	e := &Endpoint{config: config, ctx: ctx, cancel: cancel, active: RelayA, input: make(chan queuedPacket, packetQueue), binding: config.Binding, bindingActive: true}
	e.read.changed, e.write.changed = make(chan struct{}), make(chan struct{})
	for index, carrier := range config.Paths {
		if carrier == nil {
			continue
		}
		p := &path{carrier: carrier, queue: make(chan queuedFrame, packetQueue)}
		e.paths[index] = p
	}
	if config.Direct != nil {
		e.paths[Direct] = &path{carrier: config.Direct, queue: make(chan queuedFrame, packetQueue)}
	}
	for index, p := range e.paths {
		if p == nil {
			continue
		}
		e.wait.Go(func() { e.sendLoop(index, p) })
		e.wait.Go(func() { e.receiveLoop(index, p) })
	}
	e.wait.Go(e.probeLoop)
	e.wait.Go(func() {
		<-ctx.Done()
		for _, p := range e.paths {
			if p != nil {
				e.err = errors.Join(e.err, p.close())
			}
		}
	})
	return e, nil
}

func (e *Endpoint) LocalAddr() net.Addr { return logicalAddr{role: e.config.Role} }
func (e *Endpoint) RemoteAddr() net.Addr {
	return logicalAddr{role: 1 - e.config.Role}
}

func (e *Endpoint) ActivePath() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.chooseLocked()
	return e.active
}

// PathHealthy reports fresh packet-probe evidence, not merely the last selected
// path. when every path is down, ActivePath may still name an unusable carrier.
func (e *Endpoint) PathHealthy(index int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if index < 0 || index >= deliveryPathCount || e.paths[index] == nil || e.ctx.Err() != nil {
		return false
	}
	if index == Direct {
		return e.directHealthyLocked(time.Now())
	}
	p := e.paths[index]
	p.refreshRevisionLocked()
	return p.alive && !p.failed && time.Since(p.ack) <= e.config.PathTimeout
}

func (e *Endpoint) Stats(index int) PathStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	if index < 0 || index >= deliveryPathCount || e.paths[index] == nil {
		return PathStats{}
	}
	return e.paths[index].stats
}

func (e *Endpoint) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		timer, changed := e.read.wait()
		select {
		case <-e.ctx.Done():
			timer.Stop()
			return 0, nil, net.ErrClosed
		case <-changed:
			timer.Stop()
			continue
		case <-timer.C:
			return 0, nil, os.ErrDeadlineExceeded
		case packet := <-e.input:
			timer.Stop()
			if e.ctx.Err() != nil {
				return 0, nil, net.ErrClosed
			}
			if e.read.expired() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			if n, current := packet.copyTo(b); current {
				return n, e.RemoteAddr(), nil
			}
		}
	}
}

func (e *Endpoint) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr != e.RemoteAddr() || len(b) == 0 || len(b) > tunnelv1.MaxPeerPacketBytes {
		return 0, tunnelv1.ErrPeerPacket
	}
	if e.write.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	if e.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	e.mu.Lock()
	if !e.bindingActive {
		e.mu.Unlock()
		return len(b), nil
	}
	e.chooseLocked()
	index := e.active
	revision := e.paths[index].revision
	generation := uint64(e.binding.Generation)
	e.mu.Unlock()
	seq := e.seq.Add(1)
	for offset := 0; offset < len(b); offset += tunnelv1.PeerFragmentBytes {
		part := b[offset:min(offset+tunnelv1.PeerFragmentBytes, len(b))]
		e.enqueue(index, tunnelv1.PeerPacket{BindingGeneration: generation, Kind: tunnelv1.PeerData, Sequence: seq, Fragment: uint8(offset / tunnelv1.PeerFragmentBytes), Total: uint16(len(b)), Payload: part}, revision)
	}
	// bounded queues intentionally drop packets; inner QUIC performs recovery.
	return len(b), nil
}

func (e *Endpoint) enqueue(index int, packet tunnelv1.PeerPacket, revision carrierRevision) {
	packet.Sender, packet.Path = e.config.Role, uint8(index)
	e.mu.Lock()
	defer e.mu.Unlock()
	if packet.BindingGeneration == 0 {
		packet.BindingGeneration = uint64(e.binding.Generation)
	}
	if packet.BindingGeneration != uint64(e.binding.Generation) || packet.Kind == tunnelv1.PeerData && !e.bindingActive {
		return
	}
	frame, err := tunnelv1.SignPeerPacketFrame(packet, e.config.Key)
	if err != nil {
		return
	}
	p := e.paths[index]
	if p == nil || p.failed {
		return
	}
	p.refreshRevisionLocked()
	if p.revision != revision || index == Direct && (!e.bindingActive || packet.Kind == tunnelv1.PeerData && !e.directHealthyLocked(time.Now())) {
		p.stats.DroppedFrames++
		return
	}
	select {
	case p.queue <- queuedFrame{revision: revision, data: frame, epoch: e.bindingEpoch, kind: packet.Kind}:
		p.stats.PeakQueuedFrames = max(p.stats.PeakQueuedFrames, len(p.queue))
	default:
		p.stats.DroppedFrames++
	}
}

func (e *Endpoint) sendLoop(index int, p *path) {
	for {
		select {
		case <-e.ctx.Done():
			return
		case frame := <-p.queue:
			ctx, cancel := context.WithTimeout(e.ctx, e.config.PathTimeout)
			var err error
			e.mu.Lock()
			if frame.epoch != e.bindingEpoch || index == Direct && (!e.bindingActive || frame.kind == tunnelv1.PeerData && !e.directHealthyLocked(time.Now())) {
				e.mu.Unlock()
				cancel()
				continue
			}
			if slot, ok := p.carrier.(*CarrierSlot); ok {
				var entered *installedCarrier
				entered, err = slot.enter(ctx, frame.revision)
				if entered == nil && err == context.DeadlineExceeded && ctx.Err() == context.DeadlineExceeded && e.ctx.Err() == nil {
					// admission spent only this packet's budget; no physical send
					// entered, so keep the replaceable path and its worker alive.
					p.stats.DroppedFrames++
					e.mu.Unlock()
					cancel()
					continue
				}
				e.mu.Unlock()
				if entered != nil {
					err = slot.sendEntered(ctx, frame.data, frame.revision, entered)
				}
			} else {
				e.mu.Unlock()
				err = p.carrier.Send(ctx, frame.data)
			}
			cancel()
			if err != nil {
				e.fail(index)
				return
			}
			e.mu.Lock()
			p.stats.SentFrames++
			e.mu.Unlock()
		}
	}
}

func (e *Endpoint) fail(index int) {
	e.mu.Lock()
	p := e.paths[index]
	p.failed, p.alive = true, false
	e.chooseLocked()
	terminal := true
	for _, candidate := range e.paths {
		if candidate != nil && !candidate.failed {
			terminal = false
		}
	}
	e.mu.Unlock()
	// static carriers remain terminal. replaceable slots only fail at shutdown;
	// temporary loss of both slots is bounded by inner QUIC and role authority.
	if terminal {
		e.cancel()
	}
	_ = p.close()
}

func (e *Endpoint) chooseLocked() {
	now := time.Now()
	if e.directHealthyLocked(now) {
		e.active = Direct
		return
	}
	for _, index := range []int{RelayA, RelayB} {
		p := e.paths[index]
		if p == nil {
			continue
		}
		p.refreshRevisionLocked()
		if p.alive && !p.failed && now.Sub(p.ack) <= e.config.PathTimeout {
			e.active = index
			return
		}
	}
	// bound relays can carry encrypted data while their probes recover.
	// choosing a relay does not mark it healthy or change its binding.
	for _, index := range []int{RelayA, RelayB} {
		if p := e.paths[index]; p != nil && !p.failed {
			e.active = index
			return
		}
	}
	// without an eligible relay, retain only the last index for observation.
	// direct is never a speculative fallback; enqueue drops failed relays.
	if e.active == Direct {
		e.active = RelayA
	}
}

func (e *Endpoint) probeLoop() {
	ticker := time.NewTicker(e.config.ProbeInterval)
	defer ticker.Stop()
	for {
		now := time.Now()
		for index, p := range e.paths {
			if p == nil {
				continue
			}
			e.mu.Lock()
			p.refreshRevisionLocked()
			if index == Direct && !e.bindingActive {
				e.mu.Unlock()
				continue
			}
			if now.Sub(p.ack) > e.config.PathTimeout {
				p.alive = false
			}
			// retain a challenge until answered or expired, so a slow path can
			// still prove a round trip without matching only the newest tick.
			if p.challenge == [16]byte{} || now.Sub(p.sent) >= e.config.PathTimeout {
				if _, err := rand.Read(p.nonce[:]); err != nil {
					e.mu.Unlock()
					continue
				}
				p.challenge = p.nonce
				if index < relayPathCount && e.binding.valid() {
					p.challenge, _ = tunnelv1.ConnectorPeerBindingProbe(e.binding.PairID, e.binding.OperationID, e.binding.Generation, e.binding.Challenge, e.config.Role, uint8(index), p.nonce[:])
				}
				p.sent = now
			}
			challenge := p.challenge
			revision := p.revision
			generation := uint64(e.binding.Generation)
			e.chooseLocked()
			e.mu.Unlock()
			e.enqueue(index, tunnelv1.PeerPacket{BindingGeneration: generation, Kind: tunnelv1.PeerProbe, Sequence: e.seq.Add(1), Total: 16, Payload: challenge[:]}, revision)
		}
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Endpoint) receiveLoop(index int, p *path) {
	for {
		var frame []byte
		var revision carrierRevision
		var err error
		if slot, ok := p.carrier.(*CarrierSlot); ok {
			frame, revision, err = slot.receiveRevision(e.ctx)
		} else {
			frame, err = p.carrier.Receive(e.ctx)
		}
		if err != nil {
			e.fail(index)
			return
		}
		packet, ok := authenticatePacket(frame, e.config.Key, e.config.Role, index)
		if !ok {
			continue
		}
		e.mu.Lock()
		p.refreshRevisionLocked()
		if packet.BindingGeneration != uint64(e.binding.Generation) || p.revision != revision {
			e.mu.Unlock()
			continue
		}
		p.stats.ReceivedFrames++
		e.mu.Unlock()
		switch packet.Kind {
		case tunnelv1.PeerProbe:
			e.enqueue(index, tunnelv1.PeerPacket{BindingGeneration: packet.BindingGeneration, Kind: tunnelv1.PeerProbeReply, Sequence: e.seq.Add(1), Total: 16, Payload: packet.Payload}, revision)
		case tunnelv1.PeerProbeReply:
			e.mu.Lock()
			p.refreshRevisionLocked()
			now := time.Now()
			fresh := index != Direct || e.bindingActive && now.Sub(p.sent) <= e.config.PathTimeout
			if fresh && packet.BindingGeneration == uint64(e.binding.Generation) && !p.failed && p.revision == revision && p.challenge != [16]byte{} && hmac.Equal(p.challenge[:], packet.Payload) {
				p.ack, p.alive = now, true
				p.stats.RTT = p.ack.Sub(p.sent)
				p.challenge = [16]byte{}
				if index < relayPathCount {
					p.proof = bindingProof(index, p.nonce, frame)
				}
				e.chooseLocked()
			}
			e.mu.Unlock()
		case tunnelv1.PeerData:
			e.assemble(p, packet, revision)
		}
	}
}

func authenticatePacket(frame []byte, key [32]byte, role uint8, index int) (tunnelv1.PeerPacket, bool) {
	packet, err := tunnelv1.VerifyPeerPacketFrame(frame, key)
	if err != nil || packet.Sender == role || int(packet.Path) != index {
		return packet, false
	}
	return packet, true
}

func (e *Endpoint) assemble(p *path, packet tunnelv1.PeerPacket, revision carrierRevision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx != nil {
		p.refreshRevisionLocked()
		if !e.bindingActive || packet.BindingGeneration != uint64(e.binding.Generation) || p.revision != revision {
			return
		}
		if p == e.paths[Direct] && !e.directHealthyLocked(time.Now()) {
			return
		}
	}
	if packet.Sequence < p.highest && p.highest-packet.Sequence >= reassemblySlots {
		return
	}
	p.highest = max(p.highest, packet.Sequence)
	slot := packet.Sequence % reassemblySlots
	if p.complete[slot] == packet.Sequence {
		return
	}
	f := &p.fragments[slot]
	if f.sequence != packet.Sequence || f.revision != revision {
		*f = fragment{sequence: packet.Sequence, revision: revision, total: packet.Total}
	}
	if f.total != packet.Total {
		return
	}
	copy(f.data[int(packet.Fragment)*tunnelv1.PeerFragmentBytes:], packet.Payload)
	f.mask |= 1 << packet.Fragment
	needed := uint8(1)
	if packet.Total > tunnelv1.PeerFragmentBytes {
		needed = 3
	}
	if f.mask != needed {
		return
	}
	p.complete[slot] = packet.Sequence
	b := append([]byte(nil), f.data[:f.total]...)
	select {
	case e.input <- queuedPacket{data: b, revision: revision, endpoint: e, epoch: e.bindingEpoch, direct: p == e.paths[Direct]}:
	default:
		p.stats.DroppedFrames++
	}
}

func (e *Endpoint) Close() error {
	e.once.Do(func() {
		e.cancel()
		e.wait.Wait()
	})
	return e.err
}

func (e *Endpoint) SetReadDeadline(t time.Time) error  { e.read.set(t); return nil }
func (e *Endpoint) SetWriteDeadline(t time.Time) error { e.write.set(t); return nil }
func (e *Endpoint) SetDeadline(t time.Time) error {
	e.read.set(t)
	e.write.set(t)
	return nil
}

type deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func (d *deadline) set(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.at = at
	close(d.changed)
	d.changed = make(chan struct{})
}

func (d *deadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.at.IsZero() && !time.Now().Before(d.at)
}

func (d *deadline) wait() (*time.Timer, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	wait := time.Duration(1<<63 - 1)
	if !d.at.IsZero() {
		wait = time.Until(d.at)
	}
	return time.NewTimer(wait), d.changed
}
