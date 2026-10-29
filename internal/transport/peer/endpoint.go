package peer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	RelayA = iota
	RelayB
	Direct
	pathCount
	packetQueue = 64
	// a fixed ring bounds incomplete fragments independently of sender input.
	reassemblySlots = 64
	// preserve the native frame MAC domain independently of carrier selection.
	nativePacketDomain = "native_peer"
)

var ErrConfiguration = errors.New("peer packet configuration is invalid")

type Config struct {
	// key and role belong to one exact authorized peer pair, never an installation.
	Key   [32]byte
	Role  uint8
	Paths [pathCount]Carrier
	// intervals are configurable for network-fault qualification.
	ProbeInterval time.Duration
	PathTimeout   time.Duration
}

type fragment struct {
	sequence uint64
	total    uint16
	mask     uint8
	data     [tunnelv1.MaxPeerPacketBytes]byte
}

type path struct {
	carrier    Carrier
	queue      chan queuedFrame
	generation uint64
	closeOnce  sync.Once
	closeErr   error
	// health, challenge, and counters are protected by Endpoint.mu.
	alive, failed bool
	ack, sent     time.Time
	challenge     [16]byte
	stats         PathStats
	// one receiver owns this bounded reassembly ring and replay window.
	fragments [reassemblySlots]fragment
	highest   uint64
	complete  [reassemblySlots]uint64
}

type queuedFrame struct {
	generation uint64
	data       []byte
}

type changingCarrier interface {
	Generation() uint64
	SendGeneration(context.Context, []byte, uint64) error
}

func (p *path) refreshGenerationLocked() {
	if carrier, ok := p.carrier.(changingCarrier); ok {
		if next := carrier.Generation(); p.generation != next {
			p.generation = next
			p.alive = false
			p.ack = time.Time{}
			p.challenge = [16]byte{}
		}
	}
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
// ICE consent and these key-bound round trips validate delivery, not target access.
type Endpoint struct {
	config Config
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	paths  [pathCount]*path
	active int
	seq    atomic.Uint64
	input  chan []byte
	read   deadline
	write  deadline
	wait   sync.WaitGroup
	once   sync.Once
	err    error
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
	e := &Endpoint{config: config, ctx: ctx, cancel: cancel, active: RelayA, input: make(chan []byte, packetQueue)}
	e.read.changed, e.write.changed = make(chan struct{}), make(chan struct{})
	for index, carrier := range config.Paths {
		if carrier == nil {
			continue
		}
		p := &path{carrier: carrier, queue: make(chan queuedFrame, packetQueue)}
		e.paths[index] = p
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
	return e.active
}

// PathHealthy reports fresh packet-probe evidence, not merely the last selected
// path. when every path is down, ActivePath may still name an unusable carrier.
func (e *Endpoint) PathHealthy(index int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if index < 0 || index >= pathCount || e.paths[index] == nil || e.ctx.Err() != nil {
		return false
	}
	p := e.paths[index]
	p.refreshGenerationLocked()
	return p.alive && !p.failed && time.Since(p.ack) <= e.config.PathTimeout
}

func (e *Endpoint) Stats(index int) PathStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	if index < 0 || index >= pathCount || e.paths[index] == nil {
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
			return copy(b, packet), e.RemoteAddr(), nil
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
	for _, p := range e.paths {
		if p != nil {
			p.refreshGenerationLocked()
		}
	}
	e.chooseLocked()
	index := e.active
	e.mu.Unlock()
	seq := e.seq.Add(1)
	for offset := 0; offset < len(b); offset += tunnelv1.PeerFragmentBytes {
		part := b[offset:min(offset+tunnelv1.PeerFragmentBytes, len(b))]
		e.enqueue(index, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: seq, Fragment: uint8(offset / tunnelv1.PeerFragmentBytes), Total: uint16(len(b)), Payload: part})
	}
	// bounded queues intentionally drop packets; inner QUIC performs recovery.
	return len(b), nil
}

func (e *Endpoint) enqueue(index int, packet tunnelv1.PeerPacket) {
	packet.Sender, packet.Path = e.config.Role, uint8(index)
	unsigned, err := packet.AuthenticatedBytes()
	if err != nil {
		return
	}
	mac := hmac.New(sha256.New, e.config.Key[:])
	_, _ = mac.Write([]byte(nativePacketDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(unsigned)
	copy(packet.MAC[:], mac.Sum(nil))
	frame, _ := packet.MarshalBinary()
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.paths[index]
	if p == nil || p.failed {
		return
	}
	p.refreshGenerationLocked()
	if index == Direct && packet.Kind == tunnelv1.PeerData && !p.alive {
		p.stats.DroppedFrames++
		return
	}
	select {
	case p.queue <- queuedFrame{p.generation, frame}:
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
			if changing, ok := p.carrier.(changingCarrier); ok {
				err = changing.SendGeneration(ctx, frame.data, frame.generation)
			} else {
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
	e.mu.Unlock()
	_ = p.close()
}

func (e *Endpoint) chooseLocked() {
	for _, index := range []int{Direct, RelayA, RelayB} {
		if p := e.paths[index]; p != nil && p.alive && !p.failed {
			e.active = index
			return
		}
	}
	// bound relays can carry encrypted data while their probes recover. do not
	// retain an unhealthy direct path when one of those carriers is available;
	// choosing a relay does not mark it healthy or change its binding.
	for _, index := range []int{RelayA, RelayB} {
		if p := e.paths[index]; p != nil && !p.failed {
			e.active = index
			return
		}
	}
	// without an eligible relay, retain only the last index for observation.
	// enqueue still drops failed carriers and unhealthy direct data.
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
			p.refreshGenerationLocked()
			if now.Sub(p.ack) > e.config.PathTimeout {
				p.alive = false
			}
			// retain a challenge until answered or expired, so a slow path can
			// still prove a round trip without matching only the newest tick.
			if p.challenge == [16]byte{} || now.Sub(p.sent) >= e.config.PathTimeout {
				if _, err := rand.Read(p.challenge[:]); err != nil {
					e.mu.Unlock()
					continue
				}
				p.sent = now
			}
			challenge := p.challenge
			e.chooseLocked()
			e.mu.Unlock()
			e.enqueue(index, tunnelv1.PeerPacket{Kind: tunnelv1.PeerProbe, Sequence: e.seq.Add(1), Total: 16, Payload: challenge[:]})
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
		frame, err := p.carrier.Receive(e.ctx)
		if err != nil {
			e.fail(index)
			return
		}
		packet, ok := authenticatePacket(frame, e.config.Key, e.config.Role, index)
		if !ok {
			continue
		}
		e.mu.Lock()
		p.stats.ReceivedFrames++
		e.mu.Unlock()
		switch packet.Kind {
		case tunnelv1.PeerProbe:
			e.enqueue(index, tunnelv1.PeerPacket{Kind: tunnelv1.PeerProbeReply, Sequence: e.seq.Add(1), Total: 16, Payload: packet.Payload})
		case tunnelv1.PeerProbeReply:
			e.mu.Lock()
			p.refreshGenerationLocked()
			if p.challenge != [16]byte{} && hmac.Equal(p.challenge[:], packet.Payload) {
				p.ack, p.alive = time.Now(), true
				p.stats.RTT = p.ack.Sub(p.sent)
				p.challenge = [16]byte{}
				e.chooseLocked()
			}
			e.mu.Unlock()
		case tunnelv1.PeerData:
			e.assemble(p, packet)
		}
	}
}

func authenticatePacket(frame []byte, key [32]byte, role uint8, index int) (tunnelv1.PeerPacket, bool) {
	packet, err := tunnelv1.ParsePeerPacket(frame)
	if err != nil || packet.Sender == role || int(packet.Path) != index {
		return packet, false
	}
	unsigned, _ := packet.AuthenticatedBytes()
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(nativePacketDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(unsigned)
	return packet, hmac.Equal(packet.MAC[:], mac.Sum(nil))
}

func (e *Endpoint) assemble(p *path, packet tunnelv1.PeerPacket) {
	if packet.Sequence < p.highest && p.highest-packet.Sequence >= reassemblySlots {
		return
	}
	p.highest = max(p.highest, packet.Sequence)
	slot := packet.Sequence % reassemblySlots
	if p.complete[slot] == packet.Sequence {
		return
	}
	f := &p.fragments[slot]
	if f.sequence != packet.Sequence {
		*f = fragment{sequence: packet.Sequence, total: packet.Total}
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
	case e.input <- b:
	default:
		e.mu.Lock()
		p.stats.DroppedFrames++
		e.mu.Unlock()
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
