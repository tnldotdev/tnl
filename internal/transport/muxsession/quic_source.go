package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	sourceQUICPendingLimit = 64
	sourceQUICQueue        = 16
	sourceQUICQueueBytes   = 8 << 20
	sourceQUICPacketBytes  = 64 << 10
)

// sourceQUICListener owns one UDP reader and bounded virtual sockets, one for
// each canonical source IP. each socket has a separate QUIC connection-ID table,
// so a packet from another IP cannot reach an established connection, even with
// a current connection ID and valid encryption. quic-go dispatches frames before
// updating RemoteAddr; checking that address after dispatch is not an IP fence.
//
// these are transport lifetimes, not publisher or connector authority. the role
// owner still authenticates every accepted connection and chooses when to drain.
// virtual sockets deliberately do not expose the physical file descriptor:
// QUIC's optimized batch reader must not bypass this source demultiplexer.
type sourceQUICListener struct {
	packet               net.PacketConn
	trust                *tls.Config
	config               *quic.Config
	limit                int
	ctx                  context.Context
	cancel               context.CancelFunc
	mu                   sync.Mutex
	sources              map[netip.Addr]*sourceQUICSocket
	pending, queuedBytes int
	stopped              bool
	stop                 chan struct{}
	accepted             chan *quic.Conn
	wait                 sync.WaitGroup
	once                 sync.Once
	err                  error
}

type sourceQUICPacket struct {
	data    []byte
	address *net.UDPAddr
}

type sourceQUICSocket struct {
	owner           *sourceQUICListener
	ip              netip.Addr
	ctx             context.Context
	cancel          context.CancelFunc
	packets         chan sourceQUICPacket
	listener        *quic.Listener
	transport       *quic.Transport
	created, idleAt time.Time
	active          int
	pending         bool
	once            sync.Once
	deadlineMu      sync.Mutex
	readDeadline    time.Time
	readChanged     chan struct{}
}

func listenSourceQUIC(packet net.PacketConn, trust *tls.Config, config QUICConfig, alpn string) (*QUICListener, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &sourceQUICListener{packet: packet, trust: trust, config: quicConfig(config.Config), limit: config.PinnedRemoteIPLimit,
		ctx: ctx, cancel: cancel, sources: make(map[netip.Addr]*sourceQUICSocket), stop: make(chan struct{}), accepted: make(chan *quic.Conn, sourceQUICPendingLimit)}
	// validate TLS and QUIC configuration at startup, not silently on the first
	// source's packet. this probe owns no physical socket or accepted connection.
	probeCtx, stopProbe := context.WithCancel(ctx)
	probe := &sourceQUICSocket{owner: s, ctx: probeCtx, cancel: stopProbe, packets: make(chan sourceQUICPacket), readChanged: make(chan struct{})}
	transport := &quic.Transport{Conn: probe}
	listener, err := transport.Listen(trust, s.config)
	stopProbe()
	if listener != nil {
		_ = listener.Close()
	}
	_ = transport.Close()
	if err != nil {
		cancel()
		_ = packet.Close()
		return nil, fmt.Errorf("muxsession: listen source-bound QUIC: %w", err)
	}
	s.wait.Go(s.receive)
	s.wait.Go(s.expire)
	return &QUICListener{packetConn: packet, alpn: alpn, sources: s}, nil
}

func (s *sourceQUICListener) receive() {
	defer s.cancel()
	buffer := make([]byte, sourceQUICPacketBytes)
	for {
		n, address, err := s.packet.ReadFrom(buffer)
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				s.err = err
				s.mu.Unlock()
			}
			return
		}
		udp, ok := address.(*net.UDPAddr)
		if !ok || udp == nil || udp.Zone != "" {
			continue
		}
		ip := udp.AddrPort().Addr().Unmap()
		if !ip.IsValid() || ip.IsUnspecified() {
			continue
		}
		s.mu.Lock()
		source := s.sources[ip]
		if source == nil && !s.stopped && s.ctx.Err() == nil && len(s.sources) < s.limit && s.pending < sourceQUICPendingLimit && n >= 1200 && buffer[0]&0xc0 == 0xc0 {
			// only a possible long-header handshake allocates a transport. the
			// QUIC implementation, not this demultiplexer, validates its contents.
			ctx, cancel := context.WithCancel(s.ctx)
			source = &sourceQUICSocket{owner: s, ip: ip, ctx: ctx, cancel: cancel, packets: make(chan sourceQUICPacket, sourceQUICQueue),
				created: time.Now(), pending: true, readChanged: make(chan struct{})}
			source.transport = &quic.Transport{Conn: source}
			source.listener, err = source.transport.Listen(s.trust, s.config)
			if err != nil {
				cancel()
				_ = source.transport.Close()
				source = nil
			} else {
				s.sources[ip] = source
				s.pending++
				s.wait.Go(source.accept)
			}
		}
		if source != nil && source.ctx.Err() == nil && len(source.packets) < sourceQUICQueue && s.queuedBytes+n <= sourceQUICQueueBytes {
			copyAddress := net.UDPAddrFromAddrPort(udp.AddrPort())
			source.packets <- sourceQUICPacket{data: append([]byte(nil), buffer[:n]...), address: copyAddress}
			s.queuedBytes += n
		}
		s.mu.Unlock()
	}
}

func (p *sourceQUICSocket) accept() {
	s := p.owner
	for {
		connection, err := p.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.stopped || s.ctx.Err() != nil || s.sources[p.ip] != p {
			s.mu.Unlock()
			_ = connection.CloseWithError(0, "")
			continue
		}
		p.active++
		if p.pending {
			p.pending = false
			s.pending--
		}
		s.wait.Add(1)
		context.AfterFunc(connection.Context(), func() {
			defer s.wait.Done()
			s.mu.Lock()
			p.active--
			p.idleAt = time.Now()
			s.mu.Unlock()
		})
		queued := false
		select {
		case s.accepted <- connection:
			queued = true
		default:
		}
		s.mu.Unlock()
		if !queued {
			_ = connection.CloseWithError(0, "")
		}
	}
}

func (s *sourceQUICListener) accept(ctx context.Context) (*quic.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.ctx.Done():
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, ErrClosed
	case <-s.stop:
		return nil, ErrClosed
	case connection := <-s.accepted:
		s.mu.Lock()
		stopped := s.stopped || s.ctx.Err() != nil || ctx.Err() != nil
		s.mu.Unlock()
		if stopped {
			_ = connection.CloseWithError(0, "")
			return nil, ErrClosed
		}
		return connection, nil
	}
}

func (s *sourceQUICListener) expire() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			var expired []*sourceQUICSocket
			s.mu.Lock()
			for ip, p := range s.sources {
				// failed handshakes spend a fixed budget; repeated spoofed packets
				// cannot keep a pending source alive. accepted connections own their
				// ordinary QUIC deadlines, then retain a short retirement interval.
				until := p.idleAt.Add(30 * time.Second)
				if p.pending {
					until = p.created.Add(10 * time.Second)
				}
				if p.active == 0 && !until.After(now) {
					delete(s.sources, ip)
					if p.pending {
						s.pending--
					}
					expired = append(expired, p)
				}
			}
			s.mu.Unlock()
			for _, p := range expired {
				p.close()
			}
		}
	}
}

func (s *sourceQUICListener) stopAccepting() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	close(s.stop)
	sources := make([]*sourceQUICSocket, 0, len(s.sources))
	for _, p := range s.sources {
		sources = append(sources, p)
	}
	var queued []*quic.Conn
	draining := true
	for draining {
		select {
		case connection := <-s.accepted:
			queued = append(queued, connection)
		default:
			draining = false
		}
	}
	s.mu.Unlock()
	for _, p := range sources {
		_ = p.listener.Close()
	}
	for _, connection := range queued {
		_ = connection.CloseWithError(0, "")
	}
	return nil
}

func (s *sourceQUICListener) close() error {
	s.once.Do(func() {
		_ = s.stopAccepting()
		s.cancel()
		_ = s.packet.Close()
		s.mu.Lock()
		sources := make([]*sourceQUICSocket, 0, len(s.sources))
		for _, p := range s.sources {
			sources = append(sources, p)
		}
		s.mu.Unlock()
		for _, p := range sources {
			p.close()
		}
		s.wait.Wait()
		s.mu.Lock()
		s.sources = nil
		s.pending = 0
		s.mu.Unlock()
	})
	return s.err
}

func (p *sourceQUICSocket) close() {
	p.once.Do(func() {
		p.cancel()
		_ = p.listener.Close()
		_ = p.transport.Close()
		p.owner.mu.Lock()
		for len(p.packets) > 0 {
			p.owner.queuedBytes -= len((<-p.packets).data)
		}
		p.owner.mu.Unlock()
	})
}

func (p *sourceQUICSocket) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		p.deadlineMu.Lock()
		until, changed := p.readDeadline, p.readChanged
		p.deadlineMu.Unlock()
		var expired <-chan time.Time
		var timer *time.Timer
		if !until.IsZero() {
			if !until.After(time.Now()) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(until))
			expired = timer.C
		}
		select {
		case <-p.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case packet := <-p.packets:
			if timer != nil {
				timer.Stop()
			}
			p.owner.mu.Lock()
			p.owner.queuedBytes -= len(packet.data)
			p.owner.mu.Unlock()
			if p.ctx.Err() != nil {
				return 0, nil, net.ErrClosed
			}
			return copy(buffer, packet.data), packet.address, nil
		}
	}
}

func (p *sourceQUICSocket) WriteTo(buffer []byte, address net.Addr) (int, error) {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp == nil || udp.Zone != "" || udp.AddrPort().Addr().Unmap() != p.ip {
		return 0, errors.New("muxsession: QUIC destination changed its bound source IP")
	}
	if p.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return p.owner.packet.WriteTo(buffer, address)
}

func (p *sourceQUICSocket) Close() error        { p.cancel(); return nil }
func (p *sourceQUICSocket) LocalAddr() net.Addr { return p.owner.packet.LocalAddr() }
func (p *sourceQUICSocket) SetReadBuffer(size int) error {
	if socket, ok := p.owner.packet.(interface{ SetReadBuffer(int) error }); ok {
		return socket.SetReadBuffer(size)
	}
	return errors.ErrUnsupported
}
func (p *sourceQUICSocket) SetWriteBuffer(size int) error {
	if socket, ok := p.owner.packet.(interface{ SetWriteBuffer(int) error }); ok {
		return socket.SetWriteBuffer(size)
	}
	return errors.ErrUnsupported
}
func (p *sourceQUICSocket) SetReadDeadline(until time.Time) error {
	p.deadlineMu.Lock()
	defer p.deadlineMu.Unlock()
	p.readDeadline = until
	close(p.readChanged)
	p.readChanged = make(chan struct{})
	return nil
}
func (p *sourceQUICSocket) SetWriteDeadline(until time.Time) error {
	// quic-go owns packet write scheduling and never sets a UDP write deadline.
	// changing the shared socket's deadline here would interrupt other sources.
	if !until.IsZero() {
		return errors.ErrUnsupported
	}
	return nil
}
func (p *sourceQUICSocket) SetDeadline(until time.Time) error {
	return errors.Join(p.SetReadDeadline(until), p.SetWriteDeadline(until))
}
