package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

const (
	iceCheckInterval       = 200 * time.Millisecond
	iceKeepaliveInterval   = time.Second
	iceDisconnectedTimeout = 3 * time.Second
	iceFailedTimeout       = 3 * time.Second
)

// Socket owns the physical UDP socket used by relay QUIC, STUN discovery, ICE
// checks, and direct packet delivery. agents borrow its mux; closing one agent
// must not close this process-owned socket or another agent's selected path.
type Socket struct {
	transport *quic.Transport
	packet    net.PacketConn
	mux       *socketICEMux
	cancel    context.CancelFunc
	stop      func() bool
	once      sync.Once
	err       error
}

var _ muxsession.QUICDialer = (*Socket)(nil)

func ListenSocket(parent context.Context, network, address string) (*Socket, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("resolve peer socket: %w", err)
	}
	packet, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen for peer packets: %w", err)
	}
	return ListenSocketPacket(parent, packet)
}

// ListenSocketPacket takes ownership of packet, including on error. packet must expose
// its bound IP-only UDP address; wrappers may intercept reads or writes without
// replacing the physical socket used by relay QUIC and ICE.
func ListenSocketPacket(parent context.Context, packet net.PacketConn) (*Socket, error) {
	if packet == nil {
		return nil, ErrConfiguration
	}
	if err := parent.Err(); err != nil {
		return nil, errors.Join(err, packet.Close())
	}
	if _, ok := iceRemote(packet.LocalAddr()); !ok {
		return nil, errors.Join(ErrConfiguration, packet.Close())
	}
	ctx, cancel := context.WithCancel(parent)
	transport := &quic.Transport{Conn: packet}
	mux := newSocketICEMux(muxsession.NonQUICPacketConn(ctx, transport, packet.LocalAddr()))
	s := &Socket{transport: transport, packet: packet, mux: mux, cancel: cancel}
	// watch the parent, not ctx: explicit close cancels the borrowed packet view
	// without recursively invoking the same sync.Once.
	s.stop = context.AfterFunc(parent, func() { _ = s.close() })
	return s, nil
}

func (s *Socket) LocalAddr() net.Addr { return s.packet.LocalAddr() }

func (s *Socket) DialQUIC(ctx context.Context, remote net.Addr, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	return s.transport.Dial(ctx, remote, tlsConfig, config)
}

// NewICE creates one agent's checks on the shared socket. signaling owners must
// validate remote candidates and credentials before handing them to the agent.
// unfiltered application packets are delivered only to an unambiguous recipient.
func (s *Socket) NewICE(urls []*stun.URI, includeLoopback bool) (*ice.Agent, error) {
	return s.newICE(urls, includeLoopback, nil)
}

// acceptPacket must be a bounded, nonblocking authentication check. it runs in
// the shared dispatcher and must not call back into the socket or agent.
func (s *Socket) newICE(urls []*stun.URI, includeLoopback bool, acceptPacket func([]byte) bool) (*ice.Agent, error) {
	if len(urls) > 4 {
		return nil, ErrConfiguration
	}
	resolved := make([]*stun.URI, 0, len(urls))
	for _, u := range urls {
		if u == nil || u.Scheme != stun.SchemeTypeSTUN || u.Proto != stun.ProtoTypeUDP || u.Host == "" || u.Port < 1 || u.Port > 65535 {
			return nil, ErrConfiguration
		}
		// the signaling owner resolves relay hostnames with its context before
		// entering pion, whose STUN resolver cannot be canceled by agent close.
		addr, err := netip.ParseAddr(u.Host)
		if err != nil || !validConnectivityIP(addr) {
			return nil, ErrConfiguration
		}
		resolvedURL := *u
		resolved = append(resolved, &resolvedURL)
	}
	s.mux.mu.Lock()
	closed := s.mux.closed
	s.mux.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	logger := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	mux := &agentICEMux{socketICEMux: s.mux, acceptPacket: acceptPacket, includeLoopback: includeLoopback}
	options := []ice.AgentOption{
		ice.WithUDPMux(mux), ice.WithUDPMuxSrflx(mux),
		ice.WithUrls(resolved), ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled), ice.WithSTUNGatherTimeout(2 * time.Second),
		// keep failure detection well below the inner QUIC idle timeout. these
		// binding requests also refresh consent when application traffic is idle.
		ice.WithCheckInterval(iceCheckInterval), ice.WithKeepaliveInterval(iceKeepaliveInterval),
		ice.WithDisconnectedTimeout(iceDisconnectedTimeout), ice.WithFailedTimeout(iceFailedTimeout),
		// a selected pair cannot inherit proof from a different path. a new
		// attempt regathers after consent loss instead of renominating in place.
		ice.WithLoggerFactory(logger), ice.WithContinualGatheringPolicy(ice.GatherOnce),
	}
	if includeLoopback {
		options = append(options, ice.WithIncludeLoopback())
	}
	agent, err := ice.NewAgentWithOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("prepare peer connectivity checks: %w", err)
	}
	_, mux.password, err = agent.GetLocalUserCredentials()
	if err != nil {
		return nil, errors.Join(err, agent.GracefulClose())
	}
	return agent, nil
}

func validConnectivityIP(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && !address.IsUnspecified() && !address.IsMulticast() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255}) && address.Zone() == ""
}

func (s *Socket) Close() error {
	s.stop()
	return s.close()
}

func (s *Socket) close() error {
	s.once.Do(func() {
		s.cancel()
		// closing the physical connection first interrupts any in-flight write
		// before the mux joins its writer. borrowed agents never take this path.
		s.err = errors.Join(s.packet.Close(), s.transport.Close(), s.mux.Close())
	})
	return s.err
}

// ICECarrier retains packet boundaries over a selected ICE pair. its owner uses
// a non-QUIC packet prefix, authenticates envelopes, and proves the path before
// preferring it. canceling an operation retires this agent, never the socket.
type ICECarrier struct{ Conn *ice.Conn }

var _ Carrier = ICECarrier{}

func (c ICECarrier) Send(ctx context.Context, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(b) > iceSocketPacketBytes {
		return io.ErrShortBuffer
	}
	if len(b) == 0 || b[0]&0xc0 != 0 {
		return ErrConfiguration
	}
	stop := interruptOnCancel(ctx, c.Close)
	defer stop()
	n, err := c.Conn.Write(b)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func (c ICECarrier) Receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := interruptOnCancel(ctx, c.Close)
	defer stop()
	b := make([]byte, iceSocketPacketBytes)
	n, err := c.Conn.Read(b)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func (c ICECarrier) Close() error { return c.Conn.Close() }
