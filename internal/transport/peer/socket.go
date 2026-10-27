package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// Socket owns the physical UDP socket used by relay QUIC, STUN discovery, ICE
// checks, and direct packet delivery. agents borrow its mux; closing one peer
// must not close this process-owned socket or another peer's selected path.
type Socket struct {
	transport *quic.Transport
	packet    net.PacketConn
	mux       *ice.UniversalUDPMuxDefault
	cancel    context.CancelFunc
	once      sync.Once
	err       error
}

var _ muxsession.QUICDialer = (*Socket)(nil)

func ListenSocket(parent context.Context, network, address string) (*Socket, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("resolve peer socket: %w", err)
	}
	packet, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen for peer packets: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	transport := &quic.Transport{Conn: packet}
	logger := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	mux := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{
		UDPConn: muxsession.NonQUICPacketConn(ctx, transport, packet.LocalAddr()),
		Logger:  logger.NewLogger("ice"), XORMappedAddrCacheTTL: time.Second,
	})
	return &Socket{transport: transport, packet: packet, mux: mux, cancel: cancel}, nil
}

func (s *Socket) LocalAddr() net.Addr { return s.packet.LocalAddr() }

func (s *Socket) DialQUIC(ctx context.Context, remote net.Addr, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	return s.transport.Dial(ctx, remote, tlsConfig, config)
}

// NewICE creates one peer's checks on the shared socket. signaling owners bound
// remote candidates and credentials to an authorized introduction before use.
func (s *Socket) NewICE(urls []*stun.URI, includeLoopback bool) (*ice.Agent, error) {
	if len(urls) > 2 {
		return nil, ErrConfiguration
	}
	for _, u := range urls {
		if u == nil || u.Scheme != stun.SchemeTypeSTUN || u.Proto != stun.ProtoTypeUDP {
			return nil, ErrConfiguration
		}
	}
	logger := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	options := []ice.AgentOption{
		ice.WithUDPMux(s.mux), ice.WithUDPMuxSrflx(s.mux),
		ice.WithUrls(urls), ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled), ice.WithSTUNGatherTimeout(2 * time.Second),
		ice.WithLoggerFactory(logger), ice.WithRenomination(ice.DefaultNominationValueGenerator()),
		ice.WithAutomaticRenomination(time.Second), ice.WithNetworkMonitorInterval(time.Second),
	}
	if includeLoopback {
		options = append(options, ice.WithIncludeLoopback())
	}
	agent, err := ice.NewAgentWithOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("prepare peer connectivity checks: %w", err)
	}
	return agent, nil
}

func (s *Socket) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.err = errors.Join(s.mux.Close(), s.transport.Close(), s.packet.Close())
	})
	return s.err
}

// ICECarrier retains packet boundaries over a selected ICE pair. callers install
// it only after ICE consent succeeds; its packet MAC still needs a peer round trip
// before the endpoint prefers it to the warm relays.
type ICECarrier struct{ Conn *ice.Conn }

func (c ICECarrier) Send(ctx context.Context, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := c.Conn.Write(b)
	return err
}
func (c ICECarrier) Receive(ctx context.Context) ([]byte, error) {
	stop := interruptOnCancel(ctx, c.Close)
	defer stop()
	b := make([]byte, 2048)
	n, err := c.Conn.Read(b)
	if err != nil {
		return nil, err
	}
	return b[:n], err
}
func (c ICECarrier) Close() error { return c.Conn.Close() }
