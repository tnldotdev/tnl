package muxsession

import (
	"context"
	"errors"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	sourceNonQUICQueue       = 64
	sourceNonQUICPacketBytes = 2048
)

// the address carries one packet's reply metadata, not a mutable per-source
// cache. two requests from the same source to different local IPs stay distinct.
type nonQUICReplyAddr struct {
	address *net.UDPAddr
	oob     []byte
	owner   *sourceQUICListener
}

func (a *nonQUICReplyAddr) Network() string       { return a.address.Network() }
func (a *nonQUICReplyAddr) String() string        { return a.address.String() }
func (a *nonQUICReplyAddr) UDPAddr() *net.UDPAddr { return a.address }

func (s *sourceQUICListener) nonQUICPackets(parent context.Context) net.PacketConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonQUICQueue = make(chan sourceQUICPacket, sourceNonQUICQueue)
	queue := s.nonQUICQueue
	s.nonQUIC = newNonQUICPacketConn(parent, s.packet.LocalAddr(), func(ctx context.Context, b []byte) (int, net.Addr, error) {
		select {
		case <-ctx.Done():
			return 0, nil, context.Cause(ctx)
		case <-s.ctx.Done():
			return 0, nil, net.ErrClosed
		case packet := <-queue:
			return copy(b, packet.data), &nonQUICReplyAddr{address: packet.address, oob: packet.oob, owner: s}, nil
		}
	}, func(b []byte, addr net.Addr) (int, error) {
		reply, ok := addr.(*nonQUICReplyAddr)
		if !ok || reply.owner != s {
			return 0, errors.New("muxsession: non-QUIC write requires a received reply address")
		}
		if s.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		if s.oob != nil {
			oob := nonQUICReplyOOB(reply.oob)
			n, _, err := s.oob.WriteMsgUDP(b, oob, reply.address)
			return n, err
		}
		return s.packet.WriteTo(b, reply.address)
	})
	return s.nonQUIC
}

func nonQUICReplyOOB(oob []byte) []byte {
	// retain only packet-info, not received ECN/TTL control messages. replies use
	// the request's local destination as their source, on the received interface.
	var v4 ipv4.ControlMessage
	if v4.Parse(oob) == nil && v4.Dst.To4() != nil {
		return (&ipv4.ControlMessage{Src: v4.Dst, IfIndex: v4.IfIndex}).Marshal()
	}
	var v6 ipv6.ControlMessage
	if v6.Parse(oob) == nil && v6.Dst.To16() != nil {
		return (&ipv6.ControlMessage{Src: v6.Dst, IfIndex: v6.IfIndex}).Marshal()
	}
	return nil
}
