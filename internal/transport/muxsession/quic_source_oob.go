package muxsession

import (
	"net"
	"syscall"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

// retain quic-go's per-connection packet-info handling while every read still
// passes through the source fence. SyscallConn is only for socket configuration;
// ReadBatch prevents quic-go from unwrapping it to read the physical descriptor.
type sourceQUICOOBSocket struct{ *sourceQUICSocket }

var _ quic.OOBCapablePacketConn = (*sourceQUICOOBSocket)(nil)

func (p *sourceQUICSocket) packetConn() net.PacketConn {
	if p.owner.oob != nil {
		return &sourceQUICOOBSocket{p}
	}
	return p
}

func (p *sourceQUICOOBSocket) SyscallConn() (syscall.RawConn, error) {
	return p.owner.oob.SyscallConn()
}

func (p *sourceQUICOOBSocket) ReadMsgUDP(buffer, oob []byte) (int, int, int, *net.UDPAddr, error) {
	packet, err := p.readPacket()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return copy(buffer, packet.data), copy(oob, packet.oob), packet.flags, packet.address, nil
}

func (p *sourceQUICOOBSocket) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	packet, err := p.readPacket()
	if err != nil {
		return 0, err
	}
	message := &messages[0]
	message.N = 0
	for _, buffer := range message.Buffers {
		message.N += copy(buffer, packet.data[message.N:])
	}
	message.NN = copy(message.OOB, packet.oob)
	message.Flags, message.Addr = packet.flags, packet.address
	return 1, nil
}

func (p *sourceQUICOOBSocket) WriteMsgUDP(buffer, oob []byte, address *net.UDPAddr) (int, int, error) {
	if err := p.checkDestination(address); err != nil {
		return 0, 0, err
	}
	return p.owner.oob.WriteMsgUDP(buffer, oob, address)
}
