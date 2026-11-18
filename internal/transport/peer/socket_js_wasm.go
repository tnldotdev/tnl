package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// HostUDP is false because the browser and Worker adapters do not open UDP
// sockets. inner QUIC still uses a net.PacketConn backed by WSS relay paths.
const HostUDP = false

var errHostUDP = errors.New("the WebAssembly host does not provide UDP sockets")

type Socket struct{}

func ListenSocket(context.Context, string, string) (*Socket, error) { return nil, errHostUDP }
func (*Socket) DialQUIC(context.Context, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return nil, errHostUDP
}
func (*Socket) Close() error { return nil }

type Connectivity struct{}

func NewConnectivity(*Socket, *quic.Conn, *Endpoint, bool, ConnectivityOptions, func(tunnelv1.PeerPacket) bool) *Connectivity {
	return nil
}
func (*Connectivity) SetBinding(ConnectivityBinding) {}
func (*Connectivity) Suspend()                       {}
func (*Connectivity) Serve(context.Context) error    { return errHostUDP }
