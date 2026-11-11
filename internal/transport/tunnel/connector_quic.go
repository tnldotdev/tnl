package tunnel

import (
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const MaxConnectorApplicationStreams = 64

// ConnectorQUICConfig keeps quic-go's pinned application-window defaults while
// reserving connection credit for control even if every application stops
// reading at its maximum window. connection credit updates are batched: merely
// summing stream maxima can still leave control blocked behind consumed credit
// not yet replenished. twice that sum leaves room across the update threshold,
// including two connectivity signaling streams. credit is not preallocated
// memory; unread payload is bounded by 67 stream windows (402 MiB). signaling
// readers additionally enforce their 32 KiB frame bound. this config belongs only
// to the retained inner QUIC session, never its two relay carrier sessions.
func ConnectorQUICConfig() *quic.Config {
	const initial = 512 << 10
	const maximum = 6 << 20
	const total = 2 * (MaxConnectorApplicationStreams + 1) * maximum
	return &quic.Config{
		InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true,
		MaxIncomingStreams: MaxConnectorApplicationStreams + 1, MaxIncomingUniStreams: 2,
		InitialStreamReceiveWindow: initial, MaxStreamReceiveWindow: maximum,
		InitialConnectionReceiveWindow: total, MaxConnectionReceiveWindow: total,
		MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second,
	}
}
