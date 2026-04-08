// Package workersession carries RouteOwner operations over bearer-authenticated WebSockets.
package workersession

import (
	"io"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
)

const (
	defaultMaxStreams = 10_000
	handshakeTimeout  = 10 * time.Second
	requestTimeout    = 30 * time.Second
)

func muxConfig(maxIncoming int) *yamux.Config {
	if maxIncoming <= 0 {
		maxIncoming = defaultMaxStreams
	}
	config := yamux.DefaultConfig()
	config.AcceptBacklog = min(maxIncoming, 256)
	config.MaxIncomingStreams = uint32(maxIncoming)
	config.InitialStreamWindowSize = 256 << 10
	config.MaxStreamWindowSize = 1 << 20
	config.MaxMessageSize = 64 << 10
	config.ConnectionWriteTimeout = 10 * time.Second
	config.KeepAliveInterval = 30 * time.Second
	config.LogOutput = io.Discard
	return config
}
