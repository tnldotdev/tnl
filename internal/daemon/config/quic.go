package config

import (
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// RelayQUICConfig resolves a validated server configuration into listener
// mechanics shared by relay and standalone. client packet defaults are separate.
func (c Config) RelayQUICConfig() muxsession.QUICConfig {
	config := muxsession.QUICConfig{
		UDPNetwork: "udp",
		Config: &quic.Config{
			MaxIdleTimeout: c.QUICIdleTimeout, MaxIncomingStreams: c.QUICMaxIncomingStreams,
			EnableDatagrams: true,
		},
	}
	if c.RelayQUICProfile == "fly" {
		// fly replies must follow the socket route; received interface metadata
		// and larger packets do not work on its UDP forwarding path.
		config.UDPNetwork = "udp4"
		config.BasicPacketConn = true
		config.Config.InitialPacketSize = 1200
		config.Config.DisablePathMTUDiscovery = true
	}
	return config
}
