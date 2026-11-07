package config

import (
	"errors"
	"net"
	"net/netip"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func (c Config) validateRelayQUICListen() error {
	if !c.Role.RunsRelay() || c.RelayQUICProfile != "fly" {
		return nil
	}
	host, _, _ := net.SplitHostPort(c.RelayUDPListen)
	address, _ := netip.ParseAddr(host)
	if host == "" || address.Unmap().IsUnspecified() {
		return failure.WrapSetting("bind fly relay QUIC to a specific address", failure.ServerConfigInvalid,
			failure.SettingRelayUDPListen, errors.New("fly QUIC requires a non-wildcard UDP listen address"))
	}
	return nil
}

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
