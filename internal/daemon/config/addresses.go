package tnldconfig

import (
	"net"

	controlproxy "github.com/tnldotdev/tnl/internal/control/proxy"
)

func (c Config) ACMEEnabled() bool { return c.Role.RunsControl() }

func (c Config) DNSAutomationEnabled() bool {
	return c.Role.RunsControl() && c.Route53ManagedZoneID != ""
}

func (c Config) DNSProviderEnabled() bool {
	return c.Role.RunsControl() && (c.Route53ManagedZoneID != "" || c.Route53ServerZoneID != "")
}

func (c Config) RelayCertificateAutomationEnabled() bool {
	return c.Role.RunsControl() && c.Route53ServerZoneID != ""
}

func (c Config) ServerHostname() string {
	if !c.Role.RunsControl() || c.ServerDomain == "" {
		return ""
	}
	return "control." + c.ServerDomain
}

func (c Config) IngressHostname() string {
	if !c.Role.RunsControl() || c.ServerDomain == "" {
		return ""
	}
	return "ingress-a." + c.ServerDomain
}

func (c Config) StandaloneRelayHostname() string {
	if c.Role != RoleStandalone || c.ServerDomain == "" {
		return ""
	}
	return "relay." + c.ServerDomain
}

// RelayServiceHostname derives one split relay service's public hostname.
func (c Config) RelayServiceHostname(relayServiceID string) string {
	if !c.Role.RunsControl() || !validDNSLabel(relayServiceID) || c.ServerDomain == "" {
		return ""
	}
	return relayServiceID + "." + c.ServerDomain
}

// PrivateControlEndpoint is the fixed HTTPS endpoint used by ingress and relay processes.
func (c Config) PrivateControlEndpoint() string {
	hostname := c.ServerHostname()
	if hostname == "" {
		hostname = c.ControlHostname
	}
	if hostname != "" {
		return "https://" + net.JoinHostPort(hostname, "9443")
	}
	return ""
}

func (c Config) ControlOrigin() string {
	if c.ControlURL != "" {
		return c.ControlURL
	}
	if hostname := c.ServerHostname(); hostname != "" {
		return "https://" + hostname
	}
	return ""
}

func (c Config) ControlProxy() controlproxy.Config {
	peers, header := c.ControlTrustedProxies, c.ControlClientIPHeader
	if peers == nil {
		peers = []string{"127.0.0.1/32", "::1/128"}
	}
	if header == "" {
		header = "X-Forwarded-For"
	}
	return controlproxy.Config{Origin: c.ControlOrigin(), TrustedPeers: peers, ClientIPHeader: header}
}
