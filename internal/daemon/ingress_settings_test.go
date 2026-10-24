package daemon

import (
	"testing"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func TestSplitIngressPrivateTransportSettings(t *testing.T) {
	settings := ingressProcessSettingsFrom(daemonconfig.Config{
		ControlHostname: "control.example.com", IngressID: "ingress-b",
		IngressListen: "0.0.0.0:8443", IngressUDPListen: "fly-global-services:443", RequireProxyHeader: true,
	})
	if settings.listen != "0.0.0.0:8443" || settings.privateUDPListen != "fly-global-services:443" ||
		settings.privateHostname != "ingress-b.example.com" || settings.privateAddress != "ingress-b.example.com:443" || !settings.runtime.requireProxyHeader {
		t.Fatalf("split ingress settings: %+v", settings)
	}
	settings = ingressProcessSettingsFrom(daemonconfig.Config{
		ControlHostname: "control.example.com", IngressID: "ingress-b", IngressConnectorPort: 4444,
		IngressListen: "0.0.0.0:8443", IngressUDPListen: "fly-global-services:4444",
	})
	if settings.privateAddress != "ingress-b.example.com:4444" || settings.privateHostname != "ingress-b.example.com" || settings.privateUDPListen != "fly-global-services:4444" {
		t.Fatalf("process-specific connector settings: %+v", settings)
	}
}
