package daemon

import (
	"testing"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func TestSplitIngressPublicSettings(t *testing.T) {
	settings := ingressProcessSettingsFrom(daemonconfig.Config{
		ControlHostname: "control.example.com", IngressID: "ingress-b",
		IngressListen: "0.0.0.0:8443", RequireProxyHeader: true,
	})
	if settings.listen != "0.0.0.0:8443" || settings.ingressID != "ingress-b" || !settings.runtime.requireProxyHeader {
		t.Fatalf("split ingress settings: %+v", settings)
	}
}
