package tnldruntime

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestSplitProcessSettingsPreserveControlTLSIdentityAndDialAddress(t *testing.T) {
	config := tnldconfig.Config{
		ControlHostname:       "control.example.com",
		PrivateControlAddress: "control.internal:9443",
	}
	ingress := ingressProcessSettingsFrom(config)
	relay := relayProcessSettingsFrom(config)
	for name, endpoint := range map[string]string{"ingress": ingress.controlEndpoint, "relay": relay.controlEndpoint} {
		if endpoint != "https://control.example.com:9443" {
			t.Fatalf("%s control endpoint = %q", name, endpoint)
		}
	}
	if ingress.controlAddress != "control.internal:9443" || relay.controlAddress != "control.internal:9443" {
		t.Fatalf("control dial addresses = %q, %q", ingress.controlAddress, relay.controlAddress)
	}
}
