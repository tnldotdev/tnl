package daemon

import (
	"reflect"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func TestRelayQUICProfileRoleWiring(t *testing.T) {
	for _, profile := range []string{"standard", "fly"} {
		t.Run(profile, func(t *testing.T) {
			cfg := daemonconfig.Config{RelayQUICProfile: profile, RelayUDPListen: "127.0.0.1:443",
				QUICIdleTimeout: 17 * time.Second, QUICMaxIncomingStreams: 123}
			want := cfg.RelayQUICConfig()
			relay, standalone := relayProcessSettingsFrom(cfg), standaloneSettingsFrom(cfg)
			if !reflect.DeepEqual(relay.quic, want) || !reflect.DeepEqual(standalone.quic, want) {
				t.Fatal("relay and standalone must carry the resolved socket and QUIC settings")
			}
			if relay.udpListen != cfg.RelayUDPListen || standalone.relayUDPListen != cfg.RelayUDPListen {
				t.Fatal("relay and standalone lost the configured listen address")
			}
		})
	}
}
