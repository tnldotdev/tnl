package tnldruntime

import (
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestIntegrationPrivateRuntimeReservesStandaloneServicePorts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	newPrivateRuntimeFixtureTiming(t, true, nil, false, func(cfg *tnldconfig.Config, _ *http.Transport, _ *testCertificateAuthority) {
		ports, err := cfg.ServicePortInventory()
		if err != nil {
			t.Fatal(err)
		}
		for _, interval := range ports {
			for port := interval.First; port <= interval.Last; port++ {
				listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if err == nil {
					_ = listener.Close()
					t.Fatalf("service port %d was released before the runtime claimed it", port)
				}
			}
		}
	})
}

func TestIntegrationPrivateRuntimeReservesControlPorts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		name := "separated"
		if standalone {
			name = "standalone"
		}
		t.Run(name, func(t *testing.T) {
			newPrivateRuntimeFixtureTiming(t, standalone, nil, false, func(cfg *tnldconfig.Config, _ *http.Transport, _ *testCertificateAuthority) {
				addresses := []string{cfg.ControlListen}
				if !standalone {
					addresses = append(addresses, cfg.PrivateControlListen)
				}
				for _, address := range addresses {
					listener, err := net.Listen("tcp", address)
					if err == nil {
						_ = listener.Close()
						t.Fatalf("control port %s was released before the runtime claimed it", address)
					}
				}
			})
		})
	}
}
