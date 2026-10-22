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

func TestIntegrationStandalonePublishReservesSockets(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	newStandalonePublishFixture(t, "reserved", func(cfg tnldconfig.Config) {
		addresses := []string{cfg.ControlListen, cfg.MetricsListen, cfg.IngressListen}
		ports, err := cfg.ServicePortInventory()
		if err != nil {
			t.Fatal(err)
		}
		for _, interval := range ports {
			for port := interval.First; port <= interval.Last; port++ {
				addresses = append(addresses, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			}
		}
		for _, address := range addresses {
			listener, err := net.Listen("tcp", address)
			if err == nil {
				_ = listener.Close()
				t.Fatalf("standalone socket %s was released before the runtime claimed it", address)
			}
		}
	})
}

func TestIntegrationSplitPublishReservesSockets(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	newSplitPublishFixtureWithOptions(t, "reserved", splitPublishOptions{configureProcess: func(cfg *tnldconfig.Config) {
		addresses := []string{cfg.MetricsListen}
		switch cfg.Role {
		case tnldconfig.RoleControl:
			addresses = append(addresses, cfg.ControlListen, cfg.PrivateControlListen)
		case tnldconfig.RoleIngress:
			addresses = append(addresses, cfg.IngressListen)
		case tnldconfig.RoleRelay:
			addresses = append(addresses, cfg.RelayTCPListen, cfg.InternalRelayListen)
		}
		if cfg.Role.RunsControl() || cfg.Role.RunsIngress() {
			ports, err := cfg.ServicePortInventory()
			if err != nil {
				t.Fatal(err)
			}
			for _, interval := range ports {
				for port := interval.First; port <= interval.Last; port++ {
					addresses = append(addresses, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				}
			}
		}
		for _, address := range addresses {
			listener, err := net.Listen("tcp", address)
			if err == nil {
				_ = listener.Close()
				t.Fatalf("%s socket %s was released before the runtime claimed it", cfg.Role, address)
			}
		}
	}})
}
