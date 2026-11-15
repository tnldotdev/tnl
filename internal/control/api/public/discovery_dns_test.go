package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestControlDiscoverySeparatesServiceAndRelayDNSAutomation(t *testing.T) {
	for _, test := range []struct {
		name, managedZone, serverZone string
		want                          bool
	}{
		{"no_zones", "", "", false},
		{"managed_only", "ZMANAGED", "", true},
		{"server_only", "", "ZSERVER", false},
		{"both", "ZMANAGED", "ZSERVER", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := daemonconfig.Config{Role: daemonconfig.RoleControl, ServerDomain: "infra.example.test",
				ManagedDomain: "routes.other.test", Route53ManagedZoneID: test.managedZone, Route53ServerZoneID: test.serverZone}
			h := testHandler(t, Config{ManagedDomain: cfg.ManagedDomain,
				ControlURL: "https://" + cfg.ServerHostname(), DNSAutomation: cfg.DNSAutomationEnabled()}, nil, nil, nil)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/discovery", nil))
			var discovery controlv1.ControlDiscovery
			if err := json.Unmarshal(response.Body.Bytes(), &discovery); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || discovery.DnsAutomation != test.want ||
				discovery.ManagedDomain != "routes.other.test" {
				t.Fatalf("discovery status = %d, facts = %#v", response.Code, discovery)
			}
		})
	}
}
