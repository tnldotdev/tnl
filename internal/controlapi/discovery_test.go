package controlapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestControlDiscoverySeparatesRouteAndRelayDNSAutomation(t *testing.T) {
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
			cfg := tnldconfig.Config{Role: tnldconfig.RoleControl, ServerDomain: "infra.example.test",
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
