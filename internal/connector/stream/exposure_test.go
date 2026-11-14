package stream

import (
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorRunExposureChangesDoNotChangeTrust(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql", "kubernetes"} {
		t.Run(protocol, func(t *testing.T) {
			port := 0
			if protocol == "http" {
				port = 443
			}
			configuration := Config{ServiceID: "svc_" + strings.Repeat("S", 22), Protocol: protocol, TrustRevision: 3,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: port}}
			run := Run{ServiceID: configuration.ServiceID, ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 1,
				Protocol: protocol, TrustRevision: 3, Endpoint: configuration.Endpoint, ValidUntil: time.Now().Add(time.Minute)}
			permission := controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: run.ServiceID},
				Hostname: run.Endpoint.Hostname, Port: port, VisitorToken: "prepared-permission", ExpiresAt: time.Now().Add(time.Minute)}
			ports := []int{0, 25443, 0, 35443}
			if protocol == "http" {
				ports = []int{443, 443, 443, 443}
			}
			for _, publicPort := range ports {
				run.Endpoint = &controlv1.ServiceEndpoint{Hostname: configuration.Endpoint.Hostname, Port: publicPort, Public: publicPort != 0}
				if err := validateConnectorRun(configuration, run); err != nil || !validConnectorPermission(run, permission) {
					t.Fatal("public reservation changed connector authority", publicPort, err)
				}
			}
			run.TrustRevision++
			if err := validateConnectorRun(configuration, run); err == nil {
				t.Fatal("a real trust change retained connector authority")
			}
			run.TrustRevision--
			run.Endpoint.Hostname = "another.example.test"
			if err := validateConnectorRun(configuration, run); err == nil || validConnectorPermission(run, permission) {
				t.Fatal("another TLS identity retained connector authority")
			}
		})
	}
}
