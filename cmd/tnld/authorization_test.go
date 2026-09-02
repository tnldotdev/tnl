package main

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestCapabilitiesAdvertiseSignedAuthorizationMode(t *testing.T) {
	endpoint := "https://authority.example"
	result := capabilities(config.TNLD{
		PublicHostnameSuffix:           "example",
		AuthorizationAuthorityEndpoint: endpoint,
	}, "test")
	if len(result.HostnameAuthorization) != 1 || result.HostnameAuthorization[0] != serverv1.SignedAuthorization ||
		result.AuthorizationAuthorityEndpoint == nil || *result.AuthorizationAuthorityEndpoint != endpoint ||
		result.LocalHostnames != nil {
		t.Fatalf("capabilities = %#v", result)
	}
	if len(result.Administration.Operations) != 6 ||
		result.Administration.Operations[5] != serverv1.MaintenanceControls {
		t.Fatalf("administration capabilities = %#v", result.Administration)
	}
}
