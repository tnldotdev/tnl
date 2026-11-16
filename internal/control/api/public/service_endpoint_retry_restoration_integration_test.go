package public

import (
	"context"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func assertServiceEndpointRetryRestoration(t *testing.T, ctx context.Context, client *clientcontrol.Client, original controlv1.Service) {
	t.Helper()
	if original.Endpoint == nil || original.Endpoint.Hostname == "" || original.Endpoint.Port != 0 || original.Endpoint.Public {
		t.Fatal("response-loss fixture did not begin with a connector-only endpoint")
	}
	recovered, err := client.GetService(ctx, original.Id)
	if err != nil {
		t.Fatal("could not read the saved service after response-loss recovery", err)
	}
	if recovered.Id != original.Id || recovered.Endpoint == nil || *recovered.Endpoint != *original.Endpoint ||
		recovered.EndpointRevision != original.EndpointRevision {
		t.Fatal("response-loss recovery changed the exact saved connector-only endpoint", recovered.Endpoint, recovered.EndpointRevision)
	}
}
