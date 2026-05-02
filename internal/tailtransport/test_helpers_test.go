package tailtransport

import (
	"context"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil/integrationtest"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func runTestDERP(t testing.TB) *tailcfg.DERPRegion {
	t.Helper()
	region, _ := runTestDERPWithServer(t)
	return region
}

func runTestDERPWithServer(t testing.TB) (*tailcfg.DERPRegion, *derpserver.Server) {
	t.Helper()
	return integrationtest.DERPWithServer(t)
}

func startTestServer(ctx context.Context, region *tailcfg.DERPRegion, clientKey key.NodePublic, handler func(net.Conn)) (*Server, Endpoint, error) {
	server, err := NewServer(ServerConfig{
		AllowedClient: clientKey,
		RelayProfile:  "test",
		Profiles:      map[string]*tailcfg.DERPRegion{"test": region},
		Handler:       handler,
		Logf:          logger.Discard,
	})
	if err != nil {
		return nil, Endpoint{}, err
	}
	endpoint, err := server.Start(ctx)
	if err != nil {
		server.Close()
		return nil, Endpoint{}, err
	}
	return server, endpoint, nil
}

func startTestDialer(ctx context.Context, region *tailcfg.DERPRegion, endpoint Endpoint, clientKey key.NodePrivate) (*Dialer, error) {
	dialer, err := NewDialer(DialerConfig{
		Endpoint: endpoint,
		Profiles: map[string]*tailcfg.DERPRegion{"test": region},
		Key:      clientKey,
		Logf:     logger.Discard,
	})
	if err != nil {
		return nil, err
	}
	if err := dialer.Start(ctx); err != nil {
		dialer.Close()
		return nil, err
	}
	return dialer, nil
}
