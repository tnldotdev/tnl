package tailtransport

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func runTestDERP(t testing.TB) *tailcfg.DERPRegion {
	t.Helper()
	region, _ := runTestDERPWithServer(t)
	return region
}

func runTestDERPWithServer(t testing.TB) (*tailcfg.DERPRegion, *derpserver.Server) {
	t.Helper()
	d := derpserver.New(key.NewNode(), logger.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsrv := httptest.NewUnstartedServer(derpserver.Handler(d))
	httpsrv.Listener.Close()
	httpsrv.Listener = ln
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	httpsrv.StartTLS()
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
	})
	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name:             "test",
			RegionID:         1,
			HostName:         "127.0.0.1",
			IPv4:             "127.0.0.1",
			IPv6:             "none",
			STUNPort:         stunAddr.Port,
			DERPPort:         ln.Addr().(*net.TCPAddr).Port,
			InsecureForTests: true,
			STUNTestIP:       "127.0.0.1",
		}},
	}, d
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
