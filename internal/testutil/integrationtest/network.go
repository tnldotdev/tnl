package integrationtest

import (
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

func DERP(t testing.TB) *tailcfg.DERPRegion {
	t.Helper()
	region, _ := DERPWithServer(t)
	return region
}

func DERPWithServer(t testing.TB) (*tailcfg.DERPRegion, *derpserver.Server) {
	t.Helper()
	server := derpserver.New(key.NewNode(), logger.Discard)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(derpserver.Handler(server))
	httpServer.Listener.Close()
	httpServer.Listener = listener
	httpServer.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpServer.Config.ErrorLog = log.New(io.Discard, "", 0)
	httpServer.StartTLS()
	stunAddress, stopSTUN := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() {
		httpServer.CloseClientConnections()
		httpServer.Close()
		server.Close()
		stopSTUN()
	})
	return &tailcfg.DERPRegion{
		RegionID: 1, RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
			STUNPort: stunAddress.Port, DERPPort: listener.Addr().(*net.TCPAddr).Port,
			InsecureForTests: true, STUNTestIP: "127.0.0.1",
		}},
	}, server
}
