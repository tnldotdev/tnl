package ingress

import (
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

func TestUntrustedPeerCannotSupplyOriginalDestination(t *testing.T) {
	var lookups atomic.Int32
	_, address := startIngress(t, Config{RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("192.0.2.8/32")}, Lookup: func(string) (PublicURL, LookupReason) {
		lookups.Add(1)
		return PublicURL{}, LookupNotFound
	}})
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.8:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write(metadata)
	client := tls.Client(connection, &tls.Config{ServerName: "route.example", MinVersion: tls.VersionTLS13})
	if err := client.Handshake(); err == nil {
		t.Fatal("untrusted peer supplied source metadata")
	}
	if lookups.Load() != 0 {
		t.Fatal("untrusted source reached hostname routing")
	}
}
