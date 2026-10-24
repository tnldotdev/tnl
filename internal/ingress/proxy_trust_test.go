package ingress

import (
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
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

func TestTrustedConnectorPortCannotBecomePublicRouting(t *testing.T) {
	connector, _, _, roots, _, _ := privateTestSetup(t)
	t.Cleanup(func() { _ = connector.Close() })
	var lookups atomic.Int32
	_, address := startIngress(t, Config{RequireProxyHeader: true,
		TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		ConnectorPort:     4443, PrivateHostname: "ingress.test", Connector: connector,
		Lookup: func(string) (PublicURL, LookupReason) { lookups.Add(1); return PublicURL{}, LookupNotFound },
	})
	for _, test := range []struct {
		port     uint16
		host     string
		accepted bool
	}{{4443, "ingress.test", true}, {4444, "ingress.test", false}, {443, "ingress.test", false}, {4443, "public.example.test", false}} {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("127.0.0.1:40000"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), test.port)})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = connection.Write(metadata)
		config := roots.Clone()
		config.ServerName, config.NextProtos = test.host, []string{muxsession.ConnectorALPN}
		client := tls.Client(connection, config)
		err = client.HandshakeContext(t.Context())
		_ = client.Close()
		if (err == nil) != test.accepted {
			t.Fatalf("%s:%d: handshake=%v", test.host, test.port, err)
		}
	}
	if lookups.Load() != 0 {
		t.Fatal("connector endpoint reached public routing")
	}
}
