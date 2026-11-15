package ingress

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type countingServiceControl struct {
	PublicServiceControl
	calls atomic.Int32
}

func (c *countingServiceControl) AdmitPublicServiceVisitor(ctx context.Context, id string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	c.calls.Add(1)
	return c.PublicServiceControl.AdmitPublicServiceVisitor(ctx, id, claim)
}

func TestUntrustedPeerCannotSupplyOriginalDestination(t *testing.T) {
	config, _, _, _ := publicServiceTestConfig(t)
	control := &countingServiceControl{PublicServiceControl: config.Control}
	config.Control = control
	config.RequireProxyHeader = true
	config.TrustedProxyPeers = []netip.Prefix{netip.MustParsePrefix("192.0.2.8/32")}
	_, address := startIngress(t, config)
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
	if control.calls.Load() != 0 {
		t.Fatal("untrusted source reached service admission")
	}
}
