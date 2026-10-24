package service

import (
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativeAdmissionRejectsPermissionAndReservationSubstitutionBeforeTargetWork(t *testing.T) {
	for _, name := range []string{"token", "key", "signature", "session", "subject", "metadata", "allocation", "allocation-owner", "initial"} {
		t.Run(name, func(t *testing.T) {
			target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			_, bound, ref, _ := privateFixture(t, target.Addr().String())
			header := privateHeader(t, ref)
			entry := nativeFixtureOpening(t, header)
			var initial []byte
			switch name {
			case "token":
				entry.Permission.Token = "opaque-workload-credential"
			case "key":
				entry.Permission.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			case "signature":
				entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			case "session":
				header.Connector.SessionID = "cns_" + strings.Repeat("z", 22)
			case "subject":
				header.Connector.Subject.DeviceID = "vdev_" + strings.Repeat("z", 22)
			case "metadata":
				entry.MetadataRevision++
			case "allocation":
				header.Reservation.AllocationID = "salloc_" + strings.Repeat("z", 22)
			case "allocation-owner":
				header.Reservation.IngressLeaseRevision++
			case "initial":
				initial = []byte("changed visitor bytes")
			}
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { defer server.Close(); done <- bound.serveBody(t.Context(), ref, server, header) }()
			proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:25443")})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = client.Write(proxy)
			_, _ = tunnelv1.WriteConnectorVisitorOpening(client, entry, initial)
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("invalid native admission entered protocol negotiation")
			}
			if err := <-done; err == nil {
				t.Fatal("invalid native admission succeeded")
			}
			_ = target.SetDeadline(time.Now().Add(10 * time.Millisecond))
			if conn, err := target.Accept(); err == nil {
				_ = conn.Close()
				t.Fatal("invalid native admission dialed its target")
			}
		})
	}
}
