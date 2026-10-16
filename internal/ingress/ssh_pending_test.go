package ingress

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
)

func TestIngressRestrictedSSHForwardsRawBytesOnPendingCapacity(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &pendingDatabaseBackend{connection: a}
	received := make(chan proxyproto.Header, 1)
	worker := ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		header, replay, err := proxyproto.Decode(b)
		if err != nil {
			return err
		}
		received <- header
		var identification [16]byte
		if _, err := io.ReadFull(replay, identification[:]); err != nil {
			return err
		}
		if string(identification[:]) != "SSH-2.0-client\r\n" {
			return errors.New("ingress altered raw SSH identification")
		}
		_, err = b.Write([]byte("SSH-2.0-tnl\r\n"))
		return err
	})
	s, address := startIngress(t, Config{RequireProxyHeader: true, LookupPort: func(uint16) (PublicURL, LookupReason) {
		return PublicURL{ID: "ssh", PublishRunNumber: 1, AccessMode: "restricted", AllowAll: true,
			ServiceProtocol: "ssh", PublicPort: testPublicPort(2222), Backends: []routebackend.Backend{backend}}, LookupCurrent
	}})
	client := separatedVisitor(t, address, "198.51.100.1:40001", 2222)
	if _, err := io.WriteString(client, "SSH-2.0-client\r\n"); err != nil {
		t.Fatal(err)
	}
	header := ingressAwait(t, received)
	if header.Source.String() != "198.51.100.1:40001" || header.Destination.Port() != 2222 {
		t.Fatal("pending SSH changed trusted visitor metadata")
	}
	if s.Load() != 0 || backend.pending.Load() != 1 || backend.ordinary.Load() != 0 {
		t.Fatal("restricted SSH bypassed pending capacity")
	}
	var answer [13]byte
	if _, err := io.ReadFull(client, answer[:]); err != nil || string(answer[:]) != "SSH-2.0-tnl\r\n" {
		t.Fatalf("pending raw SSH exchange = %q, %v", answer, err)
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
}
