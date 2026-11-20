package transporttest

import (
	"net"
	"testing"
)

func TestQUICTransportReservesDistinctIPv4Wildcard(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	transport := QUICTransport(t)
	address, ok := transport.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP.To4() == nil || !address.IP.IsUnspecified() {
		t.Fatal("QUIC fixture needs an IPv4 wildcard for local and separated peers", transport.LocalAddr())
	}
	if address.Port == listener.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("fixture reused its peer's reserved UDP port")
	}
}
