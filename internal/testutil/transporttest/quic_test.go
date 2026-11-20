package transporttest

import (
	"net"
	"testing"
)

func TestQUICTransportReservesDistinctIPv4Loopback(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	transport := QUICTransport(t)
	address, ok := transport.LocalAddr().(*net.UDPAddr)
	if !ok || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("local QUIC fixture must reserve IPv4 loopback, not a wildcard", transport.LocalAddr())
	}
	if address.Port == listener.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("fixture reused its peer's reserved UDP port")
	}
}
