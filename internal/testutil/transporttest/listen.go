package transporttest

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

const tcpUDPListenAttempts = 16

// ListenTCPUDP reserves one loopback port for both transports. keep both sockets
// open through handoff; a TCP allocation alone does not reserve the UDP port.
func ListenTCPUDP(t testing.TB) (net.Listener, net.PacketConn) {
	t.Helper()
	tcp, udp, err := listenTCPUDP(net.Listen, net.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
	return tcp, udp
}

func listenTCPUDP(listen func(string, string) (net.Listener, error), listenPacket func(string, string) (net.PacketConn, error)) (net.Listener, net.PacketConn, error) {
	var collision error
	for range tcpUDPListenAttempts {
		tcp, err := listen("tcp", "127.0.0.1:0")
		if err != nil {
			if !errors.Is(err, syscall.EADDRINUSE) {
				return nil, nil, err
			}
			collision = err
			continue
		}
		udp, err := listenPacket("udp", tcp.Addr().String())
		if err == nil {
			return tcp, udp, nil
		}
		closeErr := tcp.Close()
		if closeErr != nil || !errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil, errors.Join(err, closeErr)
		}
		collision = err
	}
	return nil, nil, fmt.Errorf("reserve same-port TCP/UDP after %d attempts: %w", tcpUDPListenAttempts, collision)
}
