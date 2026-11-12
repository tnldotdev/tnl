package transporttest

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

const tcpUDPListenAttempts = 16

// ListenTCPUDP reserves one loopback port for both transports. keep both sockets
// open through handoff; a TCP allocation alone does not reserve the UDP port.
func ListenTCPUDP() (net.Listener, net.PacketConn, error) {
	return listenTCPUDP(net.Listen, net.ListenPacket)
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
