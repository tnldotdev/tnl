package relay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestSTUNWildcardSharedSocketPreservesPerPacketReplySource(t *testing.T) {
	for _, network := range []string{"udp4", "udp"} {
		t.Run(network, func(t *testing.T) {
			serverTLS, _ := stunTLSConfigs(t)
			listener, err := muxsession.ListenQUIC(":0", serverTLS, muxsession.QUICConfig{UDPNetwork: network, PinnedRemoteIPLimit: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(t.Context())
			packets := listener.NonQUICPackets(ctx)
			// send to two local IPs from one source socket before starting the
			// responder, so cached metadata keyed only by source cannot pass.
			client, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			port := listener.Addr().(*net.UDPAddr).Port
			for i, ip := range []string{"127.0.0.1", "127.0.0.2"} {
				request := stunTestRequest()
				request[8] = byte(i)
				if _, err := client.WriteTo(request, &net.UDPAddr{IP: net.ParseIP(ip), Port: port}); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- ServeSTUN(ctx, packets, nil) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			seen := make(map[string]bool)
			for range 2 {
				buffer := make([]byte, 512)
				n, source, err := client.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				request := stunTestRequest()
				request[8] = buffer[8]
				expected := []string{"127.0.0.1", "127.0.0.2"}[int(buffer[8])]
				if source.(*net.UDPAddr).IP.String() != expected || source.(*net.UDPAddr).Port != port {
					t.Fatal("STUN reply lost its received local destination", source, expected)
				}
				assertSTUNTestResponse(t, request, buffer[:n], client.LocalAddr().(*net.UDPAddr))
				seen[expected] = true
			}
			if len(seen) != 2 {
				t.Fatal("STUN replies reused metadata from another request")
			}
		})
	}
}
