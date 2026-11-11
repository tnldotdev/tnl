package muxsession

import (
	"net"
	"testing"
	"time"
)

func TestNonQUICReplyAddressesRetainIndependentSourceMetadata(t *testing.T) {
	for _, network := range []string{"udp4", "udp"} {
		t.Run(network, func(t *testing.T) {
			serverTLS, _ := testTLSConfigs(t)
			listener, err := ListenQUIC(":0", serverTLS, QUICConfig{UDPNetwork: network, PinnedRemoteIPLimit: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			packets := listener.NonQUICPackets(t.Context())
			defer packets.Close()
			client, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			_ = packets.SetReadDeadline(time.Now().Add(3 * time.Second))
			port := listener.Addr().(*net.UDPAddr).Port
			var replies []net.Addr
			for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
				if _, err := client.WriteTo([]byte("\x00request"), &net.UDPAddr{IP: net.ParseIP(ip), Port: port}); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 64)
				_, reply, err := packets.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				replies = append(replies, reply)
			}
			// reply to the first request only after reading the second, then to
			// the second. metadata cached by remote address would answer both .2.
			for i, reply := range replies {
				if _, err := packets.WriteTo([]byte("\x00reply"), reply); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 64)
				_, source, err := client.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := source.(*net.UDPAddr).IP.String(), []string{"127.0.0.1", "127.0.0.2"}[i]; got != want {
					t.Fatal("packet reply reused another request's source metadata", got, want)
				}
			}
		})
	}
}
