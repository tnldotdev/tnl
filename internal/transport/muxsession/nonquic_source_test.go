package muxsession

import (
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
)

func TestNonQUICFloodDoesNotAllocateQUICSourcesAndJoinsShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		serverTLS, _ := testTLSConfigs(t)
		packet := &scriptedQUICSocket{packets: make(chan sourceQUICPacket, 512), done: make(chan struct{})}
		listener, err := ListenQUICPacket(packet, serverTLS, QUICConfig{PinnedRemoteIPLimit: 3})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		child := listener.NonQUICPackets(t.Context())
		defer child.Close()
		for index := range 256 {
			address := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(index / 255), byte(index%255 + 1)}), 443))
			packet.packets <- sourceQUICPacket{data: make([]byte, sourceNonQUICPacketBytes+1), address: address}
			packet.packets <- sourceQUICPacket{data: make([]byte, sourceNonQUICPacketBytes), address: address}
		}
		synctest.Wait()
		s := listener.sources
		s.mu.Lock()
		count, pending, queued, discovery := len(s.sources), s.pending, s.queuedBytes, len(s.nonQUICQueue)
		s.mu.Unlock()
		if count != 0 || pending != 0 || queued != 0 || discovery != sourceNonQUICQueue {
			t.Fatal("discovery flood escaped its separate bounded queue", count, pending, queued, discovery)
		}
		_ = child.Close()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if len(s.nonQUICQueue) != 0 {
			t.Fatal("shutdown retained discovery packet buffers")
		}
	})
}
