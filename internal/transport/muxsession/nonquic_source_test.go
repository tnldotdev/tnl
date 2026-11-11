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

func TestNonQUICReaderRacingShutdownDoesNotBlockQueueDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		serverTLS, _ := testTLSConfigs(t)
		for range 128 {
			packet := &scriptedQUICSocket{packets: make(chan sourceQUICPacket), done: make(chan struct{})}
			listener, err := ListenQUICPacket(packet, serverTLS, QUICConfig{PinnedRemoteIPLimit: 3})
			if err != nil {
				t.Fatal(err)
			}
			child := listener.NonQUICPackets(t.Context())
			s := listener.sources
			s.nonQUICQueue <- sourceQUICPacket{data: []byte("discovery"), address: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}}
			read := make(chan struct{})
			go func() { defer close(read); _, _, _ = child.ReadFrom(make([]byte, 32)) }()
			closed := make(chan error, 1)
			go func() { closed <- listener.Close() }()
			synctest.Wait()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("listener close blocked behind its discovery reader")
			}
			select {
			case <-read:
			default:
				t.Fatal("discovery reader did not finish on listener close")
			}
			if len(s.nonQUICQueue) != 0 {
				t.Fatal("shutdown retained discovery buffers")
			}
			_ = child.Close()
		}
	})
}
