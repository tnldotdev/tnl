package transporttest

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestListenTCPUDPClosesCollisionAndRetainsQUICHandoff(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid TLS", true: "serving"}[valid], func(t *testing.T) {
			rejectedTCP, occupiedUDP := ListenTCPUDP(t)
			acceptedTCP, acceptedUDP := ListenTCPUDP(t)
			rejected := &trackedTCPListener{Listener: rejectedTCP}
			calls := 0
			tcp, packet, err := listenTCPUDP(func(network, address string) (net.Listener, error) {
				calls++
				if network != "tcp" || address != "127.0.0.1:0" {
					t.Fatal("changed loopback TCP reservation", network, address)
				}
				if calls == 1 {
					return rejected, nil
				}
				if rejected.closes != 1 {
					t.Fatal("retried before closing the rejected TCP reservation")
				}
				if _, err := rejectedTCP.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Fatal("rejected TCP reservation remains open", err)
				}
				return acceptedTCP, nil
			}, func(network, address string) (net.PacketConn, error) {
				if calls == 1 {
					// the TCP socket is still bound, but its UDP port is already owned.
					if address != occupiedUDP.LocalAddr().String() {
						t.Fatal("collision did not use the TCP port", address)
					}
					packet, err := net.ListenPacket(network, address)
					if packet != nil {
						_ = packet.Close()
					}
					if !errors.Is(err, syscall.EADDRINUSE) {
						t.Fatal("fixture did not force a real UDP collision", err)
					}
					return nil, err
				}
				if network != "udp" || address != acceptedUDP.LocalAddr().String() {
					t.Fatal("changed accepted UDP reservation", network, address)
				}
				return acceptedUDP, nil
			})
			if err != nil {
				t.Fatal("UDP collision prevented another reservation", err)
			}
			if calls != 2 || tcp != acceptedTCP || packet != acceptedUDP || tcp.Addr().String() != packet.LocalAddr().String() {
				t.Fatal("pair reservation replaced its accepted sockets", calls)
			}
			assertUDPReserved(t, occupiedUDP.LocalAddr().String())
			address := packet.LocalAddr().String()
			assertUDPReserved(t, address)
			_, certificate := testutil.TLSCertificate(t, []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			server := &tls.Config{Certificates: []tls.Certificate{certificate}}
			if !valid {
				server = nil
			}
			listener, err := muxsession.ListenQUICPacket(packet, server, muxsession.QUICConfig{})
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				if listener.Addr().String() != address {
					t.Fatal("QUIC listener changed its reserved port")
				}
				assertUDPReserved(t, address)
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				_ = listener.Close()
				t.Fatal("invalid TLS started QUIC serving")
			}
			rebound, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal("QUIC owner did not release the reserved socket", err)
			}
			_ = rebound.Close()
		})
	}
}

func TestListenTCPUDPBoundsRetriesToAddressInUse(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, cause := range []error{syscall.EADDRINUSE, syscall.EACCES} {
			t.Run(network+"/"+cause.Error(), func(t *testing.T) {
				calls := 0
				var previous *trackedTCPListener
				failure := &net.OpError{Op: "listen", Net: network, Err: cause}
				tcp, udp, err := listenTCPUDP(func(string, string) (net.Listener, error) {
					if previous != nil && previous.closes != 1 {
						t.Fatal("another attempt began before rejected TCP cleanup")
					}
					calls++
					if network == "tcp" {
						return nil, failure
					}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = listener.Close() })
					previous = &trackedTCPListener{Listener: listener}
					return previous, nil
				}, func(string, string) (net.PacketConn, error) {
					if network == "tcp" {
						t.Fatal("failed TCP acquisition tried UDP")
					}
					return nil, failure
				})
				want := 1
				if errors.Is(cause, syscall.EADDRINUSE) {
					want = tcpUDPListenAttempts
				}
				if tcp != nil || udp != nil || !errors.Is(err, cause) || calls != want || previous != nil && previous.closes != 1 {
					t.Fatal("reservation retried the wrong failure, exceeded its bound, or leaked TCP", calls, err)
				}
			})
		}
	}
}

func TestListenTCPUDPRetainsCleanupFailureWithoutRetry(t *testing.T) {
	listener, _ := ListenTCPUDP(t)
	cleanup := errors.New("TCP cleanup failed")
	tracked := &trackedTCPListener{Listener: listener, closeErr: cleanup}
	calls := 0
	tcp, udp, err := listenTCPUDP(func(string, string) (net.Listener, error) {
		calls++
		return tracked, nil
	}, func(string, string) (net.PacketConn, error) {
		return nil, syscall.EADDRINUSE
	})
	if tcp != nil || udp != nil || calls != 1 || tracked.closes != 1 || !errors.Is(err, cleanup) || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("cleanup failure was lost or another reservation started", calls, err)
	}
}

type trackedTCPListener struct {
	net.Listener
	closes   int
	closeErr error
}

func (l *trackedTCPListener) Close() error {
	l.closes++
	return errors.Join(l.Listener.Close(), l.closeErr)
}

func assertUDPReserved(t *testing.T, address string) {
	t.Helper()
	other, err := net.ListenPacket("udp", address)
	if other != nil {
		_ = other.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("UDP reservation was released before handoff or owner close", err)
	}
}
