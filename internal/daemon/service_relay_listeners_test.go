package daemon

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

type serviceRelayTestListener struct {
	closed bool
	err    error
}

func (*serviceRelayTestListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (*serviceRelayTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (l *serviceRelayTestListener) Close() error { l.closed = true; return l.err }

func TestServiceRuntimeRelayListenersReserveBothProtocols(t *testing.T) {
	// the first candidate's UDP port is deliberately occupied. retain its TCP
	// listener too so another test cannot spend the setup's reservation.
	first, occupied, err := reserveServiceRuntimeRelayListeners(net.Listen, net.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer occupied.Close()
	if err := first.(*net.TCPListener).SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	var collision error
	listener, packet, err := reserveServiceRuntimeRelayListeners(func(network, address string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		// Accept fails immediately only once the rejected reservation is closed.
		if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatal("partial TCP reservation was not closed before choosing again", err)
		}
		return net.Listen(network, address)
	}, func(network, address string) (net.PacketConn, error) {
		packet, err := net.ListenPacket(network, address)
		if calls == 1 {
			collision = err
		}
		return packet, err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer packet.Close()
	if !errors.Is(collision, syscall.EADDRINUSE) || calls < 2 || listener.Addr().String() != packet.LocalAddr().String() {
		t.Fatal("did not reserve one free TCP/UDP address after collision", calls, collision)
	}
	probe, bindErr := net.ListenPacket("udp4", occupied.LocalAddr().String())
	if probe != nil {
		defer probe.Close()
	}
	if !errors.Is(bindErr, syscall.EADDRINUSE) {
		t.Fatal("reservation closed the unrelated occupied UDP socket", bindErr)
	}
}

func TestServiceRuntimeRelayListenersRetainFailuresAndBoundCollisions(t *testing.T) {
	for _, boundary := range []string{"tcp", "udp", "close", "collisions"} {
		t.Run(boundary, func(t *testing.T) {
			failure := errors.New("fixture reservation failed")
			var listeners []*serviceRelayTestListener
			packets := 0
			listener, packet, err := reserveServiceRuntimeRelayListeners(func(string, string) (net.Listener, error) {
				if boundary == "tcp" {
					return nil, failure
				}
				l := &serviceRelayTestListener{}
				if boundary == "close" {
					l.err = failure
				}
				listeners = append(listeners, l)
				return l, nil
			}, func(string, string) (net.PacketConn, error) {
				packets++
				if boundary == "udp" {
					return nil, failure
				}
				return nil, &net.OpError{Op: "listen", Net: "udp4", Err: syscall.EADDRINUSE}
			})
			if listener != nil || packet != nil || err == nil {
				t.Fatal("failed reservation returned sockets", err)
			}
			for _, l := range listeners {
				if !l.closed {
					t.Fatal("failed reservation retained a TCP listener")
				}
			}
			if boundary == "collisions" {
				if packets != 16 || !errors.Is(err, syscall.EADDRINUSE) {
					t.Fatal("collisions were unbounded or lost their cause", packets, err)
				}
			} else if !errors.Is(err, failure) || packets > 1 {
				t.Fatal("non-collision failure was retried or lost", packets, err)
			}
			if boundary == "close" && !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatal("cleanup error hid the bind collision", err)
			}
		})
	}
}
