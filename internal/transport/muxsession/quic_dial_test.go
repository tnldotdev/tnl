package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
)

type testQUICDialFunc func(context.Context, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error)

func (f testQUICDialFunc) DialQUIC(ctx context.Context, addr net.Addr, trust *tls.Config, config *quic.Config) (*quic.Conn, error) {
	return f(ctx, addr, trust, config)
}

func TestSharedQUICResolutionHonorsCancellation(t *testing.T) {
	for _, mode := range []string{"cancelled before lookup", "cancelled during lookup", "deadline during lookup"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cause := errors.New("caller cancelled QUIC discovery")
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				if mode == "deadline during lookup" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, time.Second)
					defer stop()
					cause = context.DeadlineExceeded
				}
				started := make(chan struct{})
				lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
					if network != "ip" || host != "relay.test" {
						t.Error("unexpected QUIC resolution inputs", network, host)
					}
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				dial := testQUICDialFunc(func(context.Context, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
					t.Error("cancelled discovery reached the socket dialer")
					return nil, errors.New("unexpected dial")
				})
				if mode == "cancelled before lookup" {
					cancel(cause)
				}
				done := make(chan error, 1)
				go func() {
					_, err := dialSharedQUIC(ctx, dial, "relay.test:443", nil, nil, lookup)
					done <- err
				}()
				if mode != "cancelled before lookup" {
					<-started
					if mode == "cancelled during lookup" {
						cancel(cause)
					}
				}
				if err := <-done; !errors.Is(err, cause) {
					t.Fatal("QUIC resolution did not retain caller cancellation", err)
				}
				if mode == "cancelled before lookup" {
					select {
					case <-started:
						t.Fatal("already cancelled caller started DNS resolution")
					default:
					}
				}
			})
		})
	}
}

func TestSharedQUICLiteralAddressesPreserveScopeAndSkipDNS(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "[fe80::1%en0]:65535"} {
		t.Run(address, func(t *testing.T) {
			wanted := netip.MustParseAddrPort(address)
			sentinel := errors.New("literal dial failed")
			dial := testQUICDialFunc(func(_ context.Context, addr net.Addr, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				if got := addr.(*net.UDPAddr).AddrPort(); got != wanted {
					t.Fatal("QUIC literal lost its IP, port, or zone", got, wanted)
				}
				return nil, sentinel
			})
			_, err := dialSharedQUIC(t.Context(), dial, address, nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
				t.Fatal("literal QUIC endpoint performed DNS resolution")
				return nil, nil
			})
			if !errors.Is(err, sentinel) {
				t.Fatal("literal dial failure was not retained", err)
			}
		})
	}
}

func TestSharedQUICRejectsInvalidNumericPortsBeforeResolution(t *testing.T) {
	for _, address := range []string{"relay.test", "relay.test:", "relay.test:https", "relay.test:0", "relay.test:-1", "relay.test:65536", ":443"} {
		t.Run(address, func(t *testing.T) {
			dial := testQUICDialFunc(func(context.Context, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
				t.Fatal("invalid QUIC endpoint reached the socket dialer")
				return nil, nil
			})
			_, err := dialSharedQUIC(t.Context(), dial, address, nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
				t.Fatal("invalid QUIC endpoint performed DNS resolution")
				return nil, nil
			})
			if err == nil {
				t.Fatal("invalid QUIC endpoint was accepted")
			}
		})
	}
}

func TestSharedQUICResolutionFailuresDoNotDial(t *testing.T) {
	sentinel := errors.New("DNS lookup failed")
	for _, failure := range []error{nil, sentinel} {
		dial := testQUICDialFunc(func(context.Context, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
			t.Fatal("failed or empty DNS resolution reached the socket dialer")
			return nil, nil
		})
		_, err := dialSharedQUIC(t.Context(), dial, "relay.test:443", nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, failure
		})
		if err == nil || failure != nil && !errors.Is(err, failure) {
			t.Fatal("QUIC resolution failure was not retained", err)
		}
	}
}

func TestSharedQUICTriesAllResolvedAddressesAndRetainsFailures(t *testing.T) {
	addresses := []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}
	failures := []error{errors.New("IPv6 socket unavailable"), errors.New("IPv4 peer unavailable")}
	var attempted []netip.Addr
	dial := testQUICDialFunc(func(_ context.Context, addr net.Addr, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		attempted = append(attempted, addr.(*net.UDPAddr).AddrPort().Addr())
		return nil, failures[len(attempted)-1]
	})
	_, err := dialSharedQUIC(t.Context(), dial, "relay.test:443", nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
		return addresses, nil
	})
	if !reflect.DeepEqual(attempted, []netip.Addr{addresses[1], addresses[0]}) || !errors.Is(err, failures[0]) || !errors.Is(err, failures[1]) {
		t.Fatal("QUIC did not try all resolved addresses or retain their failures", attempted, err)
	}
}

func TestSharedQUICLeavesCallerBudgetForAnotherAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		var attempted []netip.Addr
		connected := new(quic.Conn)
		addresses := []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}
		dial := testQUICDialFunc(func(attemptCtx context.Context, addr net.Addr, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			attempted = append(attempted, addr.(*net.UDPAddr).AddrPort().Addr())
			if len(attempted) == 1 {
				deadline, ok := attemptCtx.Deadline()
				if !ok || time.Until(deadline) != 30*time.Second {
					t.Fatal("first address could spend the entire caller deadline")
				}
				<-attemptCtx.Done()
				return nil, attemptCtx.Err()
			}
			return connected, nil
		})
		connection, err := dialSharedQUIC(ctx, dial, "relay.test:443", nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
			return addresses, nil
		})
		if err != nil || connection != connected || ctx.Err() != nil || !reflect.DeepEqual(attempted, []netip.Addr{addresses[1], addresses[0]}) {
			t.Fatal("unreachable first address prevented the second QUIC attempt", attempted, err)
		}
	})
}

func TestSharedQUICRelayLegsPreferCommonIPv4Family(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	for _, addresses := range [][]netip.Addr{{netip.MustParseAddr("2001:db8::1"), ipv4}, {ipv4}} {
		var attempted []netip.Addr
		connected := new(quic.Conn)
		dial := testQUICDialFunc(func(_ context.Context, addr net.Addr, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			attempted = append(attempted, addr.(*net.UDPAddr).AddrPort().Addr())
			return connected, nil
		})
		connection, err := dialSharedQUIC(t.Context(), dial, "relay.test:443", nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
			return addresses, nil
		})
		if err != nil || connection != connected || !reflect.DeepEqual(attempted, []netip.Addr{ipv4}) {
			t.Fatal("compatible relays selected different address families", attempted, err)
		}
	}
}

func TestSharedQUICCancellationPreventsAnotherAddressAttempt(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	cause := errors.New("caller stopped QUIC dial")
	var attempts int
	dial := testQUICDialFunc(func(context.Context, net.Addr, *tls.Config, *quic.Config) (*quic.Conn, error) {
		attempts++
		cancel(cause)
		return nil, context.Canceled
	})
	_, err := dialSharedQUIC(ctx, dial, "relay.test:443", nil, nil, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}, nil
	})
	if attempts != 1 || !errors.Is(err, cause) {
		t.Fatal("cancelled caller started another QUIC address attempt", attempts, err)
	}
}

func TestSharedQUICDualStackResolutionUsesBorrowedIPv4Socket(t *testing.T) {
	for _, unreachableFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "IPv6 first", false: "IPv4 first"}[unreachableFirst], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := testTLSConfigs(t)
			listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{PinnedRemoteIPLimit: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			transport := &quic.Transport{Conn: packet}
			defer transport.Close()
			trust, err := transportTLSConfig(clientTLS, "relay.test", false)
			if err != nil {
				t.Fatal(err)
			}
			addresses := []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}
			if !unreachableFirst {
				addresses[0], addresses[1] = addresses[1], addresses[0]
			}
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			connection, err := dialSharedQUIC(ctx, borrowedTestQUICDialer{transport}, net.JoinHostPort("relay.test", port), trust, quicConnectorConfig(nil), func(context.Context, string, string) ([]netip.Addr, error) {
				return addresses, nil
			})
			if err != nil {
				t.Fatal("dual-stack resolution did not reach the available IPv4 peer", err)
			}
			client := &quicSession{connection: connection}
			defer client.Close()
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			assertRoundTrip(t, client, server, "after cancelling a per-address dial context")
		})
	}
}
