package ingress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

func TestTrustedProxyReadinessDoesNotAdmitVisitors(t *testing.T) {
	var ready atomic.Bool
	var lookups atomic.Int32
	_, address := startIngress(t, Config{
		RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		CheckReady: ready.Load,
		Lookup:     func(string) (PublicURL, LookupReason) { lookups.Add(1); return PublicURL{}, LookupNotFound },
	})
	for _, healthy := range []bool{false, true, false} {
		ready.Store(healthy)
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = fmt.Fprint(connection, "GET /ready HTTP/1.1\r\nHost: health\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(connection), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		_ = connection.Close()
		want := http.StatusServiceUnavailable
		if healthy {
			want = http.StatusNoContent
		}
		if response.StatusCode != want {
			t.Fatalf("ready=%t: status=%d, want %d", healthy, response.StatusCode, want)
		}
	}
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = connection.Write(append(metadata, []byte("GET /ready HTTP/1.1\r\nHost: health\r\n\r\n")...))
	response, _ := io.ReadAll(connection)
	if len(response) != 0 || lookups.Load() != 0 {
		t.Fatal("proxied visitor reached the readiness endpoint or hostname lookup")
	}
}

func TestReadinessRejectsUntrustedPeersAndNonProbeRequests(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		peer := "192.0.2.1/32"
		if trusted {
			peer = "127.0.0.1/32"
		}
		var checks atomic.Int32
		_, address := startIngress(t, Config{
			RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix(peer)},
			CheckReady: func() bool { checks.Add(1); return true },
			Lookup: func(string) (PublicURL, LookupReason) {
				t.Error("probe reached routing")
				return PublicURL{}, LookupNotFound
			},
		})
		requests := []string{"GET /ready?secret=x HTTP/1.1\r\nHost: health\r\n\r\n", "GET /ready HTTP/1.1\r\nHost: health\r\nContent-Length: 1\r\n\r\nx",
			"GET /ready HTTP/1.1\r\nHost: health\r\nX-Oversize: " + strings.Repeat("x", 4096) + "\r\n\r\n",
			"GET /ready HTTP/1.1\r\nHost: health\r\nUpgrade: websocket\r\n\r\n"}
		if !trusted {
			requests = append(requests, "GET /ready HTTP/1.1\r\nHost: health\r\n\r\n")
		}
		for _, request := range requests {
			connection, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(connection, request)
			response, err := http.ReadResponse(bufio.NewReader(connection), nil)
			_ = connection.Close()
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode < 300 {
					t.Fatal("non-probe request received a healthy response")
				}
			}
		}
		if checks.Load() != 0 {
			t.Fatal("non-probe request invoked readiness")
		}
	}
}
