package publisher

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

func TestPublicHTTPSPostQuantumPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		require  bool
		group    tls.CurveID
		version  uint16
		accepted bool
	}{
		{"default hybrid", false, tls.X25519MLKEM768, tls.VersionTLS13, true},
		{"default classical", false, tls.X25519, tls.VersionTLS13, true},
		{"strict hybrid", true, tls.X25519MLKEM768, tls.VersionTLS13, true},
		{"strict classical", true, tls.X25519, tls.VersionTLS13, false},
		{"default tls12", false, tls.X25519, tls.VersionTLS12, false},
		{"strict tls12", true, tls.X25519, tls.VersionTLS12, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			certificate := visitorfixture.Certificate(t, "route.example")
			route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Target: target.URL, Certificate: certificate, RequirePostQuantum: test.require})
			if err != nil {
				t.Fatal(err)
			}
			if err := route.Start(); err != nil {
				t.Fatal(err)
			}
			defer route.Close()
			handled := make(chan struct{})
			wire, err := openHTTPTestRouteServer(route, handled)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = wire.Close(); awaitPublisherTest(t, handled) }()
			visitor := tls.Client(wire, &tls.Config{
				RootCAs: visitorfixture.Roots(t, certificate), ServerName: "route.example",
				MinVersion: test.version, MaxVersion: test.version, CurvePreferences: []tls.CurveID{test.group},
			})
			err = visitor.HandshakeContext(t.Context())
			if !test.accepted {
				if err == nil || requests.Load() != 0 {
					t.Fatalf("rejected client reached HTTP: handshake=%v requests=%d", err, requests.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if state := visitor.ConnectionState(); state.CurveID != test.group || state.Version != tls.VersionTLS13 {
				t.Fatalf("public HTTPS negotiated %s with TLS %x", state.CurveID, state.Version)
			}
			if _, err := fmt.Fprint(visitor, "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(visitor), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusNoContent || requests.Load() != 1 {
				t.Fatalf("status=%d requests=%d", response.StatusCode, requests.Load())
			}
		})
	}
}
