package daemon

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestIntegrationPostQuantumPublicURLVisitorPolicy(t *testing.T) {
	for _, require := range []bool{false, true} {
		name := "default"
		if require {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newStandalonePublishFixture(t, "pq-"+name)
			var requests atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			cleanupIntegrationHTTPServer(t, target, fixture.owner)
			quic, tcp := fixture.connectors()
			cfg := fixture.identity.publisherConfig(target.URL, quic, tcp)
			cfg.RequirePostQuantum = &require
			handle := startOwnedIntegrationPublisher(t, fixture.owner, cfg, fixture.diagnostics)
			ready := fixture.waitReady(t, handle)
			for _, test := range []struct {
				name     string
				group    tls.CurveID
				version  uint16
				accepted bool
			}{
				{"hybrid", tls.X25519MLKEM768, tls.VersionTLS13, true},
				{"classical", tls.X25519, tls.VersionTLS13, !require},
				{"tls12", tls.X25519, tls.VersionTLS12, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					visitor := newProxiedIntegrationVisitor(t, fixture.pebble.roots, fixture.ingressAddress, fixture.owner)
					visitor.transport.TLSClientConfig.CurvePreferences = []tls.CurveID{test.group}
					visitor.transport.TLSClientConfig.MinVersion = test.version
					visitor.transport.TLSClientConfig.MaxVersion = test.version
					before := requests.Load()
					response, _, err := visitor.requestURL(http.MethodGet, ready.PublicURL, nil)
					if !test.accepted {
						if err == nil || requests.Load() != before {
							t.Fatalf("unsupported visitor reached HTTP: response=%v err=%v", response, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusNoContent || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.CurveID != test.group || requests.Load() != before+1 {
						t.Fatalf("visitor TLS policy: response=%v TLS=%+v requests=%d", response.Status, response.TLS, requests.Load()-before)
					}
				})
			}
			stopIntegrationPublisher(t, handle)
		})
	}
}
