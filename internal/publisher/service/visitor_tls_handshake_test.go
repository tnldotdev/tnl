package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceVisitorTLSNegotiatesTheCapturedPostQuantumPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		required bool
		group    tls.CurveID
		version  uint16
		accepted bool
	}{
		{"default hybrid", false, tls.X25519MLKEM768, tls.VersionTLS13, true},
		{"default classical", false, tls.X25519, tls.VersionTLS13, true},
		{"default tls12", false, tls.X25519, tls.VersionTLS12, false},
		{"strict hybrid", true, tls.X25519MLKEM768, tls.VersionTLS13, true},
		{"strict classical", true, tls.X25519, tls.VersionTLS13, false},
		{"strict tls12", true, tls.X25519, tls.VersionTLS12, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
			if err != nil {
				t.Fatal(err)
			}
			approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
			approved.RequirePostQuantum = test.required
			preparation := control.prep
			preparation.RequirePostQuantum = test.required
			var requests atomic.Int32
			cfg.Target = ""
			cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			prepared, err := newManagedPrepared(preparation, approved, cfg)
			if err != nil {
				t.Fatal(err)
			}
			certificate, verification := managedTestCertificate(t, preparation.Hostname)
			if err := prepared.installManagedCertificate(certificate); err != nil {
				t.Fatal(err)
			}
			bound, err := prepared.Activate(control.setup)
			if err != nil {
				t.Fatal(err)
			}
			// certificate authorization isolates visitor TLS from browser policy.
			// the actual prepared run still owns TLS, HTTP dispatch, and cleanup.
			auth := servicestream.CertificateVisitor{Check: func(context.Context, *x509.Certificate) (servicestream.Decision, error) {
				return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			visitor, server := net.Pipe()
			handled, joined := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(joined)
				defer server.Close()
				handled <- bound.forwardManaged(ctx, server, auth, "", nil)
			}()
			t.Cleanup(func() {
				cancel()
				_ = visitor.Close()
				_ = server.Close()
				serviceHTTPAwait(t, joined)
			})
			verification.Certificates = []tls.Certificate{certificate}
			verification.MinVersion, verification.MaxVersion = test.version, test.version
			verification.CurvePreferences = []tls.CurveID{test.group}
			client := tls.Client(visitor, verification)
			err = client.HandshakeContext(ctx)
			if !test.accepted {
				if err == nil || requests.Load() != 0 {
					t.Fatal("rejected visitor reached HTTP", err, requests.Load())
				}
				_ = visitor.Close()
				if err := serviceHTTPAwait(t, handled); err == nil {
					t.Fatal("publisher accepted a visitor outside its captured TLS policy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			state := client.ConnectionState()
			if state.Version != tls.VersionTLS13 || state.CurveID != test.group {
				t.Fatal("visitor negotiated a different TLS version or group", state.Version, state.CurveID)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+preparation.Hostname+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Close = true
			if err := request.Write(client); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent || requests.Load() != 1 {
				t.Fatal("accepted visitor did not reach its HTTP handler exactly once", response.StatusCode, requests.Load())
			}
			_ = visitor.Close()
			if err := serviceHTTPAwait(t, handled); err != nil {
				t.Fatal("visitor cleanup failed", err)
			}
		})
	}
}
