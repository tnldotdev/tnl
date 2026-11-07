package tlspolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestRequirePostQuantumClonesDynamicConfigurations(t *testing.T) {
	selected := &tls.Config{MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519}}
	base := selected.Clone()
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return selected, nil }
	strict := RequirePostQuantum(base)
	for _, original := range []*tls.Config{base, selected} {
		if original.MinVersion != tls.VersionTLS12 || !slices.Equal(original.CurvePreferences, []tls.CurveID{tls.X25519}) {
			t.Fatal("policy mutated caller configuration")
		}
	}
	dynamic, err := strict.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []*tls.Config{strict, dynamic} {
		if config.MinVersion != tls.VersionTLS13 || !slices.Equal(config.CurvePreferences, []tls.CurveID{tls.X25519MLKEM768}) {
			t.Fatal("dynamic configuration lost strict post-quantum policy")
		}
	}
	dynamic.CurvePreferences[0] = tls.X25519
	if strict.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatal("configurations share mutable curve preferences")
	}
}

func TestRequirePostQuantumTLSHandshake(t *testing.T) {
	// explicit requirements must not depend on process-wide default switches.
	t.Setenv("GODEBUG", "tlsmlkem=0,tlssecpmlkem=0")
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	for _, test := range []struct {
		name     string
		group    tls.CurveID
		version  uint16
		accepted bool
	}{
		{"hybrid", tls.X25519MLKEM768, tls.VersionTLS13, true},
		{"classical", tls.X25519, tls.VersionTLS13, false},
		{"tls12", tls.X25519, tls.VersionTLS12, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			base := &tls.Config{Certificates: []tls.Certificate{certificate}}
			// a certificate-selection callback must not relax the requirement.
			base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{Certificates: []tls.Certificate{certificate}}, nil
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", RequirePostQuantum(base))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				done <- conn.(*tls.Conn).HandshakeContext(ctx)
			}()
			conn, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
				RootCAs: roots, ServerName: "127.0.0.1", MinVersion: test.version, MaxVersion: test.version,
				CurvePreferences: []tls.CurveID{test.group},
			}}).DialContext(ctx, "tcp", listener.Addr().String())
			if conn != nil {
				defer conn.Close()
				state := conn.(*tls.Conn).ConnectionState()
				if state.CurveID != tls.X25519MLKEM768 {
					t.Errorf("negotiated %s", state.CurveID)
				}
			}
			serverErr := <-done
			if (err == nil) != test.accepted || (serverErr == nil) != test.accepted {
				t.Fatalf("accepted=%t, client=%v, server=%v", test.accepted, err, serverErr)
			}
		})
	}
}
