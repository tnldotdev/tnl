package localproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

func TestTargetTLSServerNameMatchesPreflightAndForwarding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"target.internal"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var forwarded atomic.Int32
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.TLS.ServerName != "target.internal" || r.Host != "route.example" {
			t.Error("target TLS name changed visitor authority")
		}
		if r.Header.Get("traceparent") != "" || r.Header.Get("tracestate") != "" || r.Header.Get("baggage") != "" {
			t.Error("tnl injected tracing headers into the customer target")
		}
		w.WriteHeader(204)
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	backend.StartTLS()
	defer backend.Close()
	for _, test := range []struct {
		name    string
		options TargetOptions
		valid   bool
	}{
		{"explicit DNS name with IP dial", TargetOptions{RootCAs: roots, ServerName: "target.internal"}, true},
		{"IP does not match DNS certificate", TargetOptions{RootCAs: roots}, false},
		{"wrong DNS name", TargetOptions{RootCAs: roots, ServerName: "other.internal"}, false},
		{"untrusted certificate", TargetOptions{ServerName: "target.internal"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			metrics := observability.New("publisher")
			ctx := observability.WithMetrics(t.Context(), metrics)
			ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled}))
			err := PreflightWithOptions(t.Context(), backend.URL, test.options)
			if (err == nil) != test.valid {
				t.Fatalf("preflight success=%t, want %t", err == nil, test.valid)
			}
			handler, err := NewWithMountsHooksOptions(backend.URL, "route.example", 1, nil, ResponseHooks{}, test.options)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequestWithContext(ctx, "GET", "/", nil)
			r.Host = "route.example"
			r.TLS = &tls.ConnectionState{ServerName: "route.example"}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want := http.StatusBadGateway
			if test.valid {
				want = 204
			}
			if w.Code != want {
				t.Fatalf("forwarding status=%d", w.Code)
			}
			observed := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(observed, httptest.NewRequest("GET", "/metrics", nil))
			outcome := "error"
			if test.valid {
				outcome = "success"
			}
			if !strings.Contains(observed.Body.String(), `tnl_publisher_operation_duration_seconds_count{operation="target_tls",outcome="`+outcome+`"} 1`) {
				t.Fatal("missing target TLS result")
			}
		})
	}
	if forwarded.Load() != 1 {
		t.Fatalf("invalid TLS fell back to an application request: %d", forwarded.Load())
	}
	if err := PreflightWithOptions(t.Context(), "http://127.0.0.1:1", TargetOptions{ServerName: "target.internal"}); err == nil {
		t.Fatal("plaintext target accepted TLS identity options")
	}
}
