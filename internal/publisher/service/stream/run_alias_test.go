package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

func TestConnectorHTTPDoesNotAcquirePublicRunAliasSNI(t *testing.T) {
	const alias = "r-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test"
	certificate := visitorfixture.Certificate(t, "*.example.test")
	var requests atomic.Int32
	admission := new(connectorAdapterAdmission)
	stream := Stream{Protocol: config.ProtocolHTTP, Public: true,
		Hostname: "web.example.test", RunHostname: alias,
		TLS:     &tls.Config{Certificates: []tls.Certificate{certificate}},
		Visitor: ConnectorVisitor{Admission: admission},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	visitor, server := net.Pipe()
	defer visitor.Close()
	done := make(chan error, 1)
	go func() { done <- stream.Forward(ctx, server) }()
	client := tls.Client(visitor, &tls.Config{RootCAs: visitorfixture.Roots(t, certificate), ServerName: alias})
	defer client.Close()
	handshake := client.HandshakeContext(ctx)
	select {
	case err := <-done:
		var refusal *VisitorHostnameRefusal
		var verification *tls.CertificateVerificationError
		if handshake == nil || errors.As(handshake, &verification) || !errors.As(err, &refusal) {
			t.Fatal("connector alias was not rejected at the SNI boundary", handshake, err)
		}
	case <-ctx.Done():
		t.Fatal("connector alias rejection did not join", context.Cause(ctx))
	}
	if requests.Load() != 0 {
		t.Fatal("connector alias reached the HTTP application")
	}
	if _, err := admission.CheckUse(ctx); !errors.Is(err, ErrEndpoint) {
		t.Fatal("rejected connector alias retained its admission", err)
	}
}
