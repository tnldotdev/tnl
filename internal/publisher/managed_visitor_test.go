package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

type nilVisitorFrontend struct{}

func (*nilVisitorFrontend) Forward(context.Context, *tls.Conn, ManagedHTTPTarget) error {
	panic("typed-nil frontend was called")
}

type visitorFrontendFunc func(context.Context, *tls.Conn, ManagedHTTPTarget) error

func (f visitorFrontendFunc) Forward(ctx context.Context, conn *tls.Conn, target ManagedHTTPTarget) error {
	return f(ctx, conn, target)
}

type undeclaredVisitor struct{}

func (undeclaredVisitor) valid() bool                    { panic("undeclared visitor was called") }
func (undeclaredVisitor) clientAuth() tls.ClientAuthType { panic("undeclared visitor was called") }
func (undeclaredVisitor) authorize(context.Context, tls.ConnectionState) (ManagedVisitorDecision, error) {
	panic("undeclared visitor was called")
}

func TestManagedVisitorNormalizationValuePointerAndTypedNil(t *testing.T) {
	public := PublicHTTPVisitor{Frontend: visitorFrontendFunc(func(context.Context, *tls.Conn, ManagedHTTPTarget) error { return nil })}
	connector := ConnectorVisitor{Check: func(context.Context) (ManagedVisitorDecision, error) { return ManagedVisitorDecision{}, nil }}
	certificate := CertificateVisitor{Check: func(context.Context, *x509.Certificate) (ManagedVisitorDecision, error) {
		return ManagedVisitorDecision{}, nil
	}}
	for _, test := range []struct {
		name           string
		value, pointer ManagedVisitorAuthentication
		auth           tls.ClientAuthType
	}{
		{"HTTP", public, &public, tls.RequestClientCert},
		{"connector", connector, &connector, tls.NoClientCert},
		{"certificate", certificate, &certificate, tls.RequireAnyClientCert},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, representation := range []ManagedVisitorAuthentication{test.value, test.pointer} {
				normalized, ok := normalizeManagedVisitor(representation)
				if !ok || reflect.TypeOf(normalized) != reflect.TypeOf(test.value) || normalized.clientAuth() != test.auth {
					t.Fatal("visitor representation changed authentication or dispatch")
				}
			}
		})
	}
	var nilFrontend *nilVisitorFrontend
	for _, invalid := range []ManagedVisitorAuthentication{nil, (*PublicHTTPVisitor)(nil), (*ConnectorVisitor)(nil), (*CertificateVisitor)(nil),
		PublicHTTPVisitor{}, &PublicHTTPVisitor{}, PublicHTTPVisitor{Frontend: nilFrontend}, &PublicHTTPVisitor{Frontend: nilFrontend}, PublicHTTPVisitor{Frontend: visitorFrontendFunc(nil)},
		ConnectorVisitor{}, &ConnectorVisitor{}, CertificateVisitor{}, &CertificateVisitor{}, undeclaredVisitor{}, (*undeclaredVisitor)(nil)} {
		if _, ok := normalizeManagedVisitor(invalid); ok {
			t.Fatal("invalid visitor was normalized")
		}
		stream := ManagedStream{Protocol: config.ProtocolHTTP, Hostname: "route.example", Target: "127.0.0.1:1", TLS: &tls.Config{}, Visitor: invalid}
		if err := stream.Forward(t.Context(), nil); !errors.Is(err, ErrManagedTLS) {
			t.Fatal("invalid visitor reached TLS or forwarding", err)
		}
	}
}
