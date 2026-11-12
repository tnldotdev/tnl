package stream

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

func (*nilVisitorFrontend) Forward(context.Context, *tls.Conn, HTTPTarget) error {
	panic("typed-nil frontend was called")
}

type visitorFrontendFunc func(context.Context, *tls.Conn, HTTPTarget) error

func (f visitorFrontendFunc) Forward(ctx context.Context, conn *tls.Conn, target HTTPTarget) error {
	return f(ctx, conn, target)
}

type undeclaredVisitor struct{}

func (undeclaredVisitor) valid() bool                    { panic("undeclared visitor was called") }
func (undeclaredVisitor) clientAuth() tls.ClientAuthType { panic("undeclared visitor was called") }
func (undeclaredVisitor) authorize(context.Context, tls.ConnectionState) (Decision, error) {
	panic("undeclared visitor was called")
}

func TestManagedVisitorNormalizationValuePointerAndTypedNil(t *testing.T) {
	public := HTTPVisitor{Frontend: visitorFrontendFunc(func(context.Context, *tls.Conn, HTTPTarget) error { return nil })}
	native := ConnectorVisitor{Admission: new(connectorAdapterAdmission)}
	certificate := CertificateVisitor{Check: func(context.Context, *x509.Certificate) (Decision, error) {
		return Decision{}, nil
	}}
	for _, test := range []struct {
		name           string
		value, pointer Authentication
		auth           tls.ClientAuthType
	}{
		{"HTTP", public, &public, tls.RequestClientCert},
		{"native", native, &native, tls.NoClientCert},
		{"certificate", certificate, &certificate, tls.RequireAnyClientCert},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, representation := range []Authentication{test.value, test.pointer} {
				normalized, ok := normalizeManagedVisitor(representation)
				if !ok || reflect.TypeOf(normalized) != reflect.TypeOf(test.value) || normalized.clientAuth() != test.auth {
					t.Fatal("visitor representation changed authentication or dispatch")
				}
			}
		})
	}
	var nilFrontend *nilVisitorFrontend
	for _, invalid := range []Authentication{nil, (*HTTPVisitor)(nil), (*ConnectorVisitor)(nil), (*CertificateVisitor)(nil),
		HTTPVisitor{}, &HTTPVisitor{}, HTTPVisitor{Frontend: nilFrontend}, &HTTPVisitor{Frontend: nilFrontend}, HTTPVisitor{Frontend: visitorFrontendFunc(nil)},
		ConnectorVisitor{}, &ConnectorVisitor{}, ConnectorVisitor{Admission: (*connectorAdapterAdmission)(nil)}, CertificateVisitor{}, &CertificateVisitor{}, undeclaredVisitor{}, (*undeclaredVisitor)(nil)} {
		if _, ok := normalizeManagedVisitor(invalid); ok {
			t.Fatal("invalid visitor was normalized")
		}
		stream := Stream{Protocol: config.ProtocolHTTP, Hostname: "route.example", Target: "127.0.0.1:1", TLS: &tls.Config{}, Visitor: invalid}
		if err := stream.Forward(t.Context(), nil); !errors.Is(err, ErrEndpoint) {
			t.Fatal("invalid visitor reached TLS or forwarding", err)
		}
	}
}
