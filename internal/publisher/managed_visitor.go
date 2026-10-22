package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"reflect"

	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

// ManagedVisitorAuthentication is selected from trusted admission metadata,
// before reading client TLS. application input cannot change its credential rule.
type ManagedVisitorAuthentication interface {
	valid() bool
	clientAuth() tls.ClientAuthType
	authorize(context.Context, tls.ConnectionState) (ManagedVisitorDecision, error)
}

// ManagedHTTPFrontend authorizes HTTP requests after mandatory verified native
// visitor TLS. it owns request-level admission before opening a target connection.
type ManagedHTTPFrontend interface {
	Forward(context.Context, *tls.Conn, ManagedHTTPTarget) error
}

type ManagedHTTPTarget struct {
	Address   string
	Transport targettransport.Transport
}

type PublicHTTPVisitor struct{ Frontend ManagedHTTPFrontend }

func (v PublicHTTPVisitor) valid() bool { return !nilManagedValue(v.Frontend) }

// TLS proves possession of an optional key. the HTTP authority verifies the
// exact leaf, issuer, scope and current permission after credential selection.
func (PublicHTTPVisitor) clientAuth() tls.ClientAuthType { return tls.RequestClientCert }
func (PublicHTTPVisitor) authorize(context.Context, tls.ConnectionState) (ManagedVisitorDecision, error) {
	return ManagedVisitorDecision{}, ErrManagedTLS
}

// ConnectorVisitor rechecks the identity already authenticated by the connector
// session. it never asks the application to supply another credential.
type ConnectorVisitor struct {
	Check func(context.Context) (ManagedVisitorDecision, error)
}

func (v ConnectorVisitor) valid() bool                  { return v.Check != nil }
func (ConnectorVisitor) clientAuth() tls.ClientAuthType { return tls.NoClientCert }
func (v ConnectorVisitor) authorize(ctx context.Context, _ tls.ConnectionState) (ManagedVisitorDecision, error) {
	return v.Check(ctx)
}

// CertificateVisitor requires key possession at the TLS boundary. control still
// checks the exact leaf's service scope, device and current permission.
type CertificateVisitor struct {
	Check func(context.Context, *x509.Certificate) (ManagedVisitorDecision, error)
}

func (v CertificateVisitor) valid() bool                  { return v.Check != nil }
func (CertificateVisitor) clientAuth() tls.ClientAuthType { return tls.RequireAnyClientCert }
func (v CertificateVisitor) authorize(ctx context.Context, state tls.ConnectionState) (ManagedVisitorDecision, error) {
	if len(state.PeerCertificates) == 0 {
		return ManagedVisitorDecision{}, ErrManagedTLS
	}
	return v.Check(ctx, state.PeerCertificates[0])
}

// normalizeManagedVisitor closes the authentication variants before any method
// call. pointer and value declarations have identical dispatch and observations.
func normalizeManagedVisitor(visitor ManagedVisitorAuthentication) (ManagedVisitorAuthentication, bool) {
	switch v := visitor.(type) {
	case PublicHTTPVisitor:
		return v, v.valid()
	case *PublicHTTPVisitor:
		if v != nil {
			return *v, v.valid()
		}
	case ConnectorVisitor:
		return v, v.valid()
	case *ConnectorVisitor:
		if v != nil {
			return *v, v.valid()
		}
	case CertificateVisitor:
		return v, v.valid()
	case *CertificateVisitor:
		if v != nil {
			return *v, v.valid()
		}
	}
	return nil, false
}

func nilManagedValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

var (
	_ ManagedVisitorAuthentication = PublicHTTPVisitor{}
	_ ManagedVisitorAuthentication = (*PublicHTTPVisitor)(nil)
	_ ManagedVisitorAuthentication = ConnectorVisitor{}
	_ ManagedVisitorAuthentication = (*ConnectorVisitor)(nil)
	_ ManagedVisitorAuthentication = CertificateVisitor{}
	_ ManagedVisitorAuthentication = (*CertificateVisitor)(nil)
)
