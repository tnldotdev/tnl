package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

// Authentication is selected from trusted admission metadata,
// before reading client TLS. application input cannot change its credential rule.
type Authentication interface {
	valid() bool
	clientAuth() tls.ClientAuthType
	authorize(context.Context, tls.ConnectionState) (Decision, error)
}

// HTTPFrontend authorizes HTTP requests after verified visitor TLS. it
// owns request-level admission before opening a target connection.
type HTTPFrontend interface {
	Forward(context.Context, *tls.Conn, HTTPTarget) error
}

type HTTPTarget struct {
	Address   string
	Handler   http.Handler
	Transport targettransport.Transport
	connector ConnectorAdmission
	lifetime  context.Context
	track     func(net.Conn)
	enter     func() (func(), bool)
}

type HTTPVisitor struct{ Frontend HTTPFrontend }

func (v HTTPVisitor) valid() bool { return !nilManagedValue(v.Frontend) }

// TLS proves possession of an optional key. the HTTP authority verifies the
// exact leaf, issuer, scope and current permission after credential selection.
func (HTTPVisitor) clientAuth() tls.ClientAuthType { return tls.RequestClientCert }
func (HTTPVisitor) authorize(context.Context, tls.ConnectionState) (Decision, error) {
	return Decision{}, ErrEndpoint
}

// ConnectorAdmission is consumed only by the connector forwarding path. the
// concrete service admission owns construction, physical-owner checks and C;
// this interface does not turn a permission guard or a callback into admission.
type ConnectorAdmission interface {
	CheckUse(context.Context) (time.Time, error)
	SetupDeadline() time.Time
	FinishSetup() error
	Stop()
}

// ConnectorVisitor is supplied by a real, stream-owned service admission after
// signed possession verification. HTTP request guards do not implement admission.
type ConnectorVisitor struct{ Admission ConnectorAdmission }

func (v ConnectorVisitor) valid() bool                  { return !nilManagedValue(v.Admission) }
func (ConnectorVisitor) clientAuth() tls.ClientAuthType { return tls.NoClientCert }
func (v ConnectorVisitor) authorize(ctx context.Context, _ tls.ConnectionState) (Decision, error) {
	until, err := v.Admission.CheckUse(ctx)
	return Decision{Allowed: err == nil, ValidUntil: until}, err
}

// CertificateVisitor requires key possession at the TLS boundary. control still
// checks the exact leaf's service scope, device and current permission.
type CertificateVisitor struct {
	Check func(context.Context, *x509.Certificate) (Decision, error)
}

func (v CertificateVisitor) valid() bool                  { return v.Check != nil }
func (CertificateVisitor) clientAuth() tls.ClientAuthType { return tls.RequireAnyClientCert }
func (v CertificateVisitor) authorize(ctx context.Context, state tls.ConnectionState) (Decision, error) {
	if len(state.PeerCertificates) == 0 {
		return Decision{}, ErrEndpoint
	}
	return v.Check(ctx, state.PeerCertificates[0])
}

// normalizeManagedVisitor closes the authentication variants before any method
// call. pointer and value declarations have identical dispatch and observations.
func normalizeManagedVisitor(visitor Authentication) (Authentication, bool) {
	switch v := visitor.(type) {
	case HTTPVisitor:
		return v, v.valid()
	case *HTTPVisitor:
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
	_ Authentication = HTTPVisitor{}
	_ Authentication = (*HTTPVisitor)(nil)
	_ Authentication = CertificateVisitor{}
	_ Authentication = (*CertificateVisitor)(nil)
)
