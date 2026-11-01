package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

// ServiceVisitorAuthentication is selected from trusted admission metadata,
// before reading client TLS. application input cannot change its credential rule.
type ServiceVisitorAuthentication interface {
	valid() bool
	clientAuth() tls.ClientAuthType
	authorize(context.Context, tls.ConnectionState) (ServiceVisitorDecision, error)
}

// ServiceHTTPFrontend authorizes HTTP requests after verified visitor TLS. it
// owns request-level admission before opening a target connection.
type ServiceHTTPFrontend interface {
	Forward(context.Context, *tls.Conn, ServiceHTTPTarget) error
}

type ServiceHTTPTarget struct {
	Address   string
	Transport targettransport.Transport
	connector ServiceConnectorAdmission
	lifetime  context.Context
	track     func(net.Conn)
	enter     func() (func(), bool)
}

type PublicHTTPVisitor struct{ Frontend ServiceHTTPFrontend }

func (v PublicHTTPVisitor) valid() bool { return !nilManagedValue(v.Frontend) }

// TLS proves possession of an optional key. the HTTP authority verifies the
// exact leaf, issuer, scope and current permission after credential selection.
func (PublicHTTPVisitor) clientAuth() tls.ClientAuthType { return tls.RequestClientCert }
func (PublicHTTPVisitor) authorize(context.Context, tls.ConnectionState) (ServiceVisitorDecision, error) {
	return ServiceVisitorDecision{}, ErrEndpoint
}

// ServiceConnectorAdmission is consumed only by the connector forwarding path. the
// concrete service admission owns construction, physical-owner checks and C;
// this interface does not turn a permission guard or a callback into admission.
type ServiceConnectorAdmission interface {
	CheckUse(context.Context) (time.Time, error)
	SetupDeadline() time.Time
	FinishSetup() error
	Stop()
}

// ConnectorVisitor is supplied by a real, stream-owned service admission after
// signed possession verification. HTTP request guards do not implement admission.
type ConnectorVisitor struct{ Admission ServiceConnectorAdmission }

func (v ConnectorVisitor) valid() bool                  { return !nilManagedValue(v.Admission) }
func (ConnectorVisitor) clientAuth() tls.ClientAuthType { return tls.NoClientCert }
func (v ConnectorVisitor) authorize(ctx context.Context, _ tls.ConnectionState) (ServiceVisitorDecision, error) {
	until, err := v.Admission.CheckUse(ctx)
	return ServiceVisitorDecision{Allowed: err == nil, ValidUntil: until}, err
}

// CertificateVisitor requires key possession at the TLS boundary. control still
// checks the exact leaf's service scope, device and current permission.
type CertificateVisitor struct {
	Check func(context.Context, *x509.Certificate) (ServiceVisitorDecision, error)
}

func (v CertificateVisitor) valid() bool                  { return v.Check != nil }
func (CertificateVisitor) clientAuth() tls.ClientAuthType { return tls.RequireAnyClientCert }
func (v CertificateVisitor) authorize(ctx context.Context, state tls.ConnectionState) (ServiceVisitorDecision, error) {
	if len(state.PeerCertificates) == 0 {
		return ServiceVisitorDecision{}, ErrEndpoint
	}
	return v.Check(ctx, state.PeerCertificates[0])
}

// normalizeManagedVisitor closes the authentication variants before any method
// call. pointer and value declarations have identical dispatch and observations.
func normalizeManagedVisitor(visitor ServiceVisitorAuthentication) (ServiceVisitorAuthentication, bool) {
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
	_ ServiceVisitorAuthentication = PublicHTTPVisitor{}
	_ ServiceVisitorAuthentication = (*PublicHTTPVisitor)(nil)
	_ ServiceVisitorAuthentication = CertificateVisitor{}
	_ ServiceVisitorAuthentication = (*CertificateVisitor)(nil)
)
