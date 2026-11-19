package local

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"

	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	api "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

// invocation material remains in the private local owner, never app snapshots.
// manager authentication precedes replacement; workers copy under this lock.
type invocationCertificate struct {
	mu         sync.Mutex
	chain, key []byte
}

func (*invocationCertificate) String() string   { return "private invocation certificate source" }
func (*invocationCertificate) GoString() string { return "private invocation certificate source" }

func (s *invocationCertificate) replace(chain, key string) error {
	if len(chain) == 0 || len(chain) > 128<<10 || len(key) == 0 || len(key) > 16<<10 {
		return publisherprotocol.ErrCertificateInvalid
	}
	if _, err := tls.X509KeyPair([]byte(chain), []byte(key)); err != nil {
		return publisherprotocol.ErrCertificateInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.chain, s.key = []byte(chain), []byte(key)
	return nil
}

func (s *invocationCertificate) current(ctx context.Context) (publisherservice.CertificateMaterial, error) {
	if err := context.Cause(ctx); err != nil {
		return publisherservice.CertificateMaterial{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return publisherservice.CertificateMaterial{CertificatePEM: append([]byte(nil), s.chain...), PrivateKeyPEM: append([]byte(nil), s.key...)}, nil
}

func (a *appRuntime) renewInvocationCertificate(request publisherprotocol.Registration) error {
	a.mu.Lock()
	supplied := a.prepared[request.RegistrationID].certificate
	a.mu.Unlock()
	if supplied == nil || request.Certificate == nil {
		return publisherprotocol.ErrForbidden
	}
	return supplied.replace(request.Certificate.CertificatePem, request.Certificate.PrivateKeyPem)
}

func (a *appRuntime) exportInvocationCertificate(ctx context.Context, id string) (publisherprotocol.InstalledServiceCertificate, error) {
	a.mu.Lock()
	exporter := a.prepared[id].certificateExport
	a.mu.Unlock()
	if exporter == nil {
		return publisherprotocol.InstalledServiceCertificate{}, publisherprotocol.ErrCertificateUnavailable
	}
	snapshot, err := exporter.Snapshot(ctx)
	if err != nil {
		if errors.Is(err, publisherservice.ErrCertificateUnavailable) {
			err = publisherprotocol.ErrCertificateUnavailable
		}
		return publisherprotocol.InstalledServiceCertificate{}, err
	}
	defer clear(snapshot.PrivateKeyPEM)
	return publisherprotocol.InstalledServiceCertificate{
		Certificate: api.SuppliedServiceCertificateMaterial{
			CertificatePem: string(snapshot.CertificatePEM),
			PrivateKeyPem:  string(snapshot.PrivateKeyPEM),
		},
		ExpiresAt: snapshot.ExpiresAt.UnixMilli(),
	}, nil
}
