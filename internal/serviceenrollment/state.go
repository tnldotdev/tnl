package serviceenrollment

import (
	"context"
	"crypto/tls"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/servicepki"
)

// Source obtains or renews one process-local service enrollment.
type Source interface {
	Enroll(context.Context) (Enrollment, error)
}

// State owns one process enrollment and atomically rotates its short-lived
// certificates while preserving the stable facts returned at startup.
type State struct {
	enroller Source
	now      func() time.Time

	mu      sync.RWMutex
	current *Enrollment
}

func NewState(ctx context.Context, enroller Source) (*State, error) {
	if enroller == nil {
		return nil, errors.New("serviceenrollment: enroller is required")
	}
	enrollment, err := enroller.Enroll(ctx)
	if err != nil {
		return nil, err
	}
	return &State{enroller: enroller, now: time.Now, current: &enrollment}, nil
}

// Run renews the process enrollment until ctx is canceled. Failed requests are
// retried, while a response that changes stable process facts is terminal.
func (s *State) Run(ctx context.Context, retryInterval time.Duration, report func(error)) error {
	if retryInterval <= 0 {
		return errors.New("serviceenrollment: retry interval must be positive")
	}
	if report == nil {
		report = func(error) {}
	}
	for {
		current := s.enrollment()
		if current == nil {
			return errors.New("serviceenrollment: enrollment state is empty")
		}
		if err := waitUntil(ctx, current.RenewAt, s.now()); err != nil {
			return nil
		}
		for {
			renewed, err := s.enroller.Enroll(ctx)
			if err == nil {
				err = s.replace(renewed)
				if err == nil {
					break
				}
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
			report(err)
			if err := waitFor(ctx, retryInterval); err != nil {
				return nil
			}
		}
	}
}

func (s *State) Ready(now time.Time) bool {
	current := s.enrollment()
	if current == nil || !current.CertificateExpiresAt.After(now) {
		return false
	}
	return current.Role != servicepki.RoleRelay || current.RelayTransportCertificate != nil &&
		current.RelayTransportCertificate.Leaf != nil && current.RelayTransportCertificate.Leaf.NotAfter.After(now)
}

// Enrollment returns the current immutable enrollment snapshot.
func (s *State) Enrollment() Enrollment {
	current := s.enrollment()
	if current == nil {
		return Enrollment{}
	}
	return *current
}

// InternalControlTLSConfig authenticates this process to its role-specific
// private control API using the current service certificate.
func (s *State) InternalControlTLSConfig() (*tls.Config, error) {
	current := s.enrollment()
	if current == nil {
		return nil, errors.New("serviceenrollment: enrollment state is empty")
	}
	endpoint, err := url.Parse(current.InternalControlEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return nil, errors.New("serviceenrollment: internal control endpoint is invalid")
	}
	role := current.Role
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: endpoint.Hostname(), RootCAs: current.TrustBundle,
		GetClientCertificate: s.getServiceClientCertificate,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("serviceenrollment: internal control server certificate is missing")
			}
			certificateRole, err := servicepki.InternalControlCertificateRole(state.PeerCertificates[0])
			if err != nil || certificateRole != role {
				return errors.New("serviceenrollment: internal control server certificate has the wrong role")
			}
			return nil
		},
	}, nil
}

// ForwardingClientTLSConfig authenticates an ingress process to relay
// internal-forwarding listeners. The forwarder adds exact relay verification.
func (s *State) ForwardingClientTLSConfig() (*tls.Config, error) {
	current := s.enrollment()
	if current == nil || current.Role != servicepki.RoleIngress {
		return nil, errors.New("serviceenrollment: ingress enrollment is required")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: current.TrustBundle,
		GetClientCertificate: s.getServiceClientCertificate,
	}, nil
}

// ForwardingServerTLSConfig authenticates ingress processes and presents this
// relay process's exact service identity.
func (s *State) ForwardingServerTLSConfig() (*tls.Config, error) {
	current := s.enrollment()
	if current == nil || current.Role != servicepki.RoleRelay {
		return nil, errors.New("serviceenrollment: relay enrollment is required")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: current.TrustBundle, GetCertificate: s.getServiceCertificate,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("serviceenrollment: ingress service certificate is missing")
			}
			identity, err := servicepki.CertificateIdentity(state.PeerCertificates[0])
			if err != nil || identity.Role != servicepki.RoleIngress {
				return errors.New("serviceenrollment: internal forwarding requires an ingress identity")
			}
			return nil
		},
	}, nil
}

// RelayTransportTLSConfig presents the current shared relay-service transport
// certificate to publishers.
func (s *State) RelayTransportTLSConfig() (*tls.Config, error) {
	current := s.enrollment()
	if current == nil || current.Role != servicepki.RoleRelay || current.RelayTransportCertificate == nil {
		return nil, errors.New("serviceenrollment: relay transport enrollment is required")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, GetCertificate: s.getRelayTransportCertificate,
	}, nil
}

func (s *State) replace(renewed Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current
	if current == nil || renewed.Role != current.Role || renewed.ProcessID != current.ProcessID ||
		renewed.RelayServiceID != current.RelayServiceID || renewed.RelayAddress != current.RelayAddress ||
		renewed.TLSServerName != current.TLSServerName || renewed.InternalControlEndpoint != current.InternalControlEndpoint ||
		renewed.TrustBundlePEM != current.TrustBundlePEM {
		return errors.New("serviceenrollment: renewal changed stable process facts")
	}
	s.current = &renewed
	return nil
}

func (s *State) enrollment() *Enrollment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *State) getServiceClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return s.serviceCertificate()
}

func (s *State) getServiceCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.serviceCertificate()
}

func (s *State) serviceCertificate() (*tls.Certificate, error) {
	current := s.enrollment()
	if current == nil || !current.CertificateExpiresAt.After(s.now()) {
		return nil, errors.New("serviceenrollment: service certificate is expired")
	}
	return &current.ServiceCertificate, nil
}

func (s *State) getRelayTransportCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	current := s.enrollment()
	if current == nil || current.RelayTransportCertificate == nil || current.RelayTransportCertificate.Leaf == nil ||
		!current.RelayTransportCertificate.Leaf.NotAfter.After(s.now()) {
		return nil, errors.New("serviceenrollment: relay transport certificate is expired")
	}
	return current.RelayTransportCertificate, nil
}

func waitUntil(ctx context.Context, deadline, now time.Time) error {
	delay := deadline.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return waitFor(ctx, delay)
}

func waitFor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}
