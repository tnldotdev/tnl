package publisher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func (r *PublicURLServer) InstallCertificate(certificate tls.Certificate) error {
	copy := certificate
	if len(copy.Certificate) == 0 || copy.PrivateKey == nil {
		return errors.New("publisher: application certificate and private key are required")
	}
	var err error
	if len(r.certificatePlan.Identifiers) != 0 {
		copy.Leaf, err = certificateidentity.ValidateCertificate(copy, r.hostname, r.certificatePlan.Identifiers)
	} else {
		copy.Leaf, err = x509.ParseCertificate(copy.Certificate[0])
		if err == nil {
			err = copy.Leaf.VerifyHostname(r.hostname)
		}
	}
	if err != nil {
		return fmt.Errorf("publisher: invalid application certificate: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	select {
	case <-r.certificateExpired:
		return errCertificateExpired
	default:
	}
	if r.certificateTimer != nil {
		r.certificateTimer.Stop()
	}
	installed := &copy
	r.certificate.Store(installed)
	r.certificateTimer = time.AfterFunc(max(time.Until(copy.Leaf.NotAfter), 0), func() {
		r.mu.Lock()
		r.expireCertificateLocked(installed)
		r.mu.Unlock()
	})
	return nil
}

func (r *PublicURLServer) certificateExpiration() <-chan struct{} { return r.certificateExpired }

func (r *PublicURLServer) withValidCertificate(call func() error) error {
	r.mu.Lock()
	certificate := r.certificate.Load()
	if certificate == nil {
		r.mu.Unlock()
		return errors.New("publisher: application certificate is not installed")
	}
	select {
	case <-r.certificateExpired:
		r.mu.Unlock()
		return errCertificateExpired
	default:
	}
	if !certificate.Leaf.NotAfter.After(time.Now()) {
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
		}
		r.expireCertificateLocked(certificate)
		r.mu.Unlock()
		return errCertificateExpired
	}
	r.mu.Unlock()
	return call()
}

func (r *PublicURLServer) expireCertificateLocked(certificate *tls.Certificate) {
	if r.closed || r.certificate.Load() != certificate {
		return
	}
	select {
	case <-r.certificateExpired:
		return
	default:
		r.certificateTimer = nil
		close(r.certificateExpired)
	}
}

func (r *PublicURLServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("publisher: TLS SNI does not match public URL")
	}
	if hello.ServerName == "" {
		return nil, errors.New("publisher: TLS SNI does not match public URL")
	} else {
		hostname, err := naming.CanonicalizeHostname(hello.ServerName)
		if err != nil || hostname != r.hostname {
			return nil, errors.New("publisher: TLS SNI does not match public URL")
		}
	}
	certificate := r.certificate.Load()
	if certificate == nil {
		return nil, errors.New("publisher: application certificate is not installed")
	}
	if !certificate.Leaf.NotAfter.After(time.Now()) {
		return nil, errCertificateExpired
	}
	return certificate, nil
}
