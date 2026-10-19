package tnldruntime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type ingressCertificateClient interface {
	GetIngressTransportCertificate(context.Context, string, ingressv1.GetIngressTransportCertificateJSONRequestBody) (ingressv1.IngressTransportCertificate, error)
}

type ingressCertificateSource struct {
	id, hostname string
	mu           sync.RWMutex
	certificate  *tls.Certificate
}

func (s *ingressCertificateSource) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.certificate == nil || s.certificate.Leaf == nil || !s.certificate.Leaf.NotAfter.After(time.Now()) {
			return nil, errors.New("ingress transport certificate is not ready")
		}
		return s.certificate, nil
	}}
}

func (s *ingressCertificateSource) install(value ingressv1.IngressTransportCertificate) error {
	trust := value.Trust
	if trust.IngressId != s.id || trust.TlsServerName != s.hostname {
		return errors.New("ingress transport certificate identity changed")
	}
	certificate, err := tls.X509KeyPair([]byte(trust.CertificatePem), []byte(value.PrivateKeyPem))
	if err != nil || len(certificate.Certificate) == 0 {
		return errors.New("ingress transport certificate key pair is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(s.hostname) != nil || !leaf.NotAfter.Equal(trust.NotAfter) || leaf.NotBefore.After(time.Now()) || !leaf.NotAfter.After(time.Now()) {
		return errors.New("ingress transport certificate is invalid")
	}
	identity := url.URL{Scheme: "tnl", Host: "ingress", Path: "/" + trust.IngressId + "/" + trust.IngressRunId + "/" + strconv.FormatInt(trust.IngressLeaseRevision, 10)}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if trust.IngressRunId == "" || trust.IngressLeaseRevision < 1 || trust.LeaseUri != identity.String() || len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity.String() ||
		hex.EncodeToString(pin[:]) != trust.PublicKeySha256 || !trust.ValidUntil.After(time.Now()) || trust.ValidUntil.After(leaf.NotAfter) {
		return errors.New("ingress transport certificate does not bind its process lease")
	}
	roots := x509.NewCertPool()
	if len(trust.IssuerPem) > 128<<10 || !roots.AppendCertsFromPEM([]byte(trust.IssuerPem)) {
		return errors.New("ingress transport issuer is invalid")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: s.hostname, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("ingress transport certificate does not verify against its issuer")
	}
	certificate.Leaf = leaf
	s.mu.Lock()
	s.certificate = &certificate
	s.mu.Unlock()
	return nil
}

func (s *ingressCertificateSource) ready(now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certificate != nil && s.certificate.Leaf != nil && s.certificate.Leaf.NotAfter.After(now)
}

func runIngressCertificate(ctx context.Context, client ingressCertificateClient, controller *ingress.Controller, source *ingressCertificateSource, retry time.Duration) error {
	if retry <= 0 {
		retry = time.Second
	}
	var refresh time.Time
	for ctx.Err() == nil {
		lease := controller.Lease()
		now := time.Now()
		if lease.IngressLeaseRevision > 0 && lease.LeaseExpiresAt.After(now) && !lease.Draining && (refresh.IsZero() || !now.Before(refresh)) {
			request, cancel := context.WithDeadline(ctx, minTime(lease.LeaseExpiresAt, now.Add(10*time.Second)))
			certificate, err := client.GetIngressTransportCertificate(request, lease.IngressId, ingressv1.GetIngressTransportCertificateJSONRequestBody{
				IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision})
			cancel()
			if err == nil {
				current := controller.Lease()
				if current.IngressRunId != lease.IngressRunId || current.IngressLeaseRevision != lease.IngressLeaseRevision || !current.LeaseExpiresAt.After(time.Now()) {
					continue
				}
				if certificate.Trust.IngressRunId != lease.IngressRunId || certificate.Trust.IngressLeaseRevision != lease.IngressLeaseRevision {
					return errors.New("ingress certificate lease identity changed")
				}
				if err := source.install(certificate); err != nil {
					return err
				}
				refresh = time.Now().Add(min(12*time.Hour, time.Until(certificate.Trust.NotAfter)/2))
			}
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

// the generated ingress client remains the wire owner; this runtime adapter
// adds certificate retrieval without widening public visitor authorization.
type ingressRuntimeClient struct {
	*ingress.HTTPControlClient
	generated ingressv1.ClientWithResponsesInterface
}

func (c *ingressRuntimeClient) GetIngressTransportCertificate(ctx context.Context, id string, params ingressv1.GetIngressTransportCertificateJSONRequestBody) (ingressv1.IngressTransportCertificate, error) {
	response, err := c.generated.GetIngressTransportCertificateWithResponse(ctx, id, params)
	if err != nil {
		return ingressv1.IngressTransportCertificate{}, err
	}
	if response == nil || response.JSON200 == nil {
		return ingressv1.IngressTransportCertificate{}, errors.New("ingress transport certificate is unavailable")
	}
	return *response.JSON200, nil
}
