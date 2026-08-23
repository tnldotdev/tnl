package controltls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const certificateIssuanceTimeout = 5 * time.Minute

// runIssuer owns all issuance, renewal, and challenge cleanup for one tenure.
// The ACME client performs context-aware requests and polling synchronously;
// there are no renewal or cleanup goroutines that can outlive leadership.
func (s *Source) runIssuer(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		delay := certificateRefreshInterval
		for _, hostname := range s.hostnames {
			if ctx.Err() != nil {
				return nil
			}
			certificate, err := s.ensureCertificate(ctx, hostname)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				if s.report != nil {
					s.report(fmt.Errorf("controltls: certificate for %s: %w", hostname, err))
				}
				delay = min(delay, time.Minute)
				continue
			}
			delay = min(delay, max(time.Until(certificateRenewAt(certificate.Leaf)), time.Second))
		}
		timer.Reset(delay)
	}
}

func certificateRenewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotAfter.Add(-min(leaf.NotAfter.Sub(leaf.NotBefore)/3, 30*24*time.Hour))
}

func (s *Source) ensureCertificate(ctx context.Context, hostname string) (*tls.Certificate, error) {
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	certificate, err := s.readCertificate(readCtx, hostname)
	cancel()
	if err == nil && time.Now().Before(certificateRenewAt(certificate.Leaf)) {
		return certificate, nil
	}
	if err != nil && !errors.Is(err, autocert.ErrCacheMiss) && !errors.Is(err, errInvalidCertificate) {
		return nil, err
	}
	issuanceCtx, cancel := context.WithTimeout(ctx, certificateIssuanceTimeout)
	defer cancel()
	return s.issueCertificate(issuanceCtx, hostname)
}

func (s *Source) issueCertificate(ctx context.Context, hostname string) (*tls.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.client.KID == "" {
		_, err := s.client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + s.email}}, func(string) bool { return s.acceptTerms })
		if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, err
		}
	}
	order, err := s.client.AuthorizeOrder(ctx, acme.DomainIDs(hostname))
	if err != nil {
		return nil, err
	}
	if len(order.Identifiers) != 1 || order.Identifiers[0].Type != "dns" || order.Identifiers[0].Value != hostname ||
		order.URI == "" || order.FinalizeURL == "" || (order.Status != acme.StatusPending && order.Status != acme.StatusReady) {
		return nil, errors.New("controltls: invalid certificate order")
	}
	for _, url := range order.AuthzURLs {
		authorization, err := s.client.GetAuthorization(ctx, url)
		if err != nil {
			return nil, err
		}
		if authorization.Identifier.Type != "dns" || authorization.Identifier.Value != hostname || authorization.Wildcard {
			return nil, errors.New("controltls: authorization does not match the requested hostname")
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		if authorization.Status != acme.StatusPending {
			return nil, fmt.Errorf("controltls: authorization status is %q", authorization.Status)
		}
		if err := s.authorize(ctx, hostname, url, authorization); err != nil {
			return nil, err
		}
	}
	order, err = s.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, err
	}
	if order.Status != acme.StatusReady || order.FinalizeURL == "" {
		return nil, errors.New("controltls: certificate order is not ready to finalize")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := s.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, err
	}
	data, err := certificatePEM(&tls.Certificate{Certificate: chain, PrivateKey: key})
	if err != nil {
		return nil, err
	}
	certificate, err := decodeCertificate(data, hostname)
	if err != nil {
		return nil, errors.New("controltls: issued certificate is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.cache.Put(ctx, hostname, data); err != nil {
		return nil, fmt.Errorf("controltls: cache issued certificate: %w", err)
	}
	return certificate, nil
}

func (s *Source) authorize(ctx context.Context, hostname, url string, authorization *acme.Authorization) (retErr error) {
	var challenge *acme.Challenge
	for _, candidate := range authorization.Challenges {
		if candidate.Type == "tls-alpn-01" {
			challenge = candidate
			break
		}
	}
	if challenge == nil {
		return errors.New("controltls: authorization has no TLS-ALPN challenge")
	}
	certificate, err := s.client.TLSALPN01ChallengeCert(challenge.Token, hostname)
	if err != nil {
		return err
	}
	data, err := certificatePEM(&certificate)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := hostname + "+token"
	if err := s.cache.Put(ctx, key, data); err != nil {
		return fmt.Errorf("controltls: cache challenge certificate: %w", err)
	}
	defer func() {
		// Never use a detached cleanup context: after leadership loss the
		// replacement leader may already have installed its own challenge.
		if ctx.Err() == nil {
			retErr = errors.Join(retErr, s.cache.Delete(ctx, key))
		}
	}()
	if _, err := s.client.Accept(ctx, challenge); err != nil {
		return err
	}
	_, err = s.client.WaitAuthorization(ctx, url)
	return err
}

// Keep the autocert PEM cache format so existing certificates and cross-process
// TLS-ALPN challenge responses remain readable during an upgrade.
func certificatePEM(certificate *tls.Certificate) ([]byte, error) {
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	for _, der := range certificate.Certificate {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return data, nil
}
