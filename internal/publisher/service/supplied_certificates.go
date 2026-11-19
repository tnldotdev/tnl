package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/state/certificatestore"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type CertificateMaterial struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

func (CertificateMaterial) String() string   { return "private supplied certificate material" }
func (CertificateMaterial) GoString() string { return "private supplied certificate material" }

type suppliedCertificateWorker struct {
	control   CertificateControl
	cache     *certificatestore.CertificateCache
	source    func(context.Context) (CertificateMaterial, error)
	prepared  *Prepared
	setup     controlv1.ServiceRunSetup
	installed chan<- struct{}
}

type suppliedCertificateSourceError struct{ cause error }

var errSuppliedCandidate = errors.New("supplied service certificate candidate was rejected")

func (suppliedCertificateSourceError) Error() string {
	return "supplied service certificate source failed"
}
func (e suppliedCertificateSourceError) Unwrap() error { return e.cause }

func (r suppliedCertificateWorker) maintain(ctx context.Context) error {
	var fingerprint string
	var expires time.Time
	for {
		attempt := ctx
		stop := func() {}
		if !expires.IsZero() {
			attempt, stop = context.WithDeadlineCause(ctx, expires, errCertificateExpired)
		}
		receipt, err := r.advance(attempt, fingerprint)
		stopped := context.Cause(attempt)
		stop()
		if stopped != nil {
			return errors.Join(stopped, serviceWorkerError(err, attempt.Err()))
		}
		if err != nil {
			var sourceErr suppliedCertificateSourceError
			rejectedReplacement := fingerprint != "" && (errors.Is(err, errSuppliedCandidate) || errors.As(err, &sourceErr))
			if !rejectedReplacement && !managedCertificateRetryable(err) {
				return err
			}
		} else {
			fingerprint, expires = receipt.CertificateSha256, receipt.ExpiresAt
			select {
			case r.installed <- struct{}{}:
			default:
			}
		}
		delay := 30 * time.Second
		if fingerprint == "" {
			delay = time.Second
		}
		if !expires.IsZero() {
			if !expires.After(time.Now()) {
				return errCertificateExpired
			}
			delay = min(delay, time.Until(expires))
		}
		if err := waitCertificateRetry(ctx, delay); err != nil {
			return err
		}
	}
}

func (r suppliedCertificateWorker) advance(ctx context.Context, previous string) (result controlv1.SuppliedServiceCertificateInstallation, resultErr error) {
	material, err := r.source(ctx)
	defer clear(material.PrivateKeyPEM)
	defer clear(material.CertificatePEM)
	if err != nil {
		return result, suppliedCertificateSourceError{cause: err}
	}
	names := []string{r.prepared.managedHostname}
	if r.prepared.runHostname != "" {
		names = append(names, r.prepared.runHostname)
	}
	certificate, err := certificateidentity.LoadSupplied(material.CertificatePEM, material.PrivateKeyPEM, names, time.Now())
	if err != nil {
		return result, errors.Join(errSuppliedCandidate, err)
	}
	digest := sha256.Sum256(certificate.Certificate[0])
	if previous != "" && previous == hex.EncodeToString(digest[:]) {
		r.prepared.certMu.Lock()
		until := r.prepared.certValidTo
		r.prepared.certMu.Unlock()
		if !until.After(time.Now()) {
			return result, errCertificateExpired
		}
		return controlv1.SuppliedServiceCertificateInstallation{CertificateSha256: previous, ExpiresAt: until}, nil
	}
	lock, err := r.cache.Lock(ctx)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	staged, err := r.cache.StageSupplied(ctx, r.prepared.managedHostname, material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		return result, err
	}
	receipt, err := r.control.MarkSuppliedServiceCertificateInstalled(ctx, r.setup.ServiceId, r.setup.ServiceRunId,
		r.setup.RunNumber, string(material.CertificatePEM), previous, credentials.ServiceRunToken(r.setup.RunToken))
	if err != nil {
		var problem *clientcontrol.ProblemError
		if errors.As(err, &problem) && problem.Status == http.StatusBadRequest && problem.Problem.Code == controlv1.InvalidRequest {
			return result, errors.Join(errSuppliedCandidate, err)
		}
		return result, err
	}
	if receipt.CertificateSha256 != staged.Fingerprint || !receipt.ExpiresAt.After(time.Now()) ||
		receipt.ExpiresAt.After(staged.Certificate.Leaf.NotAfter) {
		return result, ErrPrivateStream
	}
	if err := r.cache.PromoteSupplied(ctx, r.prepared.managedHostname, staged.Fingerprint); err != nil {
		return result, err
	}
	if err := r.prepared.installSuppliedCertificate(staged.Certificate, receipt.ExpiresAt); err != nil {
		return result, err
	}
	return receipt, nil
}

func (p *Prepared) installSuppliedCertificate(certificate tls.Certificate, expires time.Time) error {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return ErrPrivateStream
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !expires.After(time.Now()) || expires.After(leaf.NotAfter) ||
		!certificateidentity.Covers(leaf.DNSNames, p.managedHostname) ||
		p.runHostname != "" && !certificateidentity.Covers(leaf.DNSNames, p.runHostname) {
		return ErrPrivateStream
	}
	certificate.Leaf = leaf
	p.certMu.Lock()
	p.certificate, p.certValidTo = certificate, expires
	p.certMu.Unlock()
	return nil
}
