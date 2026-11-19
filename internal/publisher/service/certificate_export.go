package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"time"
)

// CertificateExport provides a snapshot of a live run's installed certificate
// to its owner. it does not read pending issuance or trigger new work.
type CertificateExport struct {
	mu       sync.Mutex
	ctx      context.Context
	prepared *Prepared
}

type ExportedCertificate struct {
	CertificateMaterial
	ExpiresAt time.Time
}

func (ExportedCertificate) String() string   { return "private installed service certificate" }
func (ExportedCertificate) GoString() string { return "private installed service certificate" }

var ErrCertificateUnavailable = errors.New("installed service certificate is unavailable")

func (e *CertificateExport) bind(ctx context.Context, p *Prepared) (func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.prepared != nil {
		return nil, ErrCertificateUnavailable
	}
	e.ctx, e.prepared = ctx, p
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.ctx, e.prepared = nil, nil
	}, nil
}

func (e *CertificateExport) Snapshot(ctx context.Context) (ExportedCertificate, error) {
	if err := context.Cause(ctx); err != nil {
		return ExportedCertificate{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.prepared == nil || e.ctx.Err() != nil {
		return ExportedCertificate{}, ErrCertificateUnavailable
	}
	certificate, expiresAt, err := e.prepared.currentCertificateSnapshot()
	if err != nil {
		return ExportedCertificate{}, ErrCertificateUnavailable
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return ExportedCertificate{}, ErrCertificateUnavailable
	}
	defer clear(key)
	material := ExportedCertificate{ExpiresAt: expiresAt}
	material.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	for _, der := range certificate.Certificate {
		material.CertificatePEM = append(material.CertificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := context.Cause(ctx); err != nil || e.ctx.Err() != nil || !material.ExpiresAt.After(e.prepared.clock()) {
		clear(material.PrivateKeyPEM)
		return ExportedCertificate{}, errors.Join(err, ErrCertificateUnavailable)
	}
	return material, nil
}
