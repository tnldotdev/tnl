package certificatestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func (r *CertificateCache) CurrentSupplied(ctx context.Context, hostname string) (Material, bool, error) {
	return r.material(ctx, hostname, false, true)
}

// StageSupplied durably records publisher-held keys before acknowledgement. it
// uses the same exact ownership, atomic storage and plan checkpoint as issuance.
func (r *CertificateCache) StageSupplied(ctx context.Context, hostname string, chain, key []byte) (result Material, resultErr error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return result, ErrPublisherStateConflict
	}
	certificate, err := certificateidentity.LoadSupplied(chain, key, []string{hostname}, time.Now())
	if err != nil {
		return result, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return result, errors.New("clientstate: supplied private key is invalid")
	}
	defer clear(der)
	digest := sha256.Sum256(certificate.Certificate[0])
	fingerprint := hex.EncodeToString(digest[:])
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close(), context.Cause(ctx)) }()
	checkpoint, err := r.files.Lock(ctx, "certificate-plans.lock")
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, checkpoint.Close()) }()
	value, err := r.read(ctx)
	if err != nil {
		return result, err
	}
	defer value.destroy()
	if value.Pending != nil {
		clear(value.Pending.PrivateKeyDER)
	}
	value.Pending = &storedCertificate{PrivateKeyDER: bytes.Clone(der), CertificatePEM: bytes.Clone(chain), SuppliedSHA256: fingerprint}
	if err = r.write(ctx, value); err != nil {
		return result, err
	}
	if err = r.checkpoint(ctx); err != nil {
		return result, err
	}
	return Material{Certificate: certificate, Fingerprint: fingerprint}, nil
}

func (r *CertificateCache) PromoteSupplied(ctx context.Context, hostname, fingerprint string) (result error) {
	if !certificateidentity.Covers(r.plan.Identifiers, hostname) {
		return ErrPublisherStateConflict
	}
	lock, err := r.files.Lock(ctx, certificateFilename(r.planJSON)+".lock")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close(), context.Cause(ctx)) }()
	value, err := r.read(ctx)
	if err != nil {
		return err
	}
	defer value.destroy()
	if value.Current != nil && value.Current.SuppliedSHA256 == fingerprint && value.Pending == nil {
		return r.files.Sync(ctx, certificateFilename(r.planJSON))
	}
	if value.Pending == nil || value.Pending.SuppliedSHA256 != fingerprint || fingerprint == "" {
		return ErrPublisherStateConflict
	}
	if _, err = suppliedCertificate(value.Pending, hostname, time.Now()); err != nil {
		return err
	}
	if value.Current != nil {
		clear(value.Current.PrivateKeyDER)
	}
	value.Current, value.Pending = value.Pending, nil
	return r.write(ctx, value)
}

func suppliedCertificate(stored *storedCertificate, hostname string, now time.Time) (tls.Certificate, error) {
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: stored.PrivateKeyDER})
	defer clear(key)
	if hostname == "" {
		block, _ := pem.Decode(stored.CertificatePEM)
		if block == nil {
			return tls.Certificate{}, ErrPublisherStateConflict
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || len(leaf.DNSNames) == 0 {
			return tls.Certificate{}, ErrPublisherStateConflict
		}
		// choose an exact covered probe for a wildcard-only recovery record.
		hostname = leaf.DNSNames[0]
		if len(hostname) > 2 && hostname[:2] == "*." {
			hostname = "certificate-check." + hostname[2:]
		}
	}
	certificate, err := certificateidentity.LoadSupplied(stored.CertificatePEM, key, []string{hostname}, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	digest := sha256.Sum256(certificate.Certificate[0])
	if hex.EncodeToString(digest[:]) != stored.SuppliedSHA256 {
		return tls.Certificate{}, ErrPublisherStateConflict
	}
	return certificate, nil
}
