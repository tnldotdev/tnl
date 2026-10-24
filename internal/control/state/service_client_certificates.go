package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	controlvisitor "github.com/tnldotdev/tnl/internal/control/certificates/visitor"
)

const serviceClientIssuerContext = "service-client-certificate-issuer/v1"

type ServiceClientCertificate struct {
	ServiceID      string    `json:"service_id"`
	CertificatePEM string    `json:"certificate_pem"`
	IssuerPEM      string    `json:"issuer_pem"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// the seed is durable control-only state. losing an individual control process
// never changes the client issuer, and storage-key rotation preserves its key.
func (d *Database) ServiceClientIssuer(ctx context.Context) (*controlvisitor.Issuer, error) {
	var ciphertext []byte
	var keyID string
	err := d.pool.QueryRow(ctx, `SELECT seed_ciphertext,storage_key_id FROM control.service_client_certificate_issuer WHERE id`).Scan(&ciphertext, &keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return nil, err
		}
		sealed, sealErr := d.storageKey.Seal(serviceClientIssuerContext, seed)
		clear(seed)
		if sealErr != nil {
			return nil, sealErr
		}
		if _, err = d.pool.Exec(ctx, `INSERT INTO control.service_client_certificate_issuer(seed_ciphertext,storage_key_id,created_at) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING`, sealed, d.storageKey.CurrentID(), time.Now()); err != nil {
			return nil, err
		}
		err = d.pool.QueryRow(ctx, `SELECT seed_ciphertext,storage_key_id FROM control.service_client_certificate_issuer WHERE id`).Scan(&ciphertext, &keyID)
	}
	if err != nil {
		return nil, err
	}
	seed, previous, err := d.storageKey.Open(keyID, serviceClientIssuerContext, ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	issuer, err := controlvisitor.New(seed)
	if err != nil {
		return nil, err
	}
	if previous {
		sealed, err := d.storageKey.Seal(serviceClientIssuerContext, seed)
		if err != nil {
			return nil, err
		}
		if _, err = d.pool.Exec(ctx, `UPDATE control.service_client_certificate_issuer SET seed_ciphertext=$1,storage_key_id=$2 WHERE id AND storage_key_id=$3 AND seed_ciphertext=$4`, sealed, d.storageKey.CurrentID(), keyID, ciphertext); err != nil {
			return nil, err
		}
	}
	return issuer, nil
}
