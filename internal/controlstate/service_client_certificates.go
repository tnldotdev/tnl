package controlstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/internal/visitorcert"
)

const serviceClientIssuerContext = "service-client-certificate-issuer/v1"

type ServiceClientCertificate struct {
	ServiceID      string    `json:"private_service_id"`
	CertificatePEM string    `json:"certificate_pem"`
	IssuerPEM      string    `json:"issuer_pem"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// the seed is durable control-only state. losing an individual control process
// never changes the client issuer, and storage-key rotation preserves its key.
func (d *Database) ServiceClientIssuer(ctx context.Context) (*visitorcert.Issuer, error) {
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
	issuer, err := visitorcert.New(seed)
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

func (d *Database) IssueServiceClientCertificate(ctx context.Context, service, identity, device string, csr []byte, now time.Time) (result ServiceClientCertificate, retErr error) {
	if !opaqueid.Valid(device, opaqueid.VisitorDevicePrefix) {
		return result, ErrPrivateServiceAccess
	}
	if _, err := visitorcert.ValidateCSR(csr); err != nil {
		return result, ErrCertificateIssuanceInvalid
	}
	issuer, err := d.ServiceClientIssuer(ctx)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue service client certificate", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	_, _, err = privateVisitorAccess(ctx, tx, service, identity, now)
	if err != nil {
		return result, err
	}
	var validDevice bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.visitor_devices WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL)`, device, identity).Scan(&validDevice); err != nil {
		return result, err
	}
	if !validDevice {
		return result, ErrPrivateServiceAccess
	}
	digest := sha256.Sum256(csr)
	var certificate []byte
	err = tx.QueryRow(ctx, `SELECT certificate_pem,expires_at FROM control.service_client_certificates WHERE private_service_id=$1 AND device_id=$2 AND identity_id=$3 AND csr_digest=$4 AND revoked_at IS NULL AND expires_at>$5`, service, device, identity, digest[:], now).Scan(&certificate, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// this credential proves identity and key possession. live permission
		// checks still bound access by the current grant, run and lease deadlines.
		expires := now.Add(visitorcert.MaxLifetime)
		certificate, err = issuer.Issue(csr, service, identity, device, expires, now)
		if err != nil {
			return result, err
		}
		block, _ := pem.Decode(certificate)
		leaf, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return result, parseErr
		}
		certificateDigest := sha256.Sum256(leaf.Raw)
		err = tx.QueryRow(ctx, `INSERT INTO control.service_client_certificates(certificate_digest,private_service_id,identity_id,device_id,csr_digest,certificate_pem,created_at,expires_at,control_session_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(private_service_id,device_id,csr_digest) DO UPDATE SET csr_digest=EXCLUDED.csr_digest WHERE control.service_client_certificates.revoked_at IS NULL AND control.service_client_certificates.expires_at>$7 RETURNING certificate_pem,expires_at`, certificateDigest[:], service, identity, device, digest[:], certificate, now, leaf.NotAfter, nullableText(companySessionID(ctx, identity))).Scan(&certificate, &result.ExpiresAt)
	}
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	// a newly authenticated company session may renew this device's existing
	// certificate binding; the earlier session's proof cannot be extended.
	if _, err = tx.Exec(ctx, `UPDATE control.service_client_certificates SET control_session_id=$4 WHERE private_service_id=$1 AND identity_id=$2 AND device_id=$3 AND csr_digest=$5 AND revoked_at IS NULL AND expires_at>$6`, service, identity, device, nullableText(companySessionID(ctx, identity)), digest[:], now); err != nil {
		return result, err
	}
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.private_services WHERE id=$1`, service).Scan(&team); err != nil {
		return result, err
	}
	if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: team, ServiceID: service, ServiceKind: "private_service", EventType: "certificate.client.issue", ActorIdentityID: identity, DeviceID: device, OccurredAt: now}, device+"/"+hex.EncodeToString(digest[:])); err != nil {
		return result, err
	}
	result.ServiceID, result.CertificatePEM, result.IssuerPEM = service, string(certificate), string(issuer.CertificatePEM())
	return result, tx.Commit(ctx)
}

func (d *Database) AuthorizeServiceClientCertificate(ctx context.Context, service, runID, token, visitor string, number int64, source netip.Addr, der []byte, now time.Time) (result PrivateVisitorValidity, retErr error) {
	if len(der) == 0 || len(der) > 16<<10 || !source.IsValid() || source.Zone() != "" {
		return result, ErrPrivateServiceAccess
	}
	issuer, err := d.ServiceClientIssuer(ctx)
	if err != nil {
		return result, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return result, ErrPrivateServiceAccess
	}
	identity, device, err := issuer.Identity(leaf, service, now)
	if err != nil {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize service client certificate", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if err := d.managedHTTPSourceAllowed(ctx, q, service, source); err != nil {
		return result, err
	}
	run, err := privateRunAuthorization(ctx, tx, q, service, runID, token, now)
	if err != nil || run.RunNumber != number {
		return result, errors.Join(ErrPrivateServiceAccess, err)
	}
	digest := sha256.Sum256(der)
	result, err = recheckDirectServiceVisitor(ctx, tx, service, runID, number, visitor, identity, device, source, digest[:], now)
	if err != nil {
		return result, err
	}
	if leaf.NotAfter.Before(result.ValidUntil) {
		result.ValidUntil = leaf.NotAfter
	}
	if !result.ValidUntil.After(now) {
		result.Allowed = false
	}
	return result, tx.Commit(ctx)
}
