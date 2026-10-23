package state

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"

	"github.com/jackc/pgx/v5"
	controlvisitor "github.com/tnldotdev/tnl/internal/control/certificates/visitor"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// IssueVisitorClientCertificate uses the same source permission as token
// preparation, then binds it to the CSR's proven TLS key and exact certificate.
// stored certificate rows support issuance and revocation, never stream admission.
func (d *Database) IssueVisitorClientCertificate(ctx context.Context, issuerURL string, scope visitorscope.Scope, source VisitorTokenSource, csrDER []byte, now time.Time) (result ServiceClientCertificate, retErr error) {
	if scope.Kind != visitorscope.Service {
		return result, ErrVisitorPermission
	}
	switch source.(type) {
	case DeviceTokenSource, WorkloadTokenSource:
	default:
		return result, ErrVisitorPermission
	}
	csr, err := controlvisitor.ValidateCSR(csrDER)
	if err != nil {
		return result, ErrCertificateIssuanceInvalid
	}
	issuer, err := d.ServiceClientIssuer(ctx)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue visitor client certificate", &retErr)()
	permission, err := d.visitorPermissionForSource(ctx, tx, scope, source, now)
	if err != nil {
		return result, err
	}
	origin := permission.Subject
	if workload, ok := origin.(visitortoken.Workload); ok {
		digest, err := visitortoken.KeyDigest(csr.PublicKey)
		if err != nil || digest != workload.KeySHA256 {
			return result, ErrVisitorPermission
		}
	}
	material, err := issuer.IssuePermission(csrDER, permission.ExpiresAt, now, func(serial string, public any, expires time.Time) (visitortoken.Token, error) {
		digest, err := visitortoken.KeyDigest(public)
		if err != nil {
			return "", err
		}
		permission.Subject = visitortoken.Certificate{Serial: serial, KeySHA256: digest, Source: origin}
		permission.ExpiresAt = expires
		return d.signVisitorPermission(ctx, tx, issuerURL, permission, now)
	})
	if err != nil {
		return result, err
	}
	block, _ := pem.Decode(material)
	if block == nil {
		return result, ErrCertificateIssuanceInvalid
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return result, ErrCertificateIssuanceInvalid
	}
	certificateDigest, csrDigest := sha256.Sum256(leaf.Raw), sha256.Sum256(csrDER)
	switch parent := origin.(type) {
	case visitortoken.Device:
		tag, writeErr := tx.Exec(ctx, `INSERT INTO control.service_client_certificates(certificate_digest,service_id,identity_id,device_id,csr_digest,certificate_pem,created_at,expires_at,control_session_id)
		    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(service_id,device_id,csr_digest) DO UPDATE
		    SET certificate_digest=EXCLUDED.certificate_digest,certificate_pem=EXCLUDED.certificate_pem,
		        expires_at=EXCLUDED.expires_at,control_session_id=EXCLUDED.control_session_id
		    WHERE control.service_client_certificates.revoked_at IS NULL`, certificateDigest[:], scope.ID, parent.IdentityID, parent.DeviceID, csrDigest[:], material, now, leaf.NotAfter, parent.SessionID)
		if writeErr != nil {
			return result, writeErr
		}
		if tag.RowsAffected() != 1 {
			return result, ErrVisitorPermission
		}
		var team string
		if err := tx.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1`, scope.ID).Scan(&team); err != nil {
			return result, err
		}
		err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: team, ServiceID: scope.ID, ServiceKind: "service", EventType: "certificate.client.issue", ActorIdentityID: parent.IdentityID, DeviceID: parent.DeviceID, OccurredAt: now}, "visitor-certificate/"+hex.EncodeToString(certificateDigest[:]))
	case visitortoken.Workload:
		_, err = tx.Exec(ctx, `INSERT INTO control.workload_client_certificates(certificate_digest,workload_session_id,service_id,csr_digest,certificate_pem,expires_at)
		    VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workload_session_id,service_id,csr_digest) DO UPDATE
		    SET certificate_digest=EXCLUDED.certificate_digest,certificate_pem=EXCLUDED.certificate_pem,expires_at=EXCLUDED.expires_at`, certificateDigest[:], parent.SessionID, scope.ID, csrDigest[:], material, leaf.NotAfter)
		if err == nil {
			err = workloadAudit(ctx, tx, parent.SessionID, "certificate.issue", scope.ID, now)
		}
	default:
		return result, ErrVisitorPermission
	}
	if err != nil {
		return result, err
	}
	result = ServiceClientCertificate{ServiceID: scope.ID, CertificatePEM: string(material), IssuerPEM: string(issuer.CertificatePEM()), ExpiresAt: leaf.NotAfter}
	return result, tx.Commit(ctx)
}
