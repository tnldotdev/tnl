package state

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (d *Database) MarkSuppliedServiceCertificateInstalled(ctx context.Context, service, runID, token string, number int64, chain, previous string, now time.Time) (controlv1.SuppliedServiceCertificateInstallation, error) {
	return d.markSuppliedServiceCertificateInstalled(ctx, service, runID, token, number, chain, previous, now, nil)
}

func (d *Database) markSuppliedServiceCertificateInstalled(ctx context.Context, service, runID, token string, number int64, chain, previous string, now time.Time, roots *x509.CertPool) (result controlv1.SuppliedServiceCertificateInstallation, retErr error) {
	if previous != "" {
		digest, err := hex.DecodeString(previous)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != previous {
			return result, ErrCertificateIssuanceInvalid
		}
	}
	if len(chain) == 0 || len(chain) > 128<<10 {
		return result, ErrCertificateIssuanceInvalid
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "install supplied service certificate", &retErr)()
	if err = lockServiceForPublication(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := d.serviceRunAuthorization(ctx, tx, q, service, runID, token, clock.current())
	if err != nil {
		return result, err
	}
	if run.RunNumber != number || run.CertificateIssuanceID.Valid {
		return result, ErrCertificateIssuanceInvalid
	}
	if _, err = serviceRunCertificatePlan(ctx, tx, run); err != nil {
		return result, err
	}
	names := []string{run.CertificateHostname}
	if run.RunHostname != "" {
		names = append(names, run.RunHostname)
	}
	validated, err := certificateidentity.ValidateSuppliedChain([]byte(chain), names, clock.current(), roots)
	if err != nil {
		return result, ErrCertificateIssuanceInvalid
	}
	current := run.SuppliedCertificateSha256.String
	if current != validated.Fingerprint && current != previous {
		return result, ErrCertificateIssuanceInvalid
	}
	// once replaced, a previously installed leaf cannot be restored by replaying
	// its original compare-and-swap request, even if it is still valid.
	if current != validated.Fingerprint {
		var retired bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_supplied_certificates
		    WHERE service_run_id=$1 AND certificate_sha256=$2)`, runID, validated.Fingerprint).Scan(&retired); err != nil {
			return result, err
		}
		if retired {
			return result, ErrCertificateIssuanceInvalid
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.service_supplied_certificates
	    (service_run_id,certificate_sha256,certificate_domain_id,not_after,installed_at)
	    VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_run_id,certificate_sha256) DO NOTHING`,
		runID, validated.Fingerprint, run.CertificateDomainID, validated.Leaf.NotAfter, clock.current()); err != nil {
		return result, err
	}
	// revalidating the same leaf may narrow its deadline when trust changes,
	// but a retry cannot extend a previously acknowledged serving deadline.
	if current == validated.Fingerprint && run.CertificateExpiresAt.Time.Before(validated.ExpiresAt) {
		validated.ExpiresAt = run.CertificateExpiresAt.Time
	}
	if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET supplied_certificate_sha256=$2,certificate_expires_at=$3 WHERE id=$1`,
		runID, validated.Fingerprint, validated.ExpiresAt); err != nil {
		return result, err
	}
	if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: run.TeamID.String, ServiceID: service, ServiceKind: "service",
		EventType: "certificate.install", RunID: runID, PublisherIdentityID: run.PublisherIdentityID, OccurredAt: now},
		runID+"/supplied/"+validated.Fingerprint); err != nil {
		return result, err
	}
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
		return result, err
	}
	if !validated.ExpiresAt.After(clock.current()) {
		return result, ErrCertificateIssuanceInvalid
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	if current != validated.Fingerprint {
		d.activity.metrics.Load().ObserveCertificateTransition("service", "installed")
	}
	return controlv1.SuppliedServiceCertificateInstallation{CertificateSha256: validated.Fingerprint, ExpiresAt: validated.ExpiresAt}, nil
}
