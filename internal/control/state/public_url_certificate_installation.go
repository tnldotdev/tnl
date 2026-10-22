package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// MarkPublicURLCertificateInstalled records publisher acknowledgement of the
// installed public URL certificate. first routability still requires both connections.
func (d *Database) MarkPublicURLCertificateInstalled(
	ctx context.Context,
	authentication PublishRunAuthentication,
	issuanceID string,
	notAfter time.Time,
	now time.Time,
) (result PublishRunLifecycle, retErr error) {
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return PublishRunLifecycle{}, err
	}
	if !validStateText(issuanceID) || !notAfter.After(now) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunLifecycle{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "install public URL certificate", &retErr)()
	queries := controlstatedb.New(tx)
	route, session, err := lockAuthenticatedPublishRun(ctx, queries, authentication, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	alreadyInstalled := session.CertificateInstalledAt.Valid
	order, err := queries.LockACMEOrderForInstall(ctx, controlstatedb.LockACMEOrderForInstallParams{
		IssuanceID: issuanceID, TeamID: session.TeamID, CertificateCacheKey: session.CertificateCacheKey.String,
		CertificateScope: session.CertificateScope.String, CertificateIdentifiers: session.CertificateIdentifiers,
		ChallengeMethod: session.CertificateChallengeMethod.String,
		NotAfter:        timestamptz(notAfter), InstalledAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	} else if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: lock issuance: %w", err)
	}
	if !validInstalledCertificate(order, route.CanonicalHostname, now) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	}
	issuedRun, err := queries.GetPublishRun(ctx, order.PublishRunID)
	if err != nil {
		return result, err
	}
	// a local cache may reuse a certificate across this publisher's runs. a
	// different enrolled publisher owns an independent TLS key and CSR cache.
	if issuedRun.PublisherIdentityID != session.PublisherIdentityID {
		return result, ErrPublicURLCertificate
	}
	if session.CertificateIssuanceID.Valid && session.CertificateIssuanceID.String != issuanceID {
		current, err := queries.GetACMEOrder(ctx, session.CertificateIssuanceID.String)
		if err != nil {
			return result, err
		}
		if order.CreatedRevision < current.CreatedRevision {
			return result, ErrPublicURLCertificate
		}
	}
	if _, err := queries.MarkACMEOrderInstalled(ctx, controlstatedb.MarkACMEOrderInstalledParams{
		InstalledAt: timestamptz(now), IssuanceID: issuanceID,
	}); errors.Is(err, pgx.ErrNoRows) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	} else if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: update issuance: %w", err)
	}
	session, err = queries.MarkPublishRunCertificateInstalled(ctx, controlstatedb.MarkPublishRunCertificateInstalledParams{
		InstalledAt: timestamptz(now), IssuanceID: text(issuanceID), NotAfter: timestamptz(notAfter),
		PublishRunID: session.ID, PublicURLID: session.PublicURLID, PublishRunNumber: session.PublishRunNumber,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	}
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: update session: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: commit: %w", err)
	}
	if !alreadyInstalled {
		d.activity.metrics.Load().ObserveCertificateTransition("public_url", "installed")
	}
	return publishRunLifecycle(session, connections, 0, 0), nil
}
