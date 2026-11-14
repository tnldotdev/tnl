package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// connectorPeerPublisherAuthority checks current publisher authority without issuing
// or extending anything. callers hold service admission and the exact run lock.
func connectorPeerPublisherAuthority(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun, now time.Time) (time.Time, error) {
	if _, err := controlstatedb.New(tx).GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: run.ServiceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	}); err != nil {
		return time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	until := run.PublisherExpiresAt.Time
	if run.CertificateExpiresAt.Valid {
		until = minTime(until, run.CertificateExpiresAt.Time)
	}
	var grantExpiry pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `SELECT expires_at FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$2 AND kind='service' AND service_id=$3 AND revoked_at IS NULL`, run.PublisherGrantID, run.PublisherIdentityID, run.ServiceID).Scan(&grantExpiry); err != nil {
		return time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	if grantExpiry.Valid {
		until = minTime(until, grantExpiry.Time)
	}
	return connectorPublisherEligibility(ctx, tx, run.PublisherIdentityID, until, now)
}

func (d *Database) connectorPublicURLPublisherAuthority(ctx context.Context, tx pgx.Tx, url controlstatedb.ControlPublicUrl, run controlstatedb.ControlPublishRun, now time.Time) (time.Time, error) {
	until, err := d.connectorPublicURLPublisherIdentity(ctx, tx, url, run, now)
	if err != nil {
		return time.Time{}, err
	}
	until = minTime(until, run.CertificateNotAfter.Time)
	if !until.After(now) {
		return time.Time{}, ErrServiceAccess
	}
	return until, nil
}

// publisher hints do not require a certificate or ready connections. delivery
// and owner observations independently check those stronger publication facts.
func (d *Database) connectorPublicURLPublisherIdentity(ctx context.Context, tx pgx.Tx, url controlstatedb.ControlPublicUrl, run controlstatedb.ControlPublishRun, now time.Time) (time.Time, error) {
	if !run.PublisherIdentityID.Valid || !run.PublisherGrantID.Valid || !run.PublisherKeyID.Valid {
		return time.Time{}, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	publisher, grant, err := d.livePublisher(ctx, q, run.PublisherIdentityID.String, run.PublisherGrantID.String, "", now)
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	if err := publisherOwnsRun(ctx, q, publisher, url); err != nil {
		return time.Time{}, err
	}
	key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: run.PublisherKeyID.String, PublisherIdentityID: publisher.ID})
	if err != nil || key.RetiredAt.Valid {
		if err != nil {
			return time.Time{}, publisherLookupError(err, ErrServiceAccess)
		}
		return time.Time{}, ErrServiceAccess
	}
	until := run.PublisherExpiresAt.Time
	if grant.ExpiresAt.Valid {
		until = minTime(until, grant.ExpiresAt.Time)
	}
	if url.ExpiresAt.Valid {
		until = minTime(until, url.ExpiresAt.Time)
	}
	return connectorPublisherEligibility(ctx, tx, publisher.ID, until, now)
}

func connectorPublisherEligibility(ctx context.Context, tx pgx.Tx, publisherID string, until, now time.Time) (time.Time, error) {
	var eligibility pgtype.Timestamptz
	// a member-owned publisher's company eligibility can expire before its run.
	if err := tx.QueryRow(ctx, `SELECT CASE WHEN publisher.ownership='member' AND NOT member.personal_account_exception
	    AND (team.company_sign_in_required OR member.identity_connection_id IS NOT NULL) THEN
	    (SELECT eligibility.valid_until FROM control.identity_connections connection
	        JOIN control.company_eligibility eligibility ON eligibility.identity_connection_id=connection.id
	        AND eligibility.team_id=connection.team_id AND eligibility.identity_id=member.identity_id
	        WHERE connection.team_id=team.id AND connection.state='active' AND eligibility.connection_revision=connection.revision
	        AND eligibility.eligible AND (member.identity_connection_id IS NULL OR member.identity_connection_id=connection.id)
	        ORDER BY eligibility.valid_until LIMIT 1) END
	    FROM control.publisher_identities publisher JOIN control.teams team ON team.id=publisher.team_id
	    LEFT JOIN control.team_memberships member ON member.id=publisher.owner_membership_id
	    WHERE publisher.id=$1`, publisherID).Scan(&eligibility); err != nil {
		return time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	if eligibility.Valid {
		until = minTime(until, eligibility.Time)
	}
	if !until.After(now) {
		return time.Time{}, ErrServiceAccess
	}
	return until, nil
}
