package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// nativePeerPublisherAuthority checks current publisher authority without issuing
// or extending anything. callers hold service admission and the exact run lock.
func nativePeerPublisherAuthority(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun, now time.Time) (time.Time, error) {
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
	var grantExpiry, eligibility pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `SELECT expires_at FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$2 AND kind='service' AND service_id=$3 AND revoked_at IS NULL`, run.PublisherGrantID, run.PublisherIdentityID, run.ServiceID).Scan(&grantExpiry); err != nil {
		return time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	if grantExpiry.Valid {
		until = minTime(until, grantExpiry.Time)
	}
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
	    WHERE publisher.id=$1`, run.PublisherIdentityID).Scan(&eligibility); err != nil {
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
