package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// currentVisitorParentSession is shared by issuance and signed subject rechecks.
// a supplied identity or session alone is never visitor permission.
func currentVisitorParentSession(ctx context.Context, tx pgx.Tx, principal ControlPrincipal, now time.Time) (time.Time, error) {
	if !opaqueid.Valid(principal.IdentityID, opaqueid.IdentityPrefix) || !opaqueid.Valid(principal.SessionID, opaqueid.ControlSessionPrefix) {
		return time.Time{}, ErrVisitorPermission
	}
	session, err := controlstatedb.New(tx).GetVisitorParentSession(ctx, principal.SessionID)
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrVisitorPermission)
	}
	if session.IdentityID != principal.IdentityID || session.RevokedAt.Valid ||
		!session.AccessExpiresAt.Time.After(now) || !session.RefreshExpiresAt.Time.After(now) {
		return time.Time{}, ErrVisitorPermission
	}
	return minTime(session.AccessExpiresAt.Time, session.RefreshExpiresAt.Time), nil
}

type visitorGrantAuthority struct {
	subject      visitortoken.Grant
	secretDigest []byte
	expiresAt    time.Time
}

// currentServiceHTTPGrantAuthority restores current grant and creator authority.
// callers separately prove either the refresh secret or the actual signed bearer.
func currentServiceHTTPGrantAuthority(ctx context.Context, tx pgx.Tx, service, grantID string, now time.Time) (result visitorGrantAuthority, err error) {
	var creator, session string
	result.subject.GrantID = grantID
	err = tx.QueryRow(ctx, `SELECT created_by_identity_id,COALESCE(control_session_id,''),expires_at,kind,secret_digest
	    FROM control.service_http_grants WHERE id=$1 AND service_id=$2 AND revoked_at IS NULL AND expires_at>$3 FOR SHARE`,
		grantID, service, now).Scan(&creator, &session, &result.expiresAt, &result.subject.Kind, &result.secretDigest)
	if err != nil {
		return visitorGrantAuthority{}, publisherLookupError(err, ErrVisitorPermission)
	}
	if session != "" {
		until, err := currentVisitorParentSession(ctx, tx, ControlPrincipal{IdentityID: creator, SessionID: session}, now)
		if err != nil {
			return visitorGrantAuthority{}, err
		}
		result.expiresAt = minTime(result.expiresAt, until)
	}
	decision, err := controlstatedb.New(tx).VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{
		ResourceKind: "service", ResourceID: service, IdentityID: creator, ControlSessionID: session, Now: timestamptz(now),
	})
	if err != nil {
		return visitorGrantAuthority{}, publisherLookupError(err, ErrVisitorPermission)
	}
	if decision.ExpiresAt.Valid && decision.ExpiresAt.InfinityModifier == 0 {
		result.expiresAt = minTime(result.expiresAt, decision.ExpiresAt.Time)
	}
	return result, nil
}
