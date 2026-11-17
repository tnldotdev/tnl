package state

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func earlierVisitorExpiry(current *time.Time, candidate time.Time) *time.Time {
	if candidate.IsZero() || current != nil && !candidate.Before(*current) {
		return current
	}
	return &candidate
}

var ErrVisitorSignIn = errors.New("visitor sign-in required")

// VisitorPermission is a current decision, not a reusable authorization token.
type VisitorPermission struct {
	Authenticated bool
	IdentityID    string
	DisplayName   string
	TeamMember    bool
	VisitAllowed  bool
	Reason        string
	ExpiresAt     *time.Time
}

// authority HTTP refresh finishes before this transaction-bound decision.
func currentVisitorSession(ctx context.Context, q *controlstatedb.Queries, access string, identityID, parentID string, now time.Time) (time.Time, error) {
	id, digest, err := credentials.ParseAccessToken(credentials.AccessToken(access))
	if err != nil {
		return time.Time{}, ErrVisitorSignIn
	}
	session, err := q.LockVisitorControlSession(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrVisitorSignIn
	}
	if err != nil {
		return time.Time{}, err
	}
	if session.IdentityID != identityID || session.RevokedAt.Valid || !session.AccessExpiresAt.Time.After(now) ||
		subtle.ConstantTimeCompare(session.AccessTokenDigest, digest[:]) != 1 {
		return time.Time{}, ErrVisitorSignIn
	}
	expires := session.AccessExpiresAt.Time
	if parentID != "" {
		parent, err := q.GetVisitorParentSession(ctx, parentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, ErrVisitorSignIn
		}
		if err != nil {
			return time.Time{}, err
		}
		if parent.IdentityID != identityID || parent.RevokedAt.Valid || !parent.RefreshExpiresAt.Time.After(now) {
			return time.Time{}, ErrVisitorSignIn
		}
		if parent.RefreshExpiresAt.Time.Before(expires) {
			expires = parent.RefreshExpiresAt.Time
		}
	}
	return expires, nil
}
