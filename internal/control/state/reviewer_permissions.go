package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// feedback may combine a verified browser author with URL-scoped share access.
// HTTP visitor selection remains exclusive at its own request boundary.
func (d *Database) currentReviewer(ctx context.Context, q *controlstatedb.Queries, url controlstatedb.ControlPublicUrl, previewID string, actor FeedbackActor, now time.Time) (authorizedFeedbackActor, error) {
	if actor.Kind != "reviewer" || url.ServiceProtocol != "http" {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	if len(actor.BrowserCookieSecret) != 0 && len(actor.BrowserCookieSecret) != 32 || len(actor.BrowserCookieSecret) == 0 && actor.IdentityID != "" {
		return authorizedFeedbackActor{}, ErrVisitorSignIn
	}
	token := ""
	if len(actor.BrowserCookieSecret) != 0 {
		token = base64.RawURLEncoding.EncodeToString(actor.BrowserCookieSecret)
	}
	identity, err := d.reviewerVisitPermission(ctx, q, url, actor, token, now)
	if err != nil {
		return authorizedFeedbackActor{}, err
	}
	reference := identity.Reason
	if identity.Reason == "anonymous_share" {
		reference = actor.ShareID
	}
	if !identity.VisitAllowed {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	if identity.IdentityID != "" {
		reference = "identity:" + identity.IdentityID
	}
	return authorizedFeedbackActor{kind: feedbackReviewer, identityID: identity.IdentityID, displayName: identity.DisplayName, reference: reference, permissions: reviewerFeedbackPermissions}, nil
}

func (d *Database) reviewerVisitPermission(ctx context.Context, q *controlstatedb.Queries, url controlstatedb.ControlPublicUrl, actor FeedbackActor, browser string, now time.Time) (VisitorPermission, error) {
	result := VisitorPermission{}
	ip, ipExpires, err := d.visitorIPAllowed(ctx, q, url, actor.SourceIP, now)
	if err != nil || !ip {
		return result, err
	}
	result.ExpiresAt = ipExpires
	if browser != "" {
		result, err = d.browserPermission(ctx, q, url.ID, browser, now)
		if err != nil {
			return result, err
		}
		if ipExpires != nil {
			result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, *ipExpires)
		}
	}
	if result.VisitAllowed {
		return result, nil
	}
	if len(actor.ShareSecret) == 32 {
		share, err := q.GetActiveShareForPublicURL(ctx, controlstatedb.GetActiveShareForPublicURLParams{ShareID: actor.ShareID, PublicURLID: url.ID, Now: timestamptz(now)})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		if err == nil {
			digest := sha256.Sum256(actor.ShareSecret)
			if subtle.ConstantTimeCompare(digest[:], share.SecretDigest) == 1 {
				result.VisitAllowed, result.Reason = true, "anonymous_share"
				result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, share.ExpiresAt.Time)
				return result, nil
			}
		}
	}
	if len(actor.CookieSecret) == 32 {
		digest := sha256.Sum256(actor.CookieSecret)
		expires, err := q.ReviewerShareCookieValid(ctx, controlstatedb.ReviewerShareCookieValidParams{ShareID: actor.ShareID, PublicURLID: url.ID, TokenDigest: digest[:], Now: timestamptz(now)})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		if err == nil {
			result.VisitAllowed, result.Reason = true, "anonymous_share"
			result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, expires.Time)
		}
	}
	if actor.ShareID == "" && len(actor.ShareSecret) == 0 && len(actor.CookieSecret) == 0 && (browser == "" || result.Authenticated) && url.AccessMode == string(VisitorAccessAnonymous) {
		result.VisitAllowed, result.Reason = true, "anonymous"
	}
	return result, nil
}
