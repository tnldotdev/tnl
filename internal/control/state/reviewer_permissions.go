package controlstate

import (
	"context"
	"encoding/base64"
	"time"

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
	identity, err := d.httpVisitorDecision(ctx, q, url, HTTPVisitorRequest{SourceIP: actor.SourceIP, BrowserCookieSecret: token, ShareID: actor.ShareID, ShareCookieSecret: actor.CookieSecret, ShareSecret: actor.ShareSecret}, now)
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
