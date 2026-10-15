package controlstate

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func (d *Database) currentReviewer(ctx context.Context, q *controlstatedb.Queries, url controlstatedb.ControlPublicUrl, previewID string, actor FeedbackActor, now time.Time) (FeedbackActor, string, error) {
	if actor.Kind != "reviewer" || url.ServiceProtocol != "http" {
		return FeedbackActor{}, "", ErrFeedbackAccess
	}
	if len(actor.BrowserCookieSecret) != 0 && len(actor.BrowserCookieSecret) != 32 || len(actor.BrowserCookieSecret) == 0 && actor.IdentityID != "" {
		return FeedbackActor{}, "", ErrVisitorSignIn
	}
	token := ""
	if len(actor.BrowserCookieSecret) != 0 {
		token = base64.RawURLEncoding.EncodeToString(actor.BrowserCookieSecret)
	}
	identity, err := d.httpVisitorDecision(ctx, q, url, HTTPVisitorRequest{SourceIP: actor.SourceIP, BrowserCookieSecret: token, ShareID: actor.ShareID, ShareCookieSecret: actor.CookieSecret, ShareSecret: actor.ShareSecret}, now)
	if err != nil {
		return FeedbackActor{}, "", err
	}
	actor.IdentityID, actor.DisplayName = identity.IdentityID, identity.DisplayName
	reference := identity.Reason
	if identity.Reason == "anonymous_share" {
		reference = actor.ShareID
	}
	if !identity.VisitAllowed {
		return FeedbackActor{}, "", ErrFeedbackAccess
	}
	if identity.IdentityID != "" {
		reference = "identity:" + identity.IdentityID
	}
	actor.VisitAllowed = identity.VisitAllowed
	return actor, reference, nil
}
