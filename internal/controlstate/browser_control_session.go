package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func (d *Database) IssueControlBrowserHandoff(ctx context.Context, access credentials.AccessToken, refresh credentials.RefreshToken, urlID string, accessLifetime, refreshLifetime time.Duration, now time.Time) (handoff BrowserHandoff, hostname string, retErr error) {
	accessID, accessHash, err := credentials.ParseAccessToken(access)
	if err != nil {
		return handoff, "", ErrControlAuthentication
	}
	refreshID, refreshHash, err := credentials.ParseRefreshToken(refresh)
	if err != nil {
		return handoff, "", ErrControlAuthentication
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return handoff, "", err
	}
	defer rollback(ctx, tx, "create control browser session", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return handoff, "", err
	}
	if url.Purpose != "app" && url.Purpose != "alias" || url.ServiceProtocol != "http" {
		return handoff, "", ErrPreviewAccess
	}
	source, err := q.LockVisitorControlSession(ctx, accessID.String())
	if err != nil {
		return handoff, "", err
	}
	if source.RevokedAt.Valid ||
		!source.AccessExpiresAt.Time.After(now) || !source.RefreshExpiresAt.Time.After(now) || source.RefreshTokenID != refreshID.String() ||
		!credentials.SecretHashMatches(source.AccessTokenDigest, accessHash) || !credentials.SecretHashMatches(source.RefreshTokenDigest, refreshHash) {
		return handoff, "", ErrControlAuthentication
	}
	if err = visitorManager(ctx, q, url, source.IdentityID); err != nil {
		return handoff, "", err
	}
	issued, err := d.createControlSession(ctx, q, source.IdentityID, accessLifetime, refreshLifetime, now)
	if err != nil {
		return handoff, "", err
	}
	identity, err := q.LockVisitorIdentity(ctx, source.IdentityID)
	if err != nil {
		return handoff, "", err
	}
	if err := q.CopyCompanySessionContexts(ctx, controlstatedb.CopyCompanySessionContextsParams{SourceSessionID: source.ID, DestinationSessionID: issued.SessionID, ExpiresAt: timestamptz(issued.RefreshExpiresAt), Now: timestamptz(now)}); err != nil {
		return handoff, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return handoff, "", err
	}
	handoff, err = d.IssueBrowserHandoff(ctx, BrowserLoginAttempt{PublicURLID: urlID, ReturnPath: "/"}, BrowserAccessSession{ParentControlSessionID: source.ID,
		IdentityID: source.IdentityID, DisplayName: identity.DisplayName, AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(), AccessExpiresAt: issued.AccessExpiresAt, ExpiresAt: issued.RefreshExpiresAt}, now)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err = errors.Join(err, d.RevokeControlSession(cleanupCtx, ControlPrincipal{SessionID: issued.SessionID, IdentityID: source.IdentityID}, now))
	}
	return handoff, url.CanonicalHostname, err
}
