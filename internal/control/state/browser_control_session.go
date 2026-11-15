package state

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func (d *Database) IssueControlBrowserHandoff(ctx context.Context, access credentials.AccessToken, refresh credentials.RefreshToken, serviceID string, accessLifetime, refreshLifetime time.Duration, now time.Time) (handoff BrowserHandoff, retErr error) {
	clock := newAuthorizationClock(now)
	accessID, accessHash, err := credentials.ParseAccessToken(access)
	if err != nil {
		return handoff, ErrControlAuthentication
	}
	refreshID, refreshHash, err := credentials.ParseRefreshToken(refresh)
	if err != nil {
		return handoff, ErrControlAuthentication
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return handoff, err
	}
	defer rollback(ctx, tx, "create control browser session", &retErr)()
	q := controlstatedb.New(tx)
	// browser authentication supplies authorship independently of visitation.
	// it needs a current http service, not the visitor's management authority.
	if err := lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return handoff, err
	}
	service, err := q.GetService(ctx, serviceID)
	if err != nil {
		return handoff, err
	}
	if service.Protocol != "http" {
		return handoff, ErrPreviewAccess
	}
	source, err := q.LockVisitorControlSession(ctx, accessID.String())
	if err != nil {
		return handoff, publisherLookupError(err, ErrControlAuthentication)
	}
	if source.RevokedAt.Valid ||
		!source.AccessExpiresAt.Time.After(clock.current()) || !source.RefreshExpiresAt.Time.After(clock.current()) || source.RefreshTokenID != refreshID.String() ||
		!credentials.SecretHashMatches(source.AccessTokenDigest, accessHash) || !credentials.SecretHashMatches(source.RefreshTokenDigest, refreshHash) {
		return handoff, ErrControlAuthentication
	}
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: serviceID, Now: timestamptz(clock.current())})
	if err != nil || len(endpoint.RunIds) == 0 {
		return handoff, ErrPreviewAccess
	}
	issued, err := d.createControlSession(ctx, q, source.IdentityID, accessLifetime, refreshLifetime, clock.current())
	if err != nil {
		return handoff, err
	}
	identity, err := q.LockVisitorIdentity(ctx, source.IdentityID)
	if err != nil {
		return handoff, err
	}
	if err := q.CopyCompanySessionContexts(ctx, controlstatedb.CopyCompanySessionContextsParams{SourceSessionID: source.ID, DestinationSessionID: issued.SessionID, ExpiresAt: timestamptz(issued.RefreshExpiresAt), Now: timestamptz(clock.current())}); err != nil {
		return handoff, err
	}
	if !source.AccessExpiresAt.Time.After(clock.current()) || !source.RefreshExpiresAt.Time.After(clock.current()) {
		return handoff, ErrControlAuthentication
	}
	if err = tx.Commit(ctx); err != nil {
		return handoff, err
	}
	handoff, err = d.IssueBrowserHandoff(ctx, BrowserLoginAttempt{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: serviceID}, ServiceRunIDs: endpoint.RunIds, ReturnPath: "/"}, BrowserAccessSession{ParentControlSessionID: source.ID,
		IdentityID: source.IdentityID, DisplayName: identity.DisplayName, AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(), AccessExpiresAt: issued.AccessExpiresAt, ExpiresAt: issued.RefreshExpiresAt}, clock.current())
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err = errors.Join(err, d.RevokeControlSession(cleanupCtx, ControlPrincipal{SessionID: issued.SessionID, IdentityID: source.IdentityID}, now))
	}
	return handoff, err
}
