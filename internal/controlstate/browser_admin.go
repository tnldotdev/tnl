package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

// IssueAdminBrowserHandoff creates an independent built-in browser control
// session after the CLI proves its current access and refresh credentials.
func (d *Database) IssueAdminBrowserHandoff(ctx context.Context, access credentials.AccessToken, refresh credentials.RefreshToken,
	publicURLID string, loginSourceRevision int64, accessLifetime, refreshLifetime time.Duration, now time.Time,
) (handoff BrowserHandoff, hostname string, retErr error) {
	accessID, accessDigest, err := credentials.ParseAccessToken(access)
	if err != nil {
		return BrowserHandoff{}, "", ErrControlAuthentication
	}
	refreshID, refreshDigest, err := credentials.ParseRefreshToken(refresh)
	if err != nil || publicURLID == "" || loginSourceRevision < 1 || accessLifetime <= 0 || refreshLifetime < accessLifetime {
		return BrowserHandoff{}, "", ErrControlAuthentication
	}
	if err := d.requireOpen(); err != nil {
		return BrowserHandoff{}, "", err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("start administrator browser handoff: %w", err)
	}
	defer rollback(ctx, tx, "issue administrator browser handoff", &retErr)()
	queries := controlstatedb.New(tx)
	candidate, err := queries.GetFeedbackPublicURL(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserHandoff{}, "", ErrPreviewAccess
	}
	if err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("read administrator browser URL: %w", err)
	}
	if err := queries.LockReviewerTeam(ctx, candidate.TeamID); err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("lock administrator browser team: %w", err)
	}
	url, err := queries.ShareBrowserPublicURL(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (url.LifecycleState != string(PublicURLLifecycleEnabled) ||
		url.Purpose != string(PublicURLPurposeApp) || url.ServiceProtocol != string(PublicURLServiceHTTP)) {
		return BrowserHandoff{}, "", ErrPreviewAccess
	}
	if err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("lock administrator browser URL: %w", err)
	}
	source, err := queries.LockAdminBrowserSourceSession(ctx, accessID.String())
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (source.AuthenticationSourceRevision != loginSourceRevision ||
		source.RefreshTokenID != refreshID.String() || !credentials.SecretHashMatches(source.AccessTokenDigest, accessDigest) ||
		!credentials.SecretHashMatches(source.RefreshTokenDigest, refreshDigest) || !source.AccessExpiresAt.Time.After(now) ||
		!source.RefreshExpiresAt.Time.After(now)) {
		return BrowserHandoff{}, "", ErrControlAuthentication
	}
	if err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("verify administrator control session: %w", err)
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: url.TeamID, IdentityID: source.IdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !(url.PublicURLScope == string(PublicURLScopeMember) && url.MembershipID.Valid && url.MembershipID.String == membership.ID ||
		url.PublicURLScope == string(PublicURLScopeShared) && (membership.Role == string(TeamRoleOwner) || membership.Role == string(TeamRoleAdmin))) {
		return BrowserHandoff{}, "", ErrPreviewAccess
	}
	if err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("read administrator URL ownership: %w", err)
	}
	landing, err := queries.BrowserLoginPublicURL(ctx, controlstatedb.BrowserLoginPublicURLParams{
		PublicURLID: url.ID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserHandoff{}, "", ErrPreviewAccess
	}
	if err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("read administrator browser run: %w", err)
	}
	issued, err := d.createControlSession(ctx, queries, source.IdentityID, true, loginAuthenticationMethod,
		loginSourceRevision, accessLifetime, refreshLifetime, now)
	if err != nil {
		return BrowserHandoff{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return BrowserHandoff{}, "", fmt.Errorf("commit administrator browser session: %w", err)
	}
	handoff, err = d.IssueBrowserHandoff(ctx, BrowserLoginAttempt{PublicURLID: url.ID, ReturnPath: "/"}, BrowserAccessSession{
		IdentityID: source.IdentityID, DisplayName: source.DisplayName, ParentControlSessionID: source.ID,
		AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(),
		AccessExpiresAt: issued.AccessExpiresAt, ExpiresAt: issued.RefreshExpiresAt,
	}, now)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		cleanup := d.RevokeControlSession(cleanupCtx, ControlPrincipal{SessionID: issued.SessionID, IdentityID: source.IdentityID}, time.Now())
		return BrowserHandoff{}, "", errors.Join(err, cleanup)
	}
	return handoff, landing.CanonicalHostname, nil
}
