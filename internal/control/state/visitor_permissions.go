package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type HTTPVisitorRequest struct {
	SourceIP, BrowserCookieSecret, ShareID string
	ShareCookieSecret, ShareSecret         []byte
}

func (d *Database) httpVisitorDecision(ctx context.Context, q *controlstatedb.Queries, url controlstatedb.ControlPublicUrl, input HTTPVisitorRequest, now time.Time) (VisitorPermission, error) {
	result := VisitorPermission{}
	ip, ipExpires, err := d.visitorIPAllowed(ctx, q, url, input.SourceIP, now)
	if err != nil || !ip {
		return result, err
	}
	result.ExpiresAt = ipExpires
	if input.BrowserCookieSecret != "" {
		verified, verifyErr := d.browserPermission(ctx, q, url.ID, input.BrowserCookieSecret, now)
		if verifyErr == nil {
			result = verified
			if ipExpires != nil {
				result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, *ipExpires)
			}
		} else {
			return result, verifyErr
		}
	}
	if result.VisitAllowed {
		return result, nil
	}
	if len(input.ShareSecret) == 32 {
		share, lookupErr := q.GetActiveShareForPublicURL(ctx, controlstatedb.GetActiveShareForPublicURLParams{
			ShareID: input.ShareID, PublicURLID: url.ID, Now: timestamptz(now),
		})
		if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
			return result, lookupErr
		}
		if lookupErr == nil {
			digest := sha256.Sum256(input.ShareSecret)
			if subtle.ConstantTimeCompare(digest[:], share.SecretDigest) == 1 {
				result.VisitAllowed, result.Reason = true, "anonymous_share"
				result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, share.ExpiresAt.Time)
				return result, nil
			}
		}
	}
	if !result.VisitAllowed && len(input.ShareCookieSecret) == 32 {
		digest := sha256.Sum256(input.ShareCookieSecret)
		expires, lookupErr := q.ReviewerShareCookieValid(ctx, controlstatedb.ReviewerShareCookieValidParams{ShareID: input.ShareID, PublicURLID: url.ID, TokenDigest: digest[:], Now: timestamptz(now)})
		err = lookupErr
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		if err == nil {
			result.VisitAllowed = true
			result.Reason = "anonymous_share"
			result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, expires.Time)
		}
	}
	if input.ShareID == "" && len(input.ShareSecret) == 0 && len(input.ShareCookieSecret) == 0 && (input.BrowserCookieSecret == "" || result.Authenticated) && url.AccessMode == string(VisitorAccessAnonymous) {
		result.VisitAllowed, result.Reason = true, "anonymous"
	}
	return result, nil
}

func (d *Database) HTTPVisitorPermission(ctx context.Context, auth PublishRunAuthentication, input HTTPVisitorRequest, now time.Time) (result VisitorPermission, retErr error) {
	// HTTP chooses one credential before authorization. feedback may separately
	// verify an author and a URL-scoped share; it retains its own actor boundary.
	if input.BrowserCookieSecret != "" && (input.ShareID != "" || len(input.ShareSecret) != 0 || len(input.ShareCookieSecret) != 0) || len(input.ShareSecret) != 0 && len(input.ShareCookieSecret) != 0 {
		return result, ErrVisitorSignIn
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize HTTP visitor", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, auth.PublicURLID)
	if err != nil {
		return result, err
	}
	if url.ServiceProtocol != "http" {
		return result, ErrPreviewAccess
	}
	run, err := d.lockAuthenticatedRun(ctx, q, auth, now)
	if err != nil {
		return result, err
	}
	result, err = d.httpVisitorDecision(ctx, q, url, input, now)
	if err != nil {
		return result, err
	}
	if result.VisitAllowed {
		result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, run.PublisherExpiresAt.Time)
		result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, now.Add(2*time.Minute))
	}
	return result, tx.Commit(ctx)
}

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

// lockVisitorURL follows team -> URL -> run -> session -> identity lock order.
// grant and membership mutations take the same team lock.
func lockVisitorURL(ctx context.Context, q *controlstatedb.Queries, id string) (controlstatedb.ControlPublicUrl, error) {
	candidate, err := q.GetFeedbackPublicURL(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return candidate, ErrPreviewAccess
	}
	if err != nil {
		return candidate, err
	}
	if candidate.Purpose == string(PublicURLPurposeDemo) {
		// guest trials have a trial-owned team ID, not a team membership row.
		// require the exact guest ownership link before accepting that boundary;
		// lockAuthenticatedRun checks the trial's live run in this transaction.
		guestID, guestErr := q.GuestForPublicURL(ctx, id)
		if errors.Is(guestErr, pgx.ErrNoRows) || guestErr == nil && guestID != candidate.CreatedByIdentityID {
			return candidate, ErrPreviewAccess
		}
		if guestErr != nil {
			return candidate, guestErr
		}
	} else if _, err = q.LockLocalTeamForMutation(ctx, candidate.TeamID); errors.Is(err, pgx.ErrNoRows) {
		return candidate, ErrPreviewAccess
	} else if err != nil {
		return candidate, err
	}
	row, err := q.LockPublicURLForRun(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.TeamID != candidate.TeamID || row.LifecycleState != "enabled") {
		return row, ErrPreviewAccess
	}
	return row, err
}

func identityPermission(ctx context.Context, q *controlstatedb.Queries, urlID, identityID, previewID string, now time.Time) (VisitorPermission, error) {
	result := VisitorPermission{}
	if identityID == "" {
		return result, nil
	}
	identity, err := q.LockVisitorIdentity(ctx, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrVisitorSignIn
	}
	if err != nil {
		return result, err
	}
	result.IdentityID, result.DisplayName = identity.ID, identity.DisplayName
	url, err := q.GetFeedbackPublicURL(ctx, urlID)
	if err != nil {
		return result, err
	}
	allowed, err := q.CompanySubjectSessionAuthorized(ctx, controlstatedb.CompanySubjectSessionAuthorizedParams{TeamID: url.TeamID, IdentityID: identityID, SessionID: companySessionID(ctx, identityID), Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	if !allowed {
		active, err := q.ActiveTeamSubject(ctx, controlstatedb.ActiveTeamSubjectParams{TeamID: url.TeamID, IdentityID: identityID, Now: timestamptz(now)})
		if err != nil {
			return result, err
		}
		if !active {
			return result, nil
		}
		return result, ErrVisitorSignIn
	}
	result.Authenticated = true
	_, err = q.VisitorCurrentMembership(ctx, controlstatedb.VisitorCurrentMembershipParams{TeamID: url.TeamID, IdentityID: identityID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	result.TeamMember = err == nil
	row, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: "public_url", ResourceID: urlID, IdentityID: identityID, ControlSessionID: companySessionID(ctx, identityID), PreviewID: previewID, Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.VisitAllowed, result.Reason = true, row.Reason
	if row.ExpiresAt.InfinityModifier != pgtype.Infinity {
		result.ExpiresAt = optionalTime(row.ExpiresAt)
	}
	deadline, err := q.CompanySubjectDeadline(ctx, controlstatedb.CompanySubjectDeadlineParams{TeamID: url.TeamID, IdentityID: identityID, SessionID: companySessionID(ctx, identityID), Now: timestamptz(now)})
	if err != nil {
		return VisitorPermission{}, err
	}
	if deadline.InfinityModifier == 0 {
		result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, deadline.Time)
	}
	return result, nil
}

// currentVisitorSession checks the local control session inside the decision
// transaction. authority HTTP refresh must finish before this boundary.
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

func (d *Database) browserPermission(ctx context.Context, q *controlstatedb.Queries, urlID, token string, now time.Time) (VisitorPermission, error) {
	digest, err := browserDigest(token)
	if err != nil {
		return VisitorPermission{}, ErrVisitorSignIn
	}
	row, err := q.LockBrowserAccessSession(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now)) {
		return VisitorPermission{}, ErrVisitorSignIn
	}
	if err != nil {
		return VisitorPermission{}, err
	}
	if _, err = q.BrowserSessionCurrentHost(ctx, controlstatedb.BrowserSessionCurrentHostParams{SessionDigest: digest, PublicURLID: urlID, PublisherExpiresAt: timestamptz(now)}); errors.Is(err, pgx.ErrNoRows) {
		return VisitorPermission{}, ErrVisitorSignIn
	} else if err != nil {
		return VisitorPermission{}, err
	}
	access, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(digest), row.AccessCiphertext)
	if err != nil {
		return VisitorPermission{}, err
	}
	sessionExpires, err := currentVisitorSession(ctx, q, string(access), row.IdentityID, row.ParentControlSessionID.String, now)
	if err != nil {
		return VisitorPermission{}, err
	}
	accessID, _, err := credentials.ParseAccessToken(credentials.AccessToken(access))
	if err != nil {
		return VisitorPermission{}, ErrVisitorSignIn
	}
	controlSession, err := q.LockVisitorControlSession(ctx, accessID.String())
	if err != nil {
		return VisitorPermission{}, err
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{SessionID: controlSession.ID, IdentityID: row.IdentityID})
	result, err := identityPermission(ctx, q, urlID, row.IdentityID, row.PreviewID.String, now)
	if err != nil {
		return result, err
	}
	result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, sessionExpires)
	result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, row.ExpiresAt.Time)
	return result, nil
}

// BrowserAuthorizationForRun is the final decision after any identity-provider
// I/O. it holds the run through the session, identity, membership and grant checks.
func (d *Database) BrowserAuthorizationForRun(ctx context.Context, auth PublishRunAuthentication, token string, now time.Time) (result VisitorPermission, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize browser visitor", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, auth.PublicURLID)
	if err != nil {
		return result, err
	}
	if url.Purpose != "app" && url.Purpose != "alias" || url.ServiceProtocol != "http" {
		return result, ErrPreviewAccess
	}
	if _, err = d.lockAuthenticatedRun(ctx, q, auth, now); err != nil {
		return result, err
	}
	result, err = d.browserPermission(ctx, q, url.ID, token, now)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return VisitorPermission{}, err
	}
	return result, nil
}

func (d *Database) lockAuthenticatedRun(ctx context.Context, q *controlstatedb.Queries, auth PublishRunAuthentication, now time.Time) (controlstatedb.ControlPublishRun, error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return controlstatedb.ControlPublishRun{}, err
	}
	run, err := q.LockPublishRun(ctx, auth.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrPublishRunStale
	}
	if err != nil {
		return run, err
	}
	if run.PublicURLID != auth.PublicURLID || uint64(run.PublishRunNumber) != auth.PublishRunNumber || run.ClosedAt.Valid ||
		!run.PublisherExpiresAt.Time.After(now) || run.State != "ready" {
		return run, ErrPublishRunStale
	}
	tokenID, digest, err := credentials.ParsePublishRunToken(auth.PublishRunToken)
	if err != nil || tokenID.String() != run.PublishRunTokenID || !credentials.SecretHashMatches(run.PublishRunTokenDigest, digest) {
		return run, ErrPublishRunCredential
	}
	url, err := q.GetFeedbackPublicURL(ctx, auth.PublicURLID)
	if err != nil {
		return run, err
	}
	live, err := d.publisherRunLive(ctx, q, url, run.ID, now)
	if err != nil {
		return run, err
	}
	if !live {
		return run, ErrPublishRunStale
	}
	return run, nil
}
