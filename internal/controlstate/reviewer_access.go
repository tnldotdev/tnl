package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// lockReviewerPublicURL establishes team -> public URL -> run -> thread order.
// the shared authority guard prevents a membership or grant mutation from
// changing the decision while a reviewer write is in progress.
func lockReviewerPublicURL(ctx context.Context, queries *controlstatedb.Queries, publicURLID string) (controlstatedb.ControlPublicUrl, error) {
	candidate, err := queries.GetFeedbackPublicURL(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, ErrFeedbackAccess
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, fmt.Errorf("read reviewer public URL: %w", err)
	}
	if err := queries.LockReviewerTeam(ctx, candidate.TeamID); err != nil {
		return controlstatedb.ControlPublicUrl{}, fmt.Errorf("lock reviewer team: %w", err)
	}
	publicURL, err := queries.LockPublicURLForRun(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (publicURL.TeamID != candidate.TeamID || publicURL.LifecycleState != string(PublicURLLifecycleEnabled)) {
		return controlstatedb.ControlPublicUrl{}, ErrFeedbackAccess
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, fmt.Errorf("lock reviewer public URL: %w", err)
	}
	return publicURL, nil
}

// reviewerAccess separates verified attribution from admission. the publisher
// proves IP admission; control validates shares and current browser permission.
// the returned actor contains only transaction-validated browser attribution.
func (d *Database) reviewerAccess(ctx context.Context, queries *controlstatedb.Queries, publicURL controlstatedb.ControlPublicUrl, previewID string, actor FeedbackActor, now time.Time) (FeedbackActor, string, error) {
	if actor.Kind != "reviewer" {
		return FeedbackActor{}, "", ErrFeedbackAccess
	}
	var identity BrowserIdentity
	if len(actor.BrowserCookieSecret) != 0 {
		if len(actor.BrowserCookieSecret) != 32 {
			return FeedbackActor{}, "", ErrFeedbackAccess
		}
		digest := sha256.Sum256(actor.BrowserCookieSecret)
		var err error
		identity, err = d.browserIdentity(ctx, queries, publicURL.ID, digest[:], now)
		if errors.Is(err, ErrPreviewAccess) || err == nil && (identity.PreviewID != "" && identity.PreviewID != previewID || actor.IdentityID != "" && identity.IdentityID != actor.IdentityID) {
			return FeedbackActor{}, "", ErrFeedbackAccess
		}
		if err != nil {
			return FeedbackActor{}, "", err
		}
		actor.IdentityID, actor.DisplayName = identity.IdentityID, identity.DisplayName
	} else if actor.IdentityID != "" {
		return FeedbackActor{}, "", ErrFeedbackAccess
	}
	reference := "allowed_ip"
	allowed := actor.AllowedIP
	if !allowed && opaqueid.Valid(actor.ShareID, opaqueid.SharePrefix) && len(actor.CookieSecret) == 32 {
		digest := sha256.Sum256(actor.CookieSecret)
		_, err := queries.ReviewerShareCookieValid(ctx, controlstatedb.ReviewerShareCookieValidParams{
			ShareID: actor.ShareID, PublicURLID: publicURL.ID, TokenDigest: digest[:], Now: timestamptz(now),
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return FeedbackActor{}, "", fmt.Errorf("check reviewer share: %w", err)
		}
		allowed, reference = err == nil, actor.ShareID
	}
	if !allowed && identity.IdentityID != "" {
		var err error
		allowed, err = browserVisitAllowed(ctx, queries, publicURL, identity)
		if err != nil {
			return FeedbackActor{}, "", err
		}
	}
	if !allowed {
		return FeedbackActor{}, "", ErrFeedbackAccess
	}
	if identity.IdentityID != "" {
		reference = "identity:" + identity.IdentityID
	}
	return actor, reference, nil
}

func (d *Database) ReviewerFeedbackScope(ctx context.Context, auth PublishRunAuthentication, previewID string, actor FeedbackActor, now time.Time) (teamID, publicURLID string, retErr error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return "", "", err
	}
	if !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) {
		return "", "", ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return "", "", err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", "", fmt.Errorf("read reviewer scope: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "read reviewer scope", &retErr)()
	queries := controlstatedb.New(tx)
	publicURL, err := lockReviewerPublicURL(ctx, queries, auth.PublicURLID)
	if err != nil {
		return "", "", err
	}
	scope, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
		PublishRunID: auth.PublishRunID, PublicURLID: publicURL.ID, PreviewID: previewID,
		PublishRunNumber: int64(auth.PublishRunNumber), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (scope.PublicURLID != publicURL.ID || scope.TeamID != publicURL.TeamID) {
		return "", "", ErrFeedbackAccess
	}
	if err != nil {
		return "", "", fmt.Errorf("read reviewer preview: %w", err)
	}
	if _, _, err := d.reviewerAccess(ctx, queries, publicURL, previewID, actor, now); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit reviewer scope: %w", err)
	}
	return scope.TeamID, scope.PublicURLID, nil
}
