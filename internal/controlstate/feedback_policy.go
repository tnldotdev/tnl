package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var ErrFeedbackSignInRequired = errors.New("feedback requires sign-in")

type TeamFeedbackPolicy struct {
	RequireSignIn bool
}

type FeedbackAccess struct {
	RequireSignIn bool
}

func (d *Database) GetTeamFeedbackPolicy(ctx context.Context, identityID, teamID string) (TeamFeedbackPolicy, error) {
	if !validStateText(identityID) || !validStateText(teamID) {
		return TeamFeedbackPolicy{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return TeamFeedbackPolicy{}, err
	}
	required, err := controlstatedb.New(d.pool).GetIdentityTeamFeedbackPolicy(ctx, controlstatedb.GetIdentityTeamFeedbackPolicyParams{IdentityID: identityID, TeamID: teamID})
	if errors.Is(err, pgx.ErrNoRows) {
		return TeamFeedbackPolicy{}, ErrTeamNotFound
	}
	if err != nil {
		return TeamFeedbackPolicy{}, fmt.Errorf("read team feedback policy: %w", err)
	}
	return TeamFeedbackPolicy{RequireSignIn: required}, nil
}

func (d *Database) SetTeamFeedbackPolicy(ctx context.Context, identityID, teamID string, requireSignIn bool, now time.Time) (result TeamFeedbackPolicy, retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || now.IsZero() {
		return TeamFeedbackPolicy{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return TeamFeedbackPolicy{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return TeamFeedbackPolicy{}, fmt.Errorf("set team feedback policy: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "set team feedback policy", &retErr)()
	queries := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return TeamFeedbackPolicy{}, err
	}
	if actor.ActorRole != string(TeamRoleOwner) && actor.ActorRole != string(TeamRoleAdmin) {
		return TeamFeedbackPolicy{}, ErrAuthorityAccess
	}
	required, err := queries.SetTeamFeedbackPolicy(ctx, controlstatedb.SetTeamFeedbackPolicyParams{
		TeamID: teamID, RequireSignIn: requireSignIn, UpdatedAt: timestamp(now),
	})
	if err != nil {
		return TeamFeedbackPolicy{}, fmt.Errorf("save team feedback policy: %w", err)
	}
	// feedback policy applies live; changing it does not replace publish runs or
	// advance publishing authorization revisions.
	if err := tx.Commit(ctx); err != nil {
		return TeamFeedbackPolicy{}, fmt.Errorf("commit team feedback policy: %w", err)
	}
	return TeamFeedbackPolicy{RequireSignIn: required}, nil
}

// callers hold the shared team guard and have normalized current reviewer access.
func requireFeedbackIdentity(ctx context.Context, queries *controlstatedb.Queries, teamID string, actor FeedbackActor) error {
	required, err := queries.GetReviewerFeedbackPolicy(ctx, teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrFeedbackAccess
	}
	if err != nil {
		return fmt.Errorf("read feedback write policy: %w", err)
	}
	if required && actor.IdentityID == "" {
		return ErrFeedbackSignInRequired
	}
	return nil
}

// ReviewerFeedbackAccess reads live policy for an existing preview and public
// URL. sign-in policy controls writes only; ordinary reviewer access is required.
func (d *Database) ReviewerFeedbackAccess(ctx context.Context, auth PublishRunAuthentication, previewID string, actor FeedbackActor, now time.Time) (result FeedbackAccess, retErr error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return FeedbackAccess{}, err
	}
	if !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) {
		return FeedbackAccess{}, ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackAccess{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return FeedbackAccess{}, fmt.Errorf("read feedback access: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "read feedback access", &retErr)()
	queries := controlstatedb.New(tx)
	publicURL, err := lockReviewerPublicURL(ctx, queries, auth.PublicURLID)
	if err != nil {
		return FeedbackAccess{}, err
	}
	scope, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
		PublishRunID: auth.PublishRunID, PublicURLID: publicURL.ID, PreviewID: previewID,
		PublishRunNumber: int64(auth.PublishRunNumber), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (scope.PublicURLID != publicURL.ID || scope.TeamID != publicURL.TeamID) {
		return FeedbackAccess{}, ErrFeedbackAccess
	}
	if err != nil {
		return FeedbackAccess{}, fmt.Errorf("read feedback access scope: %w", err)
	}
	if _, _, err := d.reviewerAccess(ctx, queries, publicURL, previewID, actor, now); err != nil {
		return FeedbackAccess{}, err
	}
	required, err := queries.GetReviewerFeedbackPolicy(ctx, scope.TeamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedbackAccess{}, ErrFeedbackAccess
	}
	if err != nil {
		return FeedbackAccess{}, fmt.Errorf("read feedback access policy: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedbackAccess{}, fmt.Errorf("commit feedback access: %w", err)
	}
	return FeedbackAccess{RequireSignIn: required}, nil
}
