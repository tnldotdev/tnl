package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var ErrFeedbackSignInRequired = errors.New("feedback requires sign-in")

type TeamFeedbackPolicy struct {
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
