package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

type TeamFeedbackPolicy struct {
	Authors string `json:"authors"`
}

func (d *Database) GetTeamFeedbackPolicy(ctx context.Context, identityID, teamID string) (TeamFeedbackPolicy, error) {
	if _, err := d.GetTeam(ctx, identityID, teamID); err != nil {
		return TeamFeedbackPolicy{}, err
	}
	authors, err := controlstatedb.New(d.pool).VisitorFeedbackPolicy(ctx, teamID)
	return TeamFeedbackPolicy{Authors: authors}, err
}
func (d *Database) SetTeamFeedbackPolicy(ctx context.Context, identityID, teamID, authors string, now time.Time) (result TeamFeedbackPolicy, retErr error) {
	if authors != "anyone" && authors != "signed_in" && authors != "team_members" {
		return result, ErrAuthorityInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "set feedback author policy", &retErr)()
	q := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, q, identityID, teamID)
	if err != nil {
		return result, err
	}
	if actor.ActorRole != "admin" && actor.ActorRole != "owner" {
		return result, ErrAuthorityAccess
	}
	if err = q.SetVisitorFeedbackPolicy(ctx, controlstatedb.SetVisitorFeedbackPolicyParams{ID: teamID, FeedbackAuthors: authors}); err != nil {
		return result, err
	}
	return TeamFeedbackPolicy{Authors: authors}, tx.Commit(ctx)
}
func requireFeedbackAuthor(ctx context.Context, q *controlstatedb.Queries, teamID string, actor FeedbackActor) error {
	authors, err := q.VisitorFeedbackPolicy(ctx, teamID)
	if err != nil {
		return err
	}
	if authors == "anyone" {
		return nil
	}
	if actor.IdentityID == "" {
		return ErrVisitorSignIn
	}
	if authors == "team_members" {
		_, err = q.VisitorCurrentMembership(ctx, controlstatedb.VisitorCurrentMembershipParams{TeamID: teamID, IdentityID: actor.IdentityID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrFeedbackAccess
		}
		return err
	}
	return nil
}

// a guest demo has no team feedback policy. its exact URL/run and visitor IP
// checks still apply, but its feedback toolbar permits a named guest report.
func requireFeedbackAuthorForURL(ctx context.Context, q *controlstatedb.Queries, teamID, urlID string, actor FeedbackActor) error {
	if _, err := q.GuestForPublicURL(ctx, urlID); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return requireFeedbackAuthor(ctx, q, teamID, actor)
}
