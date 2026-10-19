package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

type PublisherRecord struct {
	Identity controlstatedb.ControlPublisherIdentity
	Grants   []controlstatedb.ControlPublisherGrant
	Runtime  *PublisherRuntimeStatus
}
type PublisherIdentityPage struct {
	Identities []PublisherRecord
	NextCursor string
}

func (d *Database) PublisherIdentityRecord(ctx context.Context, team, id string) (PublisherRecord, error) {
	q := controlstatedb.New(d.pool)
	i, err := q.LockPublisherIdentity(ctx, id)
	if err != nil {
		return PublisherRecord{}, err
	}
	if i.TeamID != team {
		return PublisherRecord{}, ErrPublisherIdentity
	}
	g, err := q.ListPublisherGrants(ctx, id)
	if err != nil {
		return PublisherRecord{}, err
	}
	runtime, err := publisherRuntimeStatus(ctx, q, id, time.Now())
	return PublisherRecord{Identity: i, Grants: g, Runtime: runtime}, err
}

func (d *Database) ListPublisherIdentities(ctx context.Context, team, after string) (PublisherIdentityPage, error) {
	q := controlstatedb.New(d.pool)
	rows, err := q.ListPublisherIdentities(ctx, controlstatedb.ListPublisherIdentitiesParams{TeamID: team, AfterID: after})
	if err != nil {
		return PublisherIdentityPage{}, err
	}
	page := PublisherIdentityPage{Identities: make([]PublisherRecord, 0, min(len(rows), 100))}
	for _, i := range rows[:min(len(rows), 100)] {
		grants, err := q.ListPublisherGrants(ctx, i.ID)
		if err != nil {
			return PublisherIdentityPage{}, err
		}
		runtime, err := publisherRuntimeStatus(ctx, q, i.ID, time.Now())
		if err != nil {
			return PublisherIdentityPage{}, err
		}
		page.Identities = append(page.Identities, PublisherRecord{Identity: i, Grants: grants, Runtime: runtime})
	}
	if len(rows) > 100 {
		page.NextCursor = rows[99].ID
	}
	return page, nil
}

// management requires current team authority. a member can manage only the
// identity they enrolled; team admins can revoke a durable grant after its
// issuing member leaves. this check does not affect grant use.
func (d *Database) AuthorizePublisherManagement(ctx context.Context, team, publisher, editor string) error {
	q := controlstatedb.New(d.pool)
	return authorizePublisherManagement(ctx, q, team, publisher, editor)
}

// mutation callers hold the team guard through commit before reading current
// membership and locking the publisher. a prior HTTP read is not authorization.
func authorizePublisherManagement(ctx context.Context, q *controlstatedb.Queries, team, publisher, editor string) error {
	if err := requireTeamSession(ctx, q, team, editor, time.Now()); err != nil {
		if errors.Is(err, ErrAuthorityAccess) {
			return ErrPublisherIdentity
		}
		return err
	}
	m, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: team, IdentityID: editor})
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	i, err := q.LockPublisherIdentity(ctx, publisher)
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if i.TeamID != team || (i.Ownership != "member" || i.OwnerMembershipID.String != m.ID) && m.Role != "owner" && m.Role != "admin" {
		return ErrPublisherIdentity
	}
	return nil
}
