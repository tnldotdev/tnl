package controlstate

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func (d *Database) CreatePublisherGrant(ctx context.Context, r CreatePublisherGrantRequest) (result string, retErr error) {
	if r.ExpiresAt != nil && !r.ExpiresAt.After(r.Now) {
		return "", ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(ctx, tx, "create publisher grant", &retErr)()
	q := controlstatedb.New(tx)
	resolved, err := d.authorizePublisherScope(ctx, q, r.Scope, r.EditorID, r.EditorMembershipID, r.PolicyRevision)
	if err != nil {
		return "", err
	}
	s := resolved.publisherScope()
	i, err := q.LockPublisherIdentity(ctx, r.PublisherIdentityID)
	if err != nil {
		return "", publisherLookupError(err, ErrPublisherIdentity)
	}
	if i.TeamID != s.TeamID || i.RevokedAt.Valid || i.Kind == "guest" {
		return "", ErrPublisherIdentity
	}
	if i.Ownership == "team" {
		if s.Kind == "namespace" && s.PublicURLScope != PublicURLScopeShared {
			return "", ErrPublisherIdentity
		}
		if s.Kind == "saved_url" {
			u, err := q.LockPublicURLForRun(ctx, s.PublicURLID)
			if err != nil {
				return "", err
			}
			if u.PublicURLScope != "shared" {
				return "", ErrPublisherIdentity
			}
		}
	}
	if i.Ownership != "member" || i.OwnerMembershipID.String != r.EditorMembershipID {
		m, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: s.TeamID, IdentityID: r.EditorID})
		if err != nil {
			return "", err
		}
		if m.Role != "admin" && m.Role != "owner" {
			return "", ErrPublisherIdentity
		}
	}
	if err = rejectPublisherGroupGrantMutation(ctx, tx, i.ID); err != nil {
		return "", err
	}
	g, err := insertPublisherGrant(ctx, q, i.ID, r.EditorID, resolved, r.ExpiresAt, r.Now)
	if err != nil {
		return "", err
	}
	return g.ID, tx.Commit(ctx)
}

func (d *Database) RevokePublisherIdentity(ctx context.Context, team, id, editor string, now time.Time) (retErr error) {
	if !validStateText(editor) {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke publisher identity", &retErr)()
	if err = SetServiceAuditActor(ctx, tx, editor); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err := q.LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if err = lockPublisherPublications(ctx, tx, team, id, ""); err != nil {
		return err
	}
	if err := authorizePublisherManagement(ctx, q, team, id, editor); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT private_service_id FROM control.publisher_grants
		WHERE publisher_identity_id=$1 AND kind='private_service' AND private_service_id IS NOT NULL
		ORDER BY private_service_id`, id)
	if err != nil {
		return err
	}
	var privateServices []string
	for rows.Next() {
		var serviceID string
		if err = rows.Scan(&serviceID); err != nil {
			rows.Close()
			return err
		}
		privateServices = append(privateServices, serviceID)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, serviceID := range privateServices {
		if err = closeRevokedPrivatePublication(ctx, tx, q, serviceID, id, "", now); err != nil {
			return err
		}
	}
	if err = closeRevokedPublicPublications(ctx, tx, q, id, "", now); err != nil {
		return err
	}
	n, err := q.RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{ID: id, TeamID: team, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPublisherIdentity
	}
	if err = recordPublisherGroupMemberRevocation(ctx, tx, id, editor, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (d *Database) RevokePublisherGrant(ctx context.Context, team, id, grant, editor string, now time.Time) (retErr error) {
	if !validStateText(editor) {
		return ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke publisher grant", &retErr)()
	if err = SetServiceAuditActor(ctx, tx, editor); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err := q.LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if err = lockPublisherPublications(ctx, tx, team, id, grant); err != nil {
		return err
	}
	if err := authorizePublisherManagement(ctx, q, team, id, editor); err != nil {
		return err
	}
	selected, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: grant, PublisherIdentityID: id})
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if err = rejectProjectManagedGrant(ctx, tx, grant); err != nil {
		return err
	}
	if selected.Kind == "private_service" {
		if err = closeRevokedPrivatePublication(ctx, tx, q, selected.PrivateServiceID.String, id, grant, now); err != nil {
			return err
		}
	}
	if selected.Kind != "private_service" {
		if err = closeRevokedPublicPublications(ctx, tx, q, id, grant, now); err != nil {
			return err
		}
	}
	n, err := q.RevokePublisherGrant(ctx, controlstatedb.RevokePublisherGrantParams{ID: grant, PublisherIdentityID: id, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPublisherIdentity
	}
	return tx.Commit(ctx)
}
