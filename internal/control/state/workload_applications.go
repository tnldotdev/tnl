package state

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// trusted apply resolves human-readable selectors and reconciles one application
// per workload. federation proves identity; these ordinary application grants
// remain the only durable visit, publish and allocation permissions.
func (d *Database) reconcileWorkloadApplications(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, c ProjectConfiguration) error {
	q := controlstatedb.New(tx)
	member, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: r.TeamID, IdentityID: r.ActorID})
	if err != nil {
		return publisherLookupError(err, ErrApplicationRegistration)
	}
	if err := requireTeamSession(ctx, q, r.TeamID, r.ActorID, r.Now); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id,workload_name,publisher_identity_id FROM control.workload_applications WHERE team_id=$1 AND project_key=$2 AND revoked_at IS NULL ORDER BY workload_name`, r.TeamID, r.ProjectKey)
	if err != nil {
		return err
	}
	type binding struct{ id, name, application string }
	bindings := map[string]binding{}
	for rows.Next() {
		var b binding
		if err := rows.Scan(&b.id, &b.name, &b.application); err != nil {
			rows.Close()
			return err
		}
		bindings[b.name] = b
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	retire := func(b binding) error {
		if _, err := tx.Exec(ctx, `UPDATE control.workload_sessions SET revoked_at=$2 WHERE revoked_at IS NULL AND id IN (SELECT workload_session_id FROM control.publisher_identity_keys WHERE workload_binding_id=$1)`, b.id, r.Now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.workload_applications SET revoked_at=$2 WHERE id=$1`, b.id, r.Now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE publisher_identity_id=$1 AND revoked_at IS NULL`, b.application, r.Now); err != nil {
			return err
		}
		_, err := q.RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{ID: b.application, TeamID: r.TeamID, Now: timestamptz(r.Now)})
		return err
	}
	for _, name := range sortedProjectKeys(bindings) {
		if _, ok := c.Workloads[name]; !ok {
			if err := retire(bindings[name]); err != nil {
				return err
			}
		}
	}
	for _, name := range sortedProjectKeys(c.Workloads) {
		policy := c.Workloads[name]
		ownership := policy.Ownership
		if ownership == "" {
			ownership = "member"
		}
		if ownership == "team" && member.Role != "owner" && member.Role != "admin" {
			return ErrApplicationRegistration
		}
		b := bindings[name]
		if b.application != "" {
			app, err := q.LockPublisherIdentity(ctx, b.application)
			if err != nil {
				return err
			}
			if app.Kind != "application" || app.RevokedAt.Valid {
				return ErrApplicationRegistration
			}
			if app.Ownership != ownership {
				if err := retire(b); err != nil {
					return err
				}
				b = binding{}
			}
		}
		// authorization precedes grant persistence, including for existing grants.
		var desired []applicationGrantScope
		for _, operation := range []ApplicationOperation{ApplicationVisit, ApplicationPublish} {
			resources := policy.Grants.Visit
			if operation == ApplicationPublish {
				resources = policy.Grants.Publish
			}
			for _, resource := range resources {
				scope := PublisherScope{TeamID: r.TeamID}
				if resource.Service != nil {
					scope.Kind = "service"
					err = tx.QueryRow(ctx, `SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND service_id IS NOT NULL`, r.TeamID, r.ProjectKey, *resource.Service).Scan(&scope.ServiceID)
				} else {
					scope.Kind = "saved_public_url"
					err = tx.QueryRow(ctx, `SELECT id FROM control.public_urls WHERE team_id=$1 AND canonical_hostname=$2 AND lifecycle_state='enabled' AND NOT ephemeral`, r.TeamID, *resource.PublicURL).Scan(&scope.PublicURLID)
				}
				if err != nil {
					return publisherLookupError(err, ErrApplicationRegistration)
				}
				resolved, err := d.authorizeApplicationGrant(ctx, q, ApplicationGrantRequest{Operation: operation, Scope: scope}, r.ActorID, member, ownership, r.Now)
				if err != nil {
					return err
				}
				desired = append(desired, resolved)
			}
		}
		for _, allocation := range policy.Grants.Allocate {
			scope := PublisherScope{TeamID: r.TeamID, Kind: "namespace"}
			if err := tx.QueryRow(ctx, `SELECT id FROM control.domains WHERE (team_id=$1 OR kind='managed') AND canonical_domain=$2 AND state='ready'`, r.TeamID, allocation.Domain).Scan(&scope.DomainID); err != nil {
				return publisherLookupError(err, ErrApplicationRegistration)
			}
			resolved, err := d.authorizeApplicationGrant(ctx, q, ApplicationGrantRequest{Operation: ApplicationAllocate, Scope: scope}, r.ActorID, member, ownership, r.Now)
			if err != nil {
				return err
			}
			desired = append(desired, resolved)
		}
		if b.application == "" {
			application, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
			if err != nil {
				return err
			}
			owner := ""
			if ownership == "member" {
				owner = member.ID
			}
			if _, err := q.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{ID: application, TeamID: r.TeamID, Name: name, Kind: "application", CreatedByIdentityID: r.ActorID, Ownership: ownership, OwnerMembershipID: nullableText(owner), CreatedAt: timestamptz(r.Now)}); err != nil {
				return err
			}
			id, err := opaqueid.New("wla_")
			if err != nil {
				return err
			}
			b = binding{id, name, application}
			if _, err := tx.Exec(ctx, `INSERT INTO control.workload_applications(id,team_id,project_key,workload_name,publisher_identity_id,created_at) VALUES($1,$2,$3,$4,$5,$6)`, b.id, r.TeamID, r.ProjectKey, name, b.application, r.Now); err != nil {
				return err
			}
		}
		existing, err := q.ListPublisherGrants(ctx, b.application)
		if err != nil {
			return err
		}
		type grantKey struct {
			operation ApplicationOperation
			scope     PublisherScope
		}
		wanted := map[grantKey]bool{}
		for _, grant := range desired {
			wanted[grantKey{grant.operation, grant.publisherScope()}] = true
		}
		for _, grant := range existing {
			if grant.RevokedAt.Valid {
				continue
			}
			key := grantKey{ApplicationOperation(grant.Operation), scopeFromGrant(r.TeamID, grant)}
			if wanted[key] && (!grant.ExpiresAt.Valid || grant.ExpiresAt.Time.After(r.Now)) {
				delete(wanted, key)
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, grant.ID, r.Now); err != nil {
				return err
			}
		}
		for _, grant := range desired {
			key := grantKey{grant.operation, grant.publisherScope()}
			if !wanted[key] {
				continue
			}
			if _, err := insertPublisherGrant(ctx, q, b.application, r.ActorID, grant, nil, r.Now); err != nil {
				return err
			}
			delete(wanted, key)
		}
		if len(wanted) != 0 {
			return ErrApplicationRegistration
		}
	}
	return nil
}
