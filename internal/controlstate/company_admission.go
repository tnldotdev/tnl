package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type CompanyAdmissionRequest struct {
	ID                   string    `json:"request_id"`
	TeamID               string    `json:"team_id"`
	IdentityConnectionID string    `json:"identity_connection_id"`
	ConnectionRevision   int64     `json:"connection_revision"`
	IdentityID           string    `json:"identity_id"`
	Subject              string    `json:"subject"`
	MemberSlug           string    `json:"member_slug"`
	State                string    `json:"state"`
	CreatedAt            time.Time `json:"created_at"`
}

func (d *Database) RequestCompanyAdmission(ctx context.Context, p ControlPrincipal, team, connection string, revision int64, slug string, now time.Time) (result CompanyAdmissionRequest, retErr error) {
	if !naming.ValidAuthorityLabel(slug) {
		return result, ErrMemberSlugRequired
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "request company admission", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: team, ID: connection})
	if err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	if c.State != "active" || c.Revision != revision {
		return result, ErrAuthorityConflict
	}
	var authenticated bool
	if err = tx.QueryRow(ctx, `SELECT control.company_authentication_current($1,$2,$3,$4)`, team, p.IdentityID, p.SessionID, now).Scan(&authenticated); err != nil {
		return result, err
	}
	if !authenticated {
		return result, ErrAuthorityAccess
	}
	e, err := q.GetCompanyEligibility(ctx, controlstatedb.GetCompanyEligibilityParams{IdentityConnectionID: connection, IdentityID: p.IdentityID})
	if err != nil {
		return result, publisherLookupError(err, ErrAuthorityAccess)
	}
	var tombstone bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2 AND removed_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2 AND removed_at IS NULL)`, team, p.IdentityID).Scan(&tombstone); err != nil {
		return result, err
	}
	if tombstone {
		return result, ErrAuthorityConflict
	}
	id, err := opaqueid.New("caq_")
	if err != nil {
		return result, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO control.company_admission_requests(id,team_id,identity_connection_id,connection_revision,identity_id,subject,member_slug,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8) ON CONFLICT(identity_connection_id,connection_revision,identity_id) DO UPDATE SET identity_id=EXCLUDED.identity_id RETURNING id,team_id,identity_connection_id,connection_revision,identity_id,subject,member_slug,state,created_at`, id, team, connection, revision, p.IdentityID, e.Subject, slug, now).Scan(&result.ID, &result.TeamID, &result.IdentityConnectionID, &result.ConnectionRevision, &result.IdentityID, &result.Subject, &result.MemberSlug, &result.State, &result.CreatedAt)
	if err != nil {
		return result, err
	}
	if result.Subject != e.Subject || result.MemberSlug != slug {
		return result, ErrAuthorityConflict
	}
	if c.Admission == "managed" && result.State == "pending" {
		var previousSource string
		err = tx.QueryRow(ctx, `SELECT COALESCE(identity_connection_id,'') FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2 AND removed_at IS NULL`, team, p.IdentityID).Scan(&previousSource)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		if previousSource == "" || previousSource == connection {
			if err = d.admitCompanyMember(ctx, tx, q, c, result, false, now); err != nil {
				return result, err
			}
			result.State = "approved"
			if err = companyPolicyChanged(ctx, tx, q, team, connection, p.IdentityID, p.IdentityID, "membership.managed_admission", companyAccessAuditDetails{ConnectionRevision: revision}, now); err != nil {
				return result, err
			}
		}
	}
	return result, tx.Commit(ctx)
}

func (d *Database) admitCompanyMember(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, c controlstatedb.ControlIdentityConnection, r CompanyAdmissionRequest, ownerApproved bool, now time.Time) error {
	e, err := q.GetCompanyEligibility(ctx, controlstatedb.GetCompanyEligibilityParams{IdentityConnectionID: c.ID, IdentityID: r.IdentityID})
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	if !e.Eligible || e.ConnectionRevision != c.Revision || !e.ValidUntil.Time.After(now) || e.Subject != r.Subject {
		return ErrAuthorityAccess
	}
	var member, source string
	err = tx.QueryRow(ctx, `SELECT id,COALESCE(identity_connection_id,'') FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2 AND removed_at IS NULL FOR UPDATE`, r.TeamID, r.IdentityID).Scan(&member, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		var tombstone bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2)`, r.TeamID, r.IdentityID).Scan(&tombstone); err != nil {
			return err
		}
		if tombstone {
			return ErrAuthorityConflict
		}
		if err = d.createManagedCompanyMember(ctx, tx, q, c, ProvisionCompanyEligibilityRequest{TeamID: r.TeamID, IdentityID: r.IdentityID, MemberSlug: r.MemberSlug}, now); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if source != "" && source != c.ID {
		if !ownerApproved {
			return ErrAuthorityConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE control.team_memberships SET identity_connection_id=$2,updated_at=$3 WHERE id=$1`, member, c.ID, now); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE control.company_admission_requests SET state='approved',decided_at=$2 WHERE id=$1`, r.ID, now)
	return err
}

type CompanyAdmissionPage struct {
	Requests   []CompanyAdmissionRequest `json:"requests"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

func (d *Database) ListCompanyAdmissions(ctx context.Context, p ControlPrincipal, team, after string, now time.Time) (result CompanyAdmissionPage, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list company admissions", &retErr)()
	q := controlstatedb.New(tx)
	if _, _, err = lockCompanyOwner(ctx, tx, q, p, team, now); err != nil {
		return result, err
	}
	var afterTime *time.Time
	if after != "" {
		if !opaqueid.Valid(after, "caq_") {
			return result, ErrAuthorityInvalid
		}
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT created_at FROM control.company_admission_requests WHERE team_id=$1 AND id=$2`, team, after).Scan(&at); err != nil {
			return result, publisherLookupError(err, ErrAuthorityInvalid)
		}
		afterTime = &at
	}
	rows, err := tx.Query(ctx, `SELECT id,team_id,identity_connection_id,connection_revision,identity_id,subject,member_slug,state,created_at
		FROM control.company_admission_requests WHERE team_id=$1
		AND ($2::timestamptz IS NULL OR (created_at,id COLLATE "C") > ($2,$3 COLLATE "C"))
		ORDER BY created_at,id COLLATE "C" LIMIT 101`, team, afterTime, after)
	if err != nil {
		return result, err
	}
	result.Requests = []CompanyAdmissionRequest{}
	for rows.Next() {
		if len(result.Requests) == 100 {
			result.NextCursor = result.Requests[99].ID
			break
		}
		var r CompanyAdmissionRequest
		if err = rows.Scan(&r.ID, &r.TeamID, &r.IdentityConnectionID, &r.ConnectionRevision, &r.IdentityID, &r.Subject, &r.MemberSlug, &r.State, &r.CreatedAt); err != nil {
			rows.Close()
			return result, err
		}
		result.Requests = append(result.Requests, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) DecideCompanyAdmission(ctx context.Context, p ControlPrincipal, team, request string, revision int64, decision string, now time.Time) (retErr error) {
	if decision != "approved" && decision != "denied" {
		return ErrAuthorityInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "decide company admission", &retErr)()
	q := controlstatedb.New(tx)
	_, owner, err := lockCompanyOwner(ctx, tx, q, p, team, now)
	if err != nil {
		return err
	}
	var r CompanyAdmissionRequest
	err = tx.QueryRow(ctx, `SELECT id,team_id,identity_connection_id,connection_revision,identity_id,subject,member_slug,state,created_at FROM control.company_admission_requests WHERE id=$1 AND team_id=$2 FOR UPDATE`, request, team).Scan(&r.ID, &r.TeamID, &r.IdentityConnectionID, &r.ConnectionRevision, &r.IdentityID, &r.Subject, &r.MemberSlug, &r.State, &r.CreatedAt)
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: team, ID: r.IdentityConnectionID})
	if err != nil {
		return err
	}
	if c.State != "active" || c.Revision != revision || r.ConnectionRevision != revision {
		return ErrAuthorityConflict
	}
	if decision == "approved" {
		if err = d.admitCompanyMember(ctx, tx, q, c, r, true, now); err != nil {
			return err
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE control.company_admission_requests SET state='denied',decided_at=$2 WHERE id=$1`, r.ID, now); err != nil {
			return err
		}
	}
	if err = companyPolicyChanged(ctx, tx, q, team, c.ID, owner, r.IdentityID, "membership."+decision, companyAccessAuditDetails{ConnectionRevision: revision}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) SetCompanyInvitationException(ctx context.Context, p ControlPrincipal, team, invitation string, exception bool, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "company invitation exception", &retErr)()
	q := controlstatedb.New(tx)
	_, owner, err := lockCompanyOwner(ctx, tx, q, p, team, now)
	if err != nil {
		return err
	}
	i, err := q.LockTeamInvitation(ctx, controlstatedb.LockTeamInvitationParams{TeamID: team, InvitationID: invitation})
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	if i.State != "pending" || !i.ExpiresAt.Time.After(now) {
		return ErrAuthorityConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE control.team_invitations SET personal_account_exception=$2 WHERE id=$1`, invitation, exception); err != nil {
		return err
	}
	if err = companyPolicyChanged(ctx, tx, q, team, "", owner, "", "invitation.contractor_decision", companyAccessAuditDetails{PersonalAccountException: &exception}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
