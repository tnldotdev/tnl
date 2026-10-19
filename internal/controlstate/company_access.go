package controlstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const CompanyAuthenticationLifetime = time.Hour
const CompanyEligibilityLifetime = 24 * time.Hour

func nullableRevision(revision int64) pgtype.Int8 {
	return pgtype.Int8{Int64: revision, Valid: revision > 0}
}

type controlPrincipalKey struct{}

// WithControlPrincipal carries only a principal authenticated by control.
// callers must never build this value from HTTP fields or linked account metadata.
func WithControlPrincipal(ctx context.Context, principal ControlPrincipal) context.Context {
	return context.WithValue(ctx, controlPrincipalKey{}, principal)
}

func companySessionID(ctx context.Context, identity string) string {
	p, _ := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
	if p.IdentityID != identity {
		return ""
	}
	return p.SessionID
}

func requireTeamSession(ctx context.Context, q *controlstatedb.Queries, team, identity string, now time.Time) error {
	allowed, err := q.CompanySessionAuthorized(ctx, controlstatedb.CompanySessionAuthorizedParams{
		TeamID: team, IdentityID: identity, SessionID: companySessionID(ctx, identity), Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if !allowed {
		return ErrAuthorityAccess
	}
	return nil
}

func (d *Database) AuthorizeTeamSession(ctx context.Context, p ControlPrincipal, team string, now time.Time) error {
	return requireTeamSession(WithControlPrincipal(ctx, p), controlstatedb.New(d.pool), team, p.IdentityID, now)
}

type IdentityConnection struct {
	ID        string `json:"identity_connection_id"`
	TeamID    string `json:"team_id"`
	Issuer    string `json:"issuer"`
	Admission string `json:"admission"`
	State     string `json:"state"`
	Revision  int64  `json:"revision"`
	SourceID  string `json:"source_id"`
}

type CreateIdentityConnectionRequest struct {
	TeamID           string
	Issuer           string
	Admission        string
	ReplaceID        string
	ExpectedRevision int64
	SourceID         string
}

type IdentityConnectionSecret struct {
	IdentityConnection
	ProvisioningToken string `json:"provisioning_token"`
}

type IdentityConnectionSetup struct {
	IdentityConnection
	SetupToken string    `json:"setup_token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func connectionFromRow(c controlstatedb.ControlIdentityConnection) IdentityConnection {
	return IdentityConnection{ID: c.ID, TeamID: c.TeamID, Issuer: c.Issuer, SourceID: c.SourceID, Admission: c.Admission, State: c.State, Revision: c.Revision}
}

// BeginIdentityConnectionSetup leaves current access untouched until verified
// tenant consent activates this exact pending connection.
func (d *Database) BeginIdentityConnectionSetup(ctx context.Context, p ControlPrincipal, r CreateIdentityConnectionRequest, now time.Time) (result IdentityConnectionSetup, retErr error) {
	if !validStateText(r.TeamID) || !validStateText(r.Issuer) || !validStateText(r.SourceID) || len(r.SourceID) > 256 || len(r.Issuer) > 2048 || (r.Admission != "approval" && r.Admission != "managed") || now.IsZero() {
		return result, ErrAuthorityInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create identity connection", &retErr)()
	q := controlstatedb.New(tx)
	actor, ownerID, err := lockCompanyOwner(WithControlPrincipal(ctx, p), tx, q, p, r.TeamID, now)
	if err != nil {
		return result, err
	}
	if actor.Kind != "organization" || actor.ActorRole != "owner" {
		return result, ErrAuthorityAccess
	}
	var current string
	err = tx.QueryRow(ctx, `SELECT id FROM control.identity_connections WHERE team_id=$1 AND state='active'`, r.TeamID).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if current != "" {
		if current != r.ReplaceID {
			return result, ErrAuthorityConflict
		}
		c, e := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: r.TeamID, ID: current})
		if e != nil {
			return result, e
		}
		if c.Revision != r.ExpectedRevision {
			return result, ErrAuthorityConflict
		}
	} else if r.ReplaceID != "" || r.ExpectedRevision != 0 {
		return result, ErrAuthorityConflict
	}
	id, err := opaqueid.New("icn_")
	if err != nil {
		return result, err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return result, err
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(token))
	if _, err = tx.Exec(ctx, `UPDATE control.identity_connections SET state='retired',revision=revision+1,updated_at=$2 WHERE team_id=$1 AND state='pending' AND setup_expires_at<=$2`, r.TeamID, now); err != nil {
		return result, err
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.identity_connections WHERE team_id=$1 AND state='pending')`, r.TeamID).Scan(&pending); err != nil {
		return result, err
	}
	if pending {
		return result, ErrAuthorityConflict
	}
	until := now.Add(15 * time.Minute)
	_, err = tx.Exec(ctx, `INSERT INTO control.identity_connections(id,team_id,issuer,source_id,admission,state,provisioning_digest,setup_digest,setup_expires_at,replaces_id,replaces_revision,created_by_identity_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'pending',$6,$6,$7,$8,$9,$10,$11,$11)`, id, r.TeamID, r.Issuer, r.SourceID, r.Admission, digest[:], until, nullableText(r.ReplaceID), nullableRevision(r.ExpectedRevision), ownerID, now)
	if err != nil {
		return result, err
	}
	if err = q.InsertCompanyAccessAudit(ctx, controlstatedb.InsertCompanyAccessAuditParams{TeamID: r.TeamID, IdentityConnectionID: text(id), ActorIdentityID: text(ownerID), Operation: "connection.setup", Revision: actor.PolicyRevision, Now: timestamptz(now), Details: `{"state":"pending"}`}); err != nil {
		return result, err
	}
	result = IdentityConnectionSetup{IdentityConnection: IdentityConnection{ID: id, TeamID: r.TeamID, Issuer: r.Issuer, SourceID: r.SourceID, Admission: r.Admission, State: "pending", Revision: 1}, SetupToken: token, ExpiresAt: until}
	return result, tx.Commit(ctx)
}

func (d *Database) DisconnectIdentityConnection(ctx context.Context, p ControlPrincipal, team, id string, revision int64, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "set identity connection state", &retErr)()
	q := controlstatedb.New(tx)
	a, ownerID, err := lockCompanyOwner(WithControlPrincipal(ctx, p), tx, q, p, team, now)
	if err != nil {
		return err
	}
	if a.Kind != "organization" || a.ActorRole != "owner" {
		return ErrAuthorityAccess
	}
	c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: team, ID: id})
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	if c.Revision != revision || c.State == "retired" {
		return ErrAuthorityConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE control.identity_connections SET state='retired',revision=revision+1,updated_at=$2 WHERE id=$1`, id, now); err != nil {
		return err
	}
	if c.State == "pending" {
		return tx.Commit(ctx)
	}
	if err = companyPolicyChanged(ctx, tx, q, team, id, ownerID, "", "connection.disconnect", companyAccessAuditDetails{ConnectionRevision: c.Revision + 1, State: "retired"}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type ProvisionCompanyEligibilityRequest struct {
	TeamID               string    `json:"team_id"`
	IdentityConnectionID string    `json:"identity_connection_id"`
	ConnectionRevision   int64     `json:"connection_revision"`
	IdentityID           string    `json:"identity_id"`
	Subject              string    `json:"subject"`
	Revision             int64     `json:"revision"`
	Eligible             bool      `json:"eligible"`
	ValidUntil           time.Time `json:"valid_until"`
	MemberSlug           string    `json:"member_slug"`
}

// ProvisionCompanyEligibility is a narrow delta, never an authoritative list.
// a source cannot assign roles, edit manual decisions, or revive a tombstone.
func (d *Database) ProvisionCompanyEligibility(ctx context.Context, token string, r ProvisionCompanyEligibilityRequest, now time.Time) (retErr error) {
	defer func() {
		var constraint *pgconn.PgError
		if errors.As(retErr, &constraint) && (constraint.Code == "23505" || constraint.Code == "23503") {
			retErr = errors.Join(ErrAuthorityConflict, retErr)
		}
	}()
	if !validStateText(r.IdentityID) || !validStateText(r.Subject) || len(r.Subject) > 256 || r.Revision < 1 || r.ConnectionRevision < 1 || !r.ValidUntil.After(now) || r.ValidUntil.After(now.Add(CompanyEligibilityLifetime)) || now.IsZero() {
		return ErrAuthorityInvalid
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "provision company eligibility", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	c, err := q.LockIdentityConnection(ctx, controlstatedb.LockIdentityConnectionParams{TeamID: r.TeamID, ID: r.IdentityConnectionID})
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	actual := sha256.Sum256([]byte(token))
	if token == "" || subtle.ConstantTimeCompare(actual[:], c.ProvisioningDigest) != 1 || (c.State != "active" && c.State != "pending") || c.State == "pending" && !c.SetupExpiresAt.Time.After(now) {
		return ErrAuthorityAccess
	}
	if c.Revision != r.ConnectionRevision {
		return ErrAuthorityConflict
	}
	previous, err := q.GetCompanyEligibility(ctx, controlstatedb.GetCompanyEligibilityParams{IdentityConnectionID: c.ID, IdentityID: r.IdentityID})
	unchangedAuthorization := err == nil && previous.ConnectionRevision == c.Revision && previous.Eligible == r.Eligible &&
		(!r.Eligible || previous.ValidUntil.Time.After(now) && !r.ValidUntil.Before(previous.ValidUntil.Time))
	if err == nil {
		if previous.Subject != r.Subject {
			return ErrAuthorityConflict
		}
		if previous.Revision == r.Revision {
			if !bytes.Equal(previous.RequestDigest, digest[:]) {
				return ErrAuthorityIdempotency
			}
			return tx.Commit(ctx)
		}
		if previous.Revision > r.Revision {
			return ErrAuthorityConflict
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var identity string
	if err = tx.QueryRow(ctx, `SELECT id FROM control.identities WHERE id=$1 AND disabled_at IS NULL`, r.IdentityID).Scan(&identity); err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	// eligibility belongs to the connection, independently of membership binding.
	// any historical membership also prevents automatic creation: only an owner
	// admission decision can rebind a nonremoved membership from another source.
	var member string
	err = tx.QueryRow(ctx, `SELECT id FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2 ORDER BY (removed_at IS NULL) DESC,created_at DESC,id DESC LIMIT 1`, r.TeamID, r.IdentityID).Scan(&member)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if member == "" && r.Eligible && c.Admission == "managed" && c.State == "active" {
		unchangedAuthorization = false
		if !naming.ValidAuthorityLabel(r.MemberSlug) {
			return ErrMemberSlugRequired
		}
		if err = d.createManagedCompanyMember(ctx, tx, q, c, r, now); err != nil {
			return err
		}
	}
	if err = q.PutCompanyEligibility(ctx, controlstatedb.PutCompanyEligibilityParams{IdentityConnectionID: c.ID, TeamID: r.TeamID, IdentityID: r.IdentityID, Subject: r.Subject, ConnectionRevision: c.Revision, Revision: r.Revision, Eligible: r.Eligible, ValidUntil: timestamptz(r.ValidUntil), RequestDigest: digest[:], Now: timestamptz(now)}); err != nil {
		return err
	}
	details := companyAccessAuditDetails{ConnectionRevision: c.Revision, EligibilityRevision: r.Revision, Eligible: &r.Eligible, ValidUntil: &r.ValidUntil}
	if c.State == "pending" {
		return tx.Commit(ctx)
	}
	if unchangedAuthorization {
		// extending already-current eligibility does not disconnect healthy
		// visitors. the source revision and outcome remain independently audited.
		revision, err := q.GetVisitorPolicyRevision(ctx, r.TeamID)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(details)
		if err != nil {
			return err
		}
		if err = q.InsertCompanyAccessAudit(ctx, controlstatedb.InsertCompanyAccessAuditParams{TeamID: r.TeamID, IdentityConnectionID: text(c.ID), TargetIdentityID: text(r.IdentityID), Operation: "eligibility.refresh", Revision: revision, Now: timestamptz(now), Details: string(encoded)}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err = companyPolicyChanged(ctx, tx, q, r.TeamID, c.ID, "", r.IdentityID, "eligibility.update", details, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) createManagedCompanyMember(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, c controlstatedb.ControlIdentityConnection, r ProvisionCompanyEligibilityRequest, now time.Time) error {
	occupied, err := q.TeamSharedNameInUse(ctx, controlstatedb.TeamSharedNameInUseParams{TeamID: r.TeamID, Label: r.MemberSlug})
	if err != nil {
		return err
	}
	if occupied {
		return ErrAuthorityConflict
	}
	id, err := opaqueid.New(opaqueid.MembershipPrefix)
	if err != nil {
		return err
	}
	sid, err := opaqueid.New(opaqueid.SlugReservationPrefix)
	if err != nil {
		return err
	}
	label := ""
	if d.managedURLMode == naming.ManagedURLModeSimple {
		var teamName string
		if err = tx.QueryRow(ctx, `SELECT display_name FROM control.teams WHERE id=$1`, r.TeamID).Scan(&teamName); err != nil {
			return err
		}
		label, err = availablePersonalTeamName(ctx, q, r.MemberSlug+"-"+teamName, now)
		if err != nil {
			return err
		}
	} else {
		label, err = availableManagedLabel(ctx, q, now)
		if err != nil {
			return err
		}
	}
	if err = q.CreateActiveSlugReservation(ctx, controlstatedb.CreateActiveSlugReservationParams{ID: sid, TeamID: r.TeamID, MemberSlug: r.MemberSlug, IdentityID: text(r.IdentityID), CreatedAt: timestamptz(now)}); err != nil {
		return err
	}
	revision, err := q.GetVisitorPolicyRevision(ctx, r.TeamID)
	if err != nil {
		return err
	}
	if err = q.CreateTeamMembership(ctx, controlstatedb.CreateTeamMembershipParams{ID: id, TeamID: r.TeamID, IdentityID: r.IdentityID, SlugReservationID: sid, ManagedLabel: label, Role: "member", AuthorityRevision: revision + 1, CreatedAt: timestamptz(now)}); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.team_memberships SET identity_connection_id=$2 WHERE id=$1`, id, c.ID)
	return err
}

// SetCompanyMembershipDecision is the independent, owner-controlled manual
// decision. recovery explicitly grants a personal-account exception to an owner;
// it never fabricates eligibility or bypasses a removed membership.
func (d *Database) SetCompanyMembershipDecision(ctx context.Context, p ControlPrincipal, team, member string, suspended, exception, recovery bool, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "company membership decision", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return err
	}
	if recovery {
		var companyTeam bool
		if err = tx.QueryRow(ctx, `SELECT kind='organization' AND company_sign_in_required FROM control.teams WHERE id=$1`, team).Scan(&companyTeam); err != nil {
			return err
		}
		if !companyTeam {
			return ErrAuthorityAccess
		}
		var authorized bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.control_sessions s JOIN control.identities i ON i.id=s.identity_id WHERE s.id=$1 AND i.id=$2 AND i.disabled_at IS NULL AND s.revoked_at IS NULL AND s.refresh_expires_at>$4 AND (i.administrator OR EXISTS(SELECT 1 FROM control.team_memberships m WHERE m.team_id=$3 AND m.identity_id=i.id AND m.role='owner' AND m.removed_at IS NULL AND m.manual_suspended_at IS NULL)))`, p.SessionID, p.IdentityID, team, now).Scan(&authorized)
		if err != nil {
			return err
		}
		if !authorized || suspended || !exception {
			return ErrAuthorityAccess
		}
	} else {
		a, ownerID, e := lockCompanyOwner(WithControlPrincipal(ctx, p), tx, q, p, team, now)
		if e != nil {
			return e
		}
		if a.Kind != "organization" || a.ActorRole != "owner" {
			return ErrAuthorityAccess
		}
		p.IdentityID = ownerID
	}
	target, err := q.LockTeamMembership(ctx, controlstatedb.LockTeamMembershipParams{TeamID: team, MembershipID: member})
	if err != nil {
		return publisherLookupError(err, ErrAuthorityAccess)
	}
	if recovery && target.Role != "owner" {
		return ErrAuthorityAccess
	}
	_, err = tx.Exec(ctx, `UPDATE control.team_memberships SET manual_suspended_at=CASE WHEN $2 THEN $4::timestamptz END,personal_account_exception=$3,updated_at=$4 WHERE id=$1`, member, suspended, exception, now)
	if err != nil {
		return err
	}
	op := "membership.decision"
	if recovery {
		op = "membership.recovery"
	}
	if err = companyPolicyChanged(ctx, tx, q, team, "", p.IdentityID, target.IdentityID, op, companyAccessAuditDetails{ManualSuspended: &suspended, PersonalAccountException: &exception}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type companyAccessAuditDetails struct {
	ConnectionRevision       int64      `json:"connection_revision,omitempty"`
	EligibilityRevision      int64      `json:"eligibility_revision,omitempty"`
	Eligible                 *bool      `json:"eligible,omitempty"`
	ValidUntil               *time.Time `json:"valid_until,omitempty"`
	ManualSuspended          *bool      `json:"manual_suspended,omitempty"`
	PersonalAccountException *bool      `json:"personal_account_exception,omitempty"`
	State                    string     `json:"state,omitempty"`
	Admission                string     `json:"admission,omitempty"`
	ReplacedID               string     `json:"replaced_id,omitempty"`
	BootstrapMembershipID    string     `json:"bootstrap_membership_id,omitempty"`
	PreviousConnectionID     string     `json:"previous_connection_id,omitempty"`
}

func companyPolicyChanged(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, team, connection, actor, identity, operation string, details companyAccessAuditDetails, now time.Time) error {
	encoded, err := json.Marshal(details)
	if err != nil {
		return err
	}
	revision, err := q.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{TeamID: team, UpdatedAt: timestamptz(now)})
	if err != nil {
		return err
	}
	if err = q.InsertCompanyAccessAudit(ctx, controlstatedb.InsertCompanyAccessAuditParams{TeamID: team, IdentityConnectionID: nullableText(connection), ActorIdentityID: nullableText(actor), TargetIdentityID: nullableText(identity), Operation: operation, Revision: revision, Now: timestamptz(now), Details: string(encoded)}); err != nil {
		return err
	}
	// eligibility changes invalidate browser/visitor policy through the team
	// revision and close only publications whose explicit subject is inactive.
	return closeInactiveCompanySubjects(ctx, tx, q, team, now)
}

func closeInactiveCompanySubjects(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, team string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT id FROM control.team_memberships WHERE team_id=$1 AND NOT control.active_membership(id,$2) ORDER BY id`, team, now)
	if err != nil {
		return err
	}
	var members []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		members = append(members, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	pending := pendingIngressRoutingTableEvents{}
	for _, member := range members {
		if err = closeMembershipPublishRuns(ctx, q, &pending, team, member, false, now, "company_eligibility_changed"); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `SELECT p.id,COALESCE(g.private_service_id,'') FROM control.publisher_identities p LEFT JOIN control.publisher_grants g ON g.publisher_identity_id=p.id WHERE p.team_id=$1 AND p.ownership='member' AND NOT control.active_membership(p.owner_membership_id,$2) ORDER BY p.id,g.id`, team, now)
	if err != nil {
		return err
	}
	type publication struct{ id, service string }
	var publishers []publication
	for rows.Next() {
		var p publication
		if err = rows.Scan(&p.id, &p.service); err != nil {
			rows.Close()
			return err
		}
		publishers = append(publishers, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range publishers {
		if p.service != "" {
			err = closeRevokedPrivatePublication(ctx, tx, q, p.service, p.id, "", now)
			if err != nil {
				return err
			}
		}
	}
	// take the private routing clock before the public routing clock, as
	// publisher revocation does. both stay locked until this transaction commits.
	for _, p := range publishers {
		if p.service == "" {
			if err = closeRevokedPublicPublications(ctx, tx, q, p.id, "", now); err != nil {
				return err
			}
		}
	}
	if err = pending.publish(ctx, q); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.private_visitor_streams stream SET closed_at=COALESCE(stream.closed_at,$2) FROM control.private_services service WHERE service.id=stream.private_service_id AND service.team_id=$1 AND NOT control.active_team_subject($1,stream.identity_id,$2)`, team, now); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.direct_service_visitors visitor SET closed_at=COALESCE(visitor.closed_at,$2) FROM control.private_services service WHERE service.id=visitor.private_service_id AND service.team_id=$1 AND visitor.identity_id IS NOT NULL AND NOT control.active_team_subject($1,visitor.identity_id,$2)`, team, now)
	return err
}
