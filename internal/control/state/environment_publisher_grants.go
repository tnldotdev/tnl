package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

var ErrEnvironmentPublisherGrantConflict = errors.New("environment publisher grant or authorization intent changed")

// EnvironmentPublisherManager carries either an exact authenticated control
// session or a machine provisioning session, with its original deadline. a
// machine never receives a human identity or a manager role. only this owner
// constructs it; operations recheck current session, role and exact scope.
type EnvironmentPublisherManager struct {
	accessID, sessionID, identityID string
	digest                          credentials.SecretHash
	deadline                        time.Time
	provisioningCredential          string
	machineID, provisioningGrantID  string
	internalActor                   bool
}

func (EnvironmentPublisherManager) String() string { return "environment publisher manager credential" }
func (EnvironmentPublisherManager) GoString() string {
	return "environment publisher manager credential"
}

// AuthenticateEnvironmentPublisherManager captures verified session facts.
// operations check either current manager authority or exact machine scope.
// http callers must pass this value, never an earlier actor lookup.
func (d *Database) AuthenticateEnvironmentPublisherManager(ctx context.Context, token credentials.AccessToken) (EnvironmentPublisherManager, error) {
	if strings.HasPrefix(string(token), "mpc_") {
		return d.authenticateEnvironmentProvisioner(ctx, string(token))
	}
	id, digest, err := credentials.ParseAccessToken(token)
	if err != nil {
		return EnvironmentPublisherManager{}, ErrControlAuthentication
	}
	row, err := controlstatedb.New(d.pool).GetControlSessionByAccessID(ctx, id.String())
	if err != nil {
		return EnvironmentPublisherManager{}, publisherLookupError(err, ErrControlAuthentication)
	}
	a := EnvironmentPublisherManager{accessID: id.String(), sessionID: row.ID, identityID: row.IdentityID, digest: digest, deadline: row.AccessExpiresAt.Time}
	if row.RefreshExpiresAt.Time.Before(a.deadline) {
		a.deadline = row.RefreshExpiresAt.Time
	}
	if !credentials.SecretHashMatches(row.AccessTokenDigest, digest) || !a.deadline.After(time.Now()) {
		return EnvironmentPublisherManager{}, ErrControlAuthentication
	}
	return a, nil
}

// EnvironmentPublisherGrantExpectation distinguishes the required null
// precondition from a missing field. the http decoder must preserve presence.
type EnvironmentPublisherGrantExpectation struct {
	specified bool
	id        string
}

func ExpectNoEnvironmentPublisherGrant() EnvironmentPublisherGrantExpectation {
	return EnvironmentPublisherGrantExpectation{specified: true}
}

func ExpectEnvironmentPublisherGrant(id string) (EnvironmentPublisherGrantExpectation, error) {
	if !opaqueid.Valid(id, opaqueid.PublisherGrantPrefix) {
		return EnvironmentPublisherGrantExpectation{}, ErrEnvironmentInvalid
	}
	return EnvironmentPublisherGrantExpectation{specified: true, id: id}, nil
}

type EnvironmentPublisherGrantSelection struct {
	TeamID, ProjectKey, EnvironmentID, PublisherIdentityID, ServiceID string
}

type InspectEnvironmentPublisherGrantRequest struct {
	EnvironmentPublisherGrantSelection
	Manager EnvironmentPublisherManager
}

type EnvironmentPublisherGrantMutation struct {
	InspectEnvironmentPublisherGrantRequest
	ExpectedRevision          int64
	ExpectedConfigurationHash string
}

type AuthorizeEnvironmentPublisherServiceRequest struct {
	EnvironmentPublisherGrantMutation
	ExpectedPreviousGrantID EnvironmentPublisherGrantExpectation
	IdempotencyKey          string
}

type RevokeEnvironmentPublisherGrantRequest struct {
	EnvironmentPublisherGrantMutation
	GrantID string
}

// these records expose selected scope and provenance, never authority, signing
// keys, targets or internal assignment IDs.
type EnvironmentPublisherGrant struct {
	ID, CreatedByIdentityID, CreatedByMachineID, ProvisioningGrantID string
	CreatedAt                                                        time.Time
	ExpiresAt, RevokedAt                                             *time.Time
}

type EnvironmentPublisherGrantState struct {
	EnvironmentPublisherGrantSelection
	MutationRevision  int64
	ConfigurationHash string
	Grant             *EnvironmentPublisherGrant
}

type EnvironmentPublisherGrantAuthorization struct {
	EnvironmentPublisherGrantState
	Created bool
}

type environmentPublisherGrantScope struct {
	environment controlstatedb.ControlEnvironment
	binding     controlstatedb.ControlAppliedProjectService
	grant       *controlstatedb.ControlPublisherGrant
}

func (s EnvironmentPublisherGrantSelection) valid() bool {
	return opaqueid.Valid(s.TeamID, opaqueid.TeamPrefix) && naming.ValidProjectKey(s.ProjectKey) &&
		opaqueid.Valid(s.EnvironmentID, opaqueid.EnvironmentPrefix) && opaqueid.Valid(s.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) && opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix)
}

func (r EnvironmentPublisherGrantMutation) valid() bool {
	return r.EnvironmentPublisherGrantSelection.valid() && r.ExpectedRevision > 0 && fingerprintPattern.MatchString(r.ExpectedConfigurationHash)
}

func (a EnvironmentPublisherManager) checkSession(id, identity string, digest []byte, access, refresh time.Time) error {
	now := time.Now()
	if a.accessID == "" || a.sessionID != id || a.identityID != identity || !a.deadline.After(now) ||
		!access.After(now) || !refresh.After(now) || !credentials.SecretHashMatches(digest, a.digest) {
		return ErrControlAuthentication
	}
	return nil
}

func (a EnvironmentPublisherManager) check(ctx context.Context, tx pgx.Tx, team string) error {
	if a.accessID == "" || !a.deadline.After(time.Now()) {
		return ErrControlAuthentication
	}
	q := controlstatedb.New(tx)
	row, err := q.GetControlSessionByAccessID(ctx, a.accessID)
	if err != nil {
		return publisherLookupError(err, ErrControlAuthentication)
	}
	if err = a.checkSession(row.ID, row.IdentityID, row.AccessTokenDigest, row.AccessExpiresAt.Time, row.RefreshExpiresAt.Time); err != nil {
		return err
	}
	principal := ControlPrincipal{SessionID: a.sessionID, IdentityID: a.identityID}
	if err = controlSessionServiceManagerAt(WithControlPrincipal(ctx, principal), tx, team, a.identityID, time.Now()); err != nil {
		return err
	}
	if !a.deadline.After(time.Now()) {
		return ErrControlAuthentication
	}
	return nil
}

// finish serializes with session revocation/rotation and spends the original
// access deadline after every lock wait. reauthentication cannot extend it.
func (a EnvironmentPublisherManager) finish(ctx context.Context, tx pgx.Tx, team string) error {
	if a.provisioningCredential != "" {
		return a.checkProvisioner(ctx, tx, team)
	}
	if a.internalActor {
		return serviceManager(ctx, tx, team, a.identityID)
	}
	q := controlstatedb.New(tx)
	row, err := q.LockEnvironmentPublisherManagerSession(ctx, a.accessID)
	if err != nil {
		return publisherLookupError(err, ErrControlAuthentication)
	}
	if err = a.checkSession(row.ID, row.IdentityID, row.AccessTokenDigest, row.AccessExpiresAt.Time, row.RefreshExpiresAt.Time); err != nil {
		return err
	}
	return a.check(ctx, tx, team)
}

// team -> project -> environment -> assignment -> service -> member/key ->
// mapping is shared by reads and mutations. no caller can substitute a group
// selector or bypass current environment ownership with an old group grant.
func (d *Database) lockEnvironmentPublisherGrant(ctx context.Context, tx pgx.Tx, r InspectEnvironmentPublisherGrantRequest, expected *EnvironmentPublisherGrantMutation, operation ProvisioningOperation) (s environmentPublisherGrantScope, err error) {
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return s, err
	}
	if err = r.Manager.start(ctx, tx, r.TeamID); err != nil {
		return s, err
	}
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey}); err != nil {
		return s, err
	}
	s.environment, err = q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: r.EnvironmentID})
	if err != nil {
		return s, err
	}
	if s.environment.RetiredAt.Valid {
		return s, ErrEnvironmentRetired
	}
	if expected != nil && (s.environment.MutationRevision != expected.ExpectedRevision || s.environment.ConfigurationHash != expected.ExpectedConfigurationHash) {
		return s, ErrEnvironmentStale
	}
	if _, err = q.LockEnvironmentPublisherAssignment(ctx, controlstatedb.LockEnvironmentPublisherAssignmentParams{GroupID: s.environment.GroupID, EnvironmentID: text(r.EnvironmentID), TeamID: r.TeamID, ProjectKey: r.ProjectKey}); err != nil {
		return s, err
	}
	_, _, projection, err := d.environmentProjection(ctx, tx, s.environment)
	if err != nil {
		return s, err
	}
	s.binding, err = q.LockEnvironmentPublisherService(ctx, controlstatedb.LockEnvironmentPublisherServiceParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, GroupID: text(s.environment.GroupID), ServiceID: text(r.ServiceID)})
	if err != nil {
		return s, err
	}
	service, err := q.LockService(ctx, r.ServiceID)
	if err != nil {
		return s, err
	}
	configuration, found := projection[appliedServiceName(s.binding.Service)]
	if !found || service.TeamID != r.TeamID || !service.Enabled || service.DeletedAt.Valid || service.Protocol != configuration.Protocol {
		return s, ErrEnvironmentNotFound
	}
	if err = r.Manager.authorize(ctx, tx, ProvisioningScope{Operation: operation, TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: r.EnvironmentID, Services: []string{appliedServiceName(s.binding.Service)}, EnrollmentMembers: 1, EnrollmentLifetime: time.Minute}, false); err != nil {
		return s, err
	}
	if _, err = q.LockEnvironmentPublisherMember(ctx, controlstatedb.LockEnvironmentPublisherMemberParams{PublisherIdentityID: r.PublisherIdentityID, GroupID: s.environment.GroupID, TeamID: r.TeamID, Now: timestamptz(time.Now())}); err != nil {
		return s, err
	}
	grant, err := q.LockEnvironmentPublisherGrantMapping(ctx, controlstatedb.LockEnvironmentPublisherGrantMappingParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, PublisherIdentityID: r.PublisherIdentityID, Service: s.binding.Service})
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if grant.Kind != "service" || grant.ServiceID.String != r.ServiceID || grant.PublisherIdentityID != r.PublisherIdentityID {
		return s, ErrEnvironmentInvalid
	}
	s.grant = &grant
	return s, nil
}

func (s environmentPublisherGrantScope) status(selection EnvironmentPublisherGrantSelection) EnvironmentPublisherGrantState {
	r := EnvironmentPublisherGrantState{EnvironmentPublisherGrantSelection: selection, MutationRevision: s.environment.MutationRevision, ConfigurationHash: s.environment.ConfigurationHash}
	if g := s.grant; g != nil {
		r.Grant = &EnvironmentPublisherGrant{ID: g.ID, CreatedByIdentityID: g.CreatedByIdentityID.String, CreatedByMachineID: g.CreatedByMachineID.String, ProvisioningGrantID: g.ProvisioningGrantID.String, CreatedAt: g.CreatedAt.Time, ExpiresAt: optionalTime(g.ExpiresAt), RevokedAt: optionalTime(g.RevokedAt)}
	}
	return r
}

func (d *Database) GetEnvironmentPublisherGrant(ctx context.Context, r InspectEnvironmentPublisherGrantRequest) (result EnvironmentPublisherGrantState, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !r.EnvironmentPublisherGrantSelection.valid() {
		return result, ErrEnvironmentInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "inspect environment publisher grant", &retErr)()
	scope, err := d.lockEnvironmentPublisherGrant(ctx, tx, r, nil, ProvisioningRead)
	if err != nil {
		return result, err
	}
	if err = r.Manager.finish(ctx, tx, r.TeamID); err != nil {
		return result, err
	}
	return scope.status(r.EnvironmentPublisherGrantSelection), tx.Commit(ctx)
}

func environmentPublisherGrantDigest(r AuthorizeEnvironmentPublisherServiceRequest) [32]byte {
	var previous *string
	if r.ExpectedPreviousGrantID.id != "" {
		previous = &r.ExpectedPreviousGrantID.id
	}
	data, _ := json.Marshal(struct {
		Selection EnvironmentPublisherGrantSelection
		Revision  int64
		Hash      string
		Previous  *string
	}{r.EnvironmentPublisherGrantSelection, r.ExpectedRevision, r.ExpectedConfigurationHash, previous})
	return sha256.Sum256(append([]byte("tnl:environment-publisher-grant:v1\x00"), data...))
}

func activeEnvironmentPublisherGrant(g *controlstatedb.ControlPublisherGrant) bool {
	return g != nil && !g.RevokedAt.Valid && (!g.ExpiresAt.Valid || g.ExpiresAt.Time.After(time.Now()))
}

func (d *Database) AuthorizeEnvironmentPublisherService(ctx context.Context, r AuthorizeEnvironmentPublisherServiceRequest) (result EnvironmentPublisherGrantAuthorization, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !r.EnvironmentPublisherGrantMutation.valid() || !r.ExpectedPreviousGrantID.specified || len(r.IdempotencyKey) == 0 || len(r.IdempotencyKey) > 128 || !validEnvironmentKey(r.IdempotencyKey) {
		return result, ErrEnvironmentInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize environment publisher service", &retErr)()
	scope, err := d.lockEnvironmentPublisherGrant(ctx, tx, r.InspectEnvironmentPublisherGrantRequest, &r.EnvironmentPublisherGrantMutation, ProvisioningEnroll)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	digest := environmentPublisherGrantDigest(r)
	receipt, err := q.ReadEnvironmentPublisherGrantRequest(ctx, controlstatedb.ReadEnvironmentPublisherGrantRequestParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: r.EnvironmentID, IdempotencyKey: r.IdempotencyKey})
	switch {
	case err == nil:
		if !bytes.Equal(receipt.RequestDigest, digest[:]) || !activeEnvironmentPublisherGrant(scope.grant) || scope.grant.ID != receipt.GrantID || receipt.PublisherIdentityID != r.PublisherIdentityID || receipt.ServiceID != r.ServiceID {
			return result, ErrEnvironmentPublisherGrantConflict
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return result, err
	default:
		previous := ""
		if scope.grant != nil {
			previous = scope.grant.ID
		}
		if previous != r.ExpectedPreviousGrantID.id || scope.grant != nil && !scope.grant.RevokedAt.Valid && !activeEnvironmentPublisherGrant(scope.grant) {
			return result, ErrEnvironmentPublisherGrantConflict
		}
		if scope.grant == nil || scope.grant.RevokedAt.Valid {
			if err = r.Manager.authorize(ctx, tx, ProvisioningScope{Operation: ProvisioningEnroll, TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: r.EnvironmentID, Services: []string{appliedServiceName(scope.binding.Service)}, EnrollmentMembers: 1, EnrollmentLifetime: time.Minute}, true); err != nil {
				return result, err
			}
			grant, e := insertPublisherGrantForIssuer(ctx, q, r.PublisherIdentityID, r.Manager.issuer(), servicePublisherScope{r.TeamID, r.ServiceID}, nil, time.Now())
			if e != nil {
				return result, e
			}
			n, e := q.SetEnvironmentPublisherGrantMapping(ctx, controlstatedb.SetEnvironmentPublisherGrantMappingParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, PublisherIdentityID: r.PublisherIdentityID, Service: scope.binding.Service, GrantID: grant.ID, PreviousGrantID: nullableText(previous)})
			if e != nil {
				return result, e
			}
			if n != 1 {
				return result, ErrEnvironmentPublisherGrantConflict
			}
			scope.grant, result.Created = &grant, true
			if err = q.InvalidateEnvironmentPublisherMember(ctx, controlstatedb.InvalidateEnvironmentPublisherMemberParams{PublisherIdentityID: r.PublisherIdentityID, GroupID: scope.environment.GroupID}); err != nil {
				return result, err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO control.environment_publisher_grant_requests(team_id,project_key,environment_id,idempotency_key,publisher_identity_id,service_id,request_digest,grant_id,created_by_identity_id,created_by_machine_id,provisioning_grant_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),$12)`, r.TeamID, r.ProjectKey, r.EnvironmentID, r.IdempotencyKey, r.PublisherIdentityID, r.ServiceID, digest[:], scope.grant.ID, r.Manager.identityID, r.Manager.machineID, r.Manager.provisioningGrantID, time.Now()); err != nil {
			return EnvironmentPublisherGrantAuthorization{}, err
		}
	}
	if err = r.Manager.finish(ctx, tx, r.TeamID); err != nil {
		return EnvironmentPublisherGrantAuthorization{}, err
	}
	result.EnvironmentPublisherGrantState = scope.status(r.EnvironmentPublisherGrantSelection)
	return result, tx.Commit(ctx)
}

func (d *Database) RevokeEnvironmentPublisherGrant(ctx context.Context, r RevokeEnvironmentPublisherGrantRequest) (retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !r.EnvironmentPublisherGrantMutation.valid() || !opaqueid.Valid(r.GrantID, opaqueid.PublisherGrantPrefix) {
		return ErrEnvironmentInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke environment publisher grant", &retErr)()
	scope, err := d.lockEnvironmentPublisherGrant(ctx, tx, r.InspectEnvironmentPublisherGrantRequest, &r.EnvironmentPublisherGrantMutation, ProvisioningRevokeMember)
	if err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	g, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: r.GrantID, PublisherIdentityID: r.PublisherIdentityID})
	if err != nil {
		return err
	}
	if g.Kind != "service" || g.ServiceID.String != r.ServiceID {
		return ErrEnvironmentNotFound
	}
	if !g.RevokedAt.Valid {
		if scope.grant == nil || scope.grant.ID != g.ID {
			return ErrEnvironmentPublisherGrantConflict
		}
		if err = lockAppliedPublicationReservations(ctx, tx); err != nil {
			return err
		}
		if err = setServiceAuditIssuer(ctx, tx, r.Manager.issuer()); err != nil {
			return err
		}
		if err = closeRevokedPrivatePublication(ctx, tx, q, r.ServiceID, r.PublisherIdentityID, g.ID, time.Now()); err != nil {
			return err
		}
		if _, err = q.RevokePublisherGrant(ctx, controlstatedb.RevokePublisherGrantParams{ID: g.ID, PublisherIdentityID: r.PublisherIdentityID, Now: timestamptz(time.Now())}); err != nil {
			return err
		}
		if err = q.InvalidateEnvironmentPublisherMember(ctx, controlstatedb.InvalidateEnvironmentPublisherMemberParams{PublisherIdentityID: r.PublisherIdentityID, GroupID: scope.environment.GroupID}); err != nil {
			return err
		}
	}
	if err = r.Manager.finish(ctx, tx, r.TeamID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
