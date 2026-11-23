package state

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrServiceAccess = errors.New("service access denied or no current run")
var ErrServiceConflict = errors.New("service name or idempotency key conflicts")

var serviceName = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`)

type ServiceRecord struct {
	ServiceMetadata
	ID, TeamID, GuestID, DomainID, Name string
	EndpointRevision                    int64
	ServiceRevision                     int64
	Placement                           *ServicePlacement   `json:"placement,omitempty"`
	Source                              *LocalServiceSource `json:"source,omitempty"`
	HTTPLimits                          *ProjectHTTPApplicationLimits
	HTTPRequestBodyIdleTimeout          *string
	Enabled                             bool
	Ephemeral, RequirePostQuantum       bool
	ExpiresAt                           *time.Time
	CreatedAt                           time.Time
	Recovered                           bool `json:"-"`
}

type ServiceGrant struct {
	ID, ServiceID, Kind, IdentityID, InvitationID string
	CreatedAt                                     time.Time
	ExpiresAt, RevokedAt                          *time.Time
}

func privateGrantRecord(row controlstatedb.ControlVisitorGrant) ServiceGrant {
	return ServiceGrant{ID: row.ID, ServiceID: row.ServiceID.String, Kind: row.Kind,
		IdentityID: row.IdentityID.String, InvitationID: row.InvitationID.String,
		CreatedAt: row.CreatedAt.Time, ExpiresAt: optionalTime(row.ExpiresAt), RevokedAt: optionalTime(row.RevokedAt)}
}

func lockService(ctx context.Context, tx pgx.Tx, serviceID, actorID string) (controlstatedb.ControlService, error) {
	service, err := lockManagedService(ctx, tx, serviceID, actorID)
	if err == nil && !service.Enabled {
		err = ErrServiceAccess
	}
	return service, err
}

// operational suspension retains management authority without treating a
// disabled service as available for publication or declaration changes.
func lockManagedService(ctx context.Context, tx pgx.Tx, serviceID, actorID string) (controlstatedb.ControlService, error) {
	return managedServiceAuthority(ctx, tx, serviceID, actorID, false)
}

func observeManagedService(ctx context.Context, tx pgx.Tx, serviceID, actorID string) (controlstatedb.ControlService, error) {
	return managedServiceAuthority(ctx, tx, serviceID, actorID, true)
}

func managedServiceAuthority(ctx context.Context, tx pgx.Tx, serviceID, actorID string, observe bool) (controlstatedb.ControlService, error) {
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1 AND guest_id IS NULL AND deleted_at IS NULL`, serviceID).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlService{}, ErrServiceAccess
	}
	if err != nil {
		return controlstatedb.ControlService{}, err
	}
	q := controlstatedb.New(tx)
	teamGuard, serviceGuard := q.LockLocalTeamForMutation, q.LockService
	if observe {
		teamGuard, serviceGuard = q.LockLocalTeamForSession, q.ObservePublisherEnrollmentService
	}
	_, err = teamGuard(ctx, teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlService{}, ErrServiceAccess
	}
	if err != nil {
		return controlstatedb.ControlService{}, err
	}
	clock := newAuthorizationClock(time.Now())
	member, err := checkedActorMembership(ctx, tx, teamID, actorID, clock, !observe)
	if err != nil {
		return controlstatedb.ControlService{}, err
	}
	if observe {
		if err := queueRunReader(ctx, tx, serviceID); err != nil {
			return controlstatedb.ControlService{}, err
		}
	}
	service, err := serviceGuard(ctx, serviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return service, ErrServiceAccess
	}
	if err != nil {
		return service, err
	}
	if service.TeamID.String != teamID || service.GuestID.Valid || service.DeletedAt.Valid {
		return service, ErrServiceAccess
	}
	if observe {
		if err := recheckServiceMembership(ctx, tx, teamID, actorID, member, clock); err != nil {
			return service, err
		}
	}
	if err = requireServiceManagement(ctx, tx, service, member); err != nil {
		return service, err
	}
	return service, nil
}

func checkedServiceRecord(row controlstatedb.ControlService) (ServiceRecord, error) {
	metadata, err := checkedServiceMetadata(row)
	if err != nil {
		return ServiceRecord{}, err
	}
	return ServiceRecord{ServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID.String, GuestID: row.GuestID.String, DomainID: row.DomainID.String, Name: row.Name, EndpointRevision: row.EndpointRevision, ServiceRevision: row.ServiceRevision, Enabled: row.Enabled, Ephemeral: row.Ephemeral, RequirePostQuantum: row.RequirePostQuantum, ExpiresAt: optionalTime(row.ExpiresAt), CreatedAt: row.CreatedAt.Time, Placement: &ServicePlacement{DomainID: row.DomainID.String, Hostname: row.CertificateHostname, WorktreeKey: row.PlacementWorktreeKey, WorktreeLabel: row.PlacementWorktreeLabel}}, nil
}

func serviceManager(ctx context.Context, tx pgx.Tx, teamID, actorID string) error {
	member, err := serviceMembershipForActor(ctx, tx, teamID, actorID, time.Now())
	if err != nil {
		return err
	}
	return member.requireAdministrator(ctx)
}

func (member serviceMembership) requireAdministrator(ctx context.Context) error {
	if !member.administrator() {
		if _, signed := serviceActor(ctx); signed {
			return ErrServiceManagerRequired
		}
		return ErrServiceAccess
	}
	return nil
}

// service membership is validated once in the operation's transaction, then
// reused for each exact service. it carries no publisher or visitor authority.
type serviceMembership struct {
	teamID, id, role string
}

func (m serviceMembership) administrator() bool {
	return m.role == "owner" || m.role == "admin"
}

func requireServiceManagement(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, member serviceMembership) error {
	return requireStoredServiceManagement(ctx, tx, service, member, false)
}

// revocation and retained feedback may read a service tombstone and its source
// ownership receipt. ordinary management still requires the live saved service.
func requireStoredServiceManagement(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, member serviceMembership, retained bool) error {
	denied := ErrServiceAccess
	if _, signed := serviceActor(ctx); signed {
		denied = ErrServiceManagerRequired
	}
	if member.id == "" || service.GuestID.Valid || member.teamID != service.TeamID.String || service.DeletedAt.Valid && !retained {
		return denied
	}
	if member.administrator() {
		return nil
	}
	// ownership comes from exactly one stored source, never the creator, a
	// hostname suffix, or a publisher's current ability to serve the service.
	var allocated, applied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_namespace_allocations WHERE service_id=$1),
	    EXISTS(SELECT 1 FROM control.applied_project_services WHERE service_id=$1)`, service.ID).Scan(&allocated, &applied); err != nil {
		return err
	}
	if applied {
		return denied
	}
	if !allocated {
		owner, err := storedServiceSourceOwner(ctx, tx, service, retained)
		if errors.Is(err, ErrServiceAccess) {
			return denied
		}
		if err != nil {
			return err
		}
		if owner.scope != NamespaceScopeMember || owner.membership != member.id {
			return denied
		}
		return nil
	}
	var owned bool
	err := tx.QueryRow(ctx, `SELECT
	        NOT EXISTS(SELECT 1 FROM control.local_project_services WHERE service_id=$1)
	        AND NOT EXISTS(SELECT 1 FROM control.service_source_owners WHERE service_id=$1)
	        AND NOT EXISTS(SELECT 1 FROM control.service_endpoints
	            WHERE service_id=$1 AND (local_source_key<>'' OR deployment_id IS NOT NULL))
	        AND EXISTS(SELECT 1 FROM control.publisher_namespace_allocations allocation
	            JOIN control.publisher_grants grant_record
	              ON grant_record.id=allocation.publisher_grant_id
	              AND grant_record.publisher_identity_id=allocation.publisher_identity_id
	            JOIN control.publisher_identities publisher ON publisher.id=allocation.publisher_identity_id
	            WHERE allocation.service_id=$1 AND allocation.deployment_id IS NULL
	              AND publisher.team_id=$2 AND grant_record.kind='namespace'
	              AND grant_record.namespace_scope='member' AND grant_record.membership_id=$3)`,
		service.ID, service.TeamID, member.id).Scan(&owned)
	if err != nil {
		return err
	}
	if !owned {
		return denied
	}
	return nil
}

func (d *Database) CreateServiceAt(ctx context.Context, teamID, actorID, name, key string, placement ServicePlacement, now time.Time, metadata ServiceMetadata, configuration *ProjectServiceConfiguration) (result ServiceRecord, retErr error) {
	clock := newAuthorizationClock(now)
	public, ephemeral, postQuantum := false, false, false
	if configuration != nil {
		// normalize a private copy of the canonical declaration. metadata and
		// placement may select the same facts, never replace declaration policy.
		normalized, err := normalizeServiceConfiguration(name, configuration)
		if err != nil {
			return result, err
		}
		trust, err := appliedServiceTargetTrust(normalized.TargetTLS)
		if err != nil {
			return result, err
		}
		if metadata.Protocol != "" && metadata.Protocol != normalized.Protocol ||
			metadata.TLS != nil && !reflect.DeepEqual(metadata.TLS, trust) ||
			placement.Hostname != "" && normalized.Hostname != "" && placement.Hostname != normalized.Hostname ||
			placement.DomainID != "" && normalized.DomainID != "" && placement.DomainID != normalized.DomainID {
			return result, ErrServiceConflict
		}
		metadata.Protocol, metadata.TLS = normalized.Protocol, trust
		placement.RunAliasParent = normalized.RunAliasParent
		if normalized.Hostname != "" {
			placement.Hostname = normalized.Hostname
		}
		if normalized.DomainID != "" {
			placement.DomainID = normalized.DomainID
		}
		public, ephemeral = projectServicePublic(*normalized), normalized.Ephemeral
		postQuantum = normalized.RequirePostQuantum != nil && *normalized.RequirePostQuantum
		configuration = normalized
	}
	if err := placement.Validate(); err != nil {
		return result, err
	}
	if err := metadata.Validate(); err != nil {
		return result, err
	}
	if !serviceName.MatchString(name) || len(key) == 0 || len(key) > 128 {
		return result, ErrServiceAccess
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		return result, err
	}
	intent, err := json.Marshal(struct {
		Team, Name    string
		Placement     ServicePlacement
		Metadata      ServiceMetadata
		Configuration *ProjectServiceConfiguration
		Reserve       bool
	}{teamID, name, placement, ServiceMetadata{Protocol: metadata.Protocol, TLS: metadata.TLS, PublisherPool: metadata.PublisherPool}, configuration, placement.Reserve})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(intent)
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create service", &retErr)()
	// queue on the team advisory guard before taking its row, as apply does.
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	} else if err != nil {
		return result, err
	}
	var parentUntil *time.Time
	if _, signed := serviceActor(ctx); !signed {
		if principal, present := ctx.Value(controlPrincipalKey{}).(ControlPrincipal); present {
			if principal.IdentityID != actorID {
				return result, ErrServiceAccess
			}
			until, err := currentVisitorParentSession(ctx, tx, principal, clock.current())
			if err != nil {
				return result, errors.Join(ErrServiceAccess, err)
			}
			parentUntil = &until
		}
	}
	member, err := serviceMembershipForActor(ctx, tx, teamID, actorID, clock.current())
	if err != nil {
		return result, err
	}
	commit := func() error {
		return finishServiceCreation(ctx, tx, teamID, actorID, member, parentUntil, clock)
	}
	if !placement.Reserve && !member.administrator() {
		if _, signed := serviceActor(ctx); signed {
			return result, ErrServiceManagerRequired
		}
		return result, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	nameScope := "member/" + actorID + "/" + placement.WorktreeKey
	var selectedOwner serviceSourceOwner
	if placement.Reserve {
		selectedOwner, err = d.serviceReservationOwner(ctx, tx, teamID, actorID, name, placement, configuration, clock.current())
		if err != nil {
			return result, err
		}
		if selectedOwner.scope == NamespaceScopeShared {
			nameScope = "shared"
		}
	}
	receipt, err := q.GetServiceCreationRequest(ctx, controlstatedb.GetServiceCreationRequestParams{CreatedByIdentityID: actorID, IdempotencyKey: key})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	existing := receipt.ServiceID
	if existing != "" && !bytes.Equal(receipt.RequestDigest, digest[:]) {
		return result, ErrServiceConflict
	}
	saveReceipt := func(service string) error {
		return q.InsertServiceCreationRequest(ctx, controlstatedb.InsertServiceCreationRequestParams{
			CreatedByIdentityID: actorID, IdempotencyKey: key, ServiceID: service, RequestDigest: digest[:], CreatedAt: timestamptz(clock.current()),
		})
	}
	if placement.Reserve {
		if existing == "" {
			candidates, readErr := q.ListServiceReservationCandidates(ctx, controlstatedb.ListServiceReservationCandidatesParams{
				TeamID: text(teamID), Name: name, NameScope: nameScope, Hostname: placement.Hostname,
			})
			if readErr != nil {
				return result, readErr
			}
			if len(candidates) > 1 {
				return result, ErrServiceConflict
			}
			if len(candidates) == 1 {
				existing = candidates[0].ID
			}
		}
		if existing != "" {
			row, readErr := q.LockService(ctx, existing)
			if readErr != nil {
				return result, readErr
			}
			result, err = reservedServiceRecord(ctx, tx, row, member, name, placement, selectedOwner)
			if err != nil {
				return ServiceRecord{}, err
			}
			if receipt.ServiceID == "" {
				if err = saveReceipt(existing); err != nil {
					return ServiceRecord{}, err
				}
			}
			if err = commit(); err != nil {
				return ServiceRecord{}, err
			}
			return result, nil
		}
		if !member.administrator() && metadata.Protocol != "http" {
			return result, ErrServiceAccess
		}
	}
	if existing != "" {
		row, err := controlstatedb.New(tx).LockService(ctx, existing)
		if err != nil {
			return result, err
		}
		saved, err := checkedServiceMetadata(row)
		if err != nil {
			return result, err
		}
		if row.DeletedAt.Valid || !row.Enabled || row.TeamID.String != teamID || row.CreatedByIdentityID.String != actorID ||
			row.Name != name || row.NameScope != "member/"+actorID+"/"+placement.WorktreeKey && row.NameScope != "shared" ||
			!bytes.Equal(row.RequestDigest, digest[:]) || !serviceMetadataMatches(saved, metadata) ||
			row.PublisherPool != metadata.PublisherPool || row.Public != public || row.Ephemeral != ephemeral || row.RequirePostQuantum != postQuantum {
			return result, ErrServiceConflict
		}
		stored, err := controlstatedb.New(tx).GetServiceConfiguration(ctx, row.ID)
		if err != nil {
			return result, err
		}
		if stored.LocalOwned || stored.DeploymentOwned || stored.AllocationOwned {
			return result, ErrServiceConflict
		}
		previous, err := d.openServiceConfiguration(row.ID, row.Name, stored.StorageKeyID.String, stored.ConfigurationCiphertext, "", savedServiceConfiguration)
		if err != nil {
			return result, err
		}
		if !reflect.DeepEqual(previous, configuration) {
			return result, ErrServiceConflict
		}
		if err = d.ensureLocalServiceEndpoint(ctx, tx, row.ID, actorID, name, placement, public, now); err != nil {
			return result, err
		}
		result, err = checkedServiceRecord(row)
		if err != nil {
			return result, err
		}
		result.Recovered = true
		if err = commit(); err != nil {
			return ServiceRecord{}, err
		}
		return result, nil
	}
	if err = requireNewServiceWork(ctx, controlstatedb.New(tx), MaintenanceControlServiceCreation); err != nil {
		return result, err
	}
	if !placement.Reserve && placement.Hostname != "" && placement.SourceKey == "" {
		domain := placement.DomainID
		if domain == "" {
			if err := tx.QueryRow(ctx, `SELECT COALESCE(default_domain_id,'') FROM control.teams WHERE id=$1`, teamID).Scan(&domain); err != nil {
				return result, err
			}
		}
		facts, factsErr := serviceHostnameAuthority(ctx, tx, teamID, actorID, domain, clock.current())
		if factsErr != nil {
			return result, factsErr
		}
		owner, ownerErr := d.newServiceSourceOwner(ctx, tx, facts, teamID, placement.Hostname, "adhoc/"+placement.WorktreeKey+"/"+name, true, true)
		if ownerErr != nil {
			return result, ownerErr
		}
		if owner.scope == NamespaceScopeShared {
			nameScope = "shared"
		}
	}
	_, err = controlstatedb.New(tx).InsertService(ctx, controlstatedb.InsertServiceParams{
		ID: id, TeamID: text(teamID), Name: name, NameScope: nameScope, CreatedByIdentityID: text(actorID),
		IdempotencyKey: key, RequestDigest: digest[:], Now: timestamptz(now),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return result, ErrServiceConflict
	}
	if err != nil {
		return result, err
	}
	var encoded []byte
	if metadata.TLS != nil {
		encoded, err = json.Marshal(metadata.TLS)
		if err != nil {
			return result, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2, tls_metadata=convert_from($3::bytea,'UTF8')::jsonb, publisher_pool=$4,
	    ephemeral=$5,require_post_quantum=$6 WHERE id=$1`, id, metadata.Protocol, encoded, metadata.PublisherPool, ephemeral, postQuantum); err != nil {
		return result, err
	}
	if configuration != nil {
		if err = d.saveServiceConfiguration(ctx, tx, id, *configuration); err != nil {
			return result, err
		}
	}
	if err = d.ensureLocalServiceEndpoint(ctx, tx, id, actorID, name, placement, public, clock.current()); err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, id, actorID, "service.create", id, now); err != nil {
		return result, err
	}
	// ordinary administrator creation retains its revocable visitor default.
	// a member reservation grants no connector visitor authority, including
	// no dormant auto-owner grant; HTTP browser ownership is path-specific.
	if member.administrator() {
		ownerGrantID, err := opaqueid.New(opaqueid.ServiceGrantPrefix)
		if err != nil {
			return result, err
		}
		ownerDigest := sha256.Sum256([]byte("service-owner:" + id))
		if _, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,service_id,team_id,kind,identity_id,auto_owner,created_by_identity_id,idempotency_key,request_digest,created_at)
		    VALUES($1,$2,$3,'identity',$4,true,$4,$5,$6,$7)`, ownerGrantID, id, teamID, actorID, "owner/"+id, ownerDigest[:], now); err != nil {
			return result, err
		}
		if err = auditPrivateMutation(ctx, tx, id, actorID, "grant.create", ownerGrantID, now); err != nil {
			return result, err
		}
	}
	row, err := q.LockService(ctx, id)
	if err != nil {
		return result, err
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = saveReceipt(id); err != nil {
		return result, err
	}
	if err = commit(); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}

func privateSecret() (string, []byte, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256(secret[:])
	return encoded, digest[:], nil
}

func serviceSecretDigest(encoded string) ([]byte, error) {
	if len(encoded) != 43 {
		return nil, ErrServiceAccess
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return nil, ErrServiceAccess
	}
	digest := sha256.Sum256(secret)
	return digest[:], nil
}
