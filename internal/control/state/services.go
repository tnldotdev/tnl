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
	Placement                           *ServicePlacement   `json:"placement,omitempty"`
	Source                              *LocalServiceSource `json:"source,omitempty"`
	HTTPLimits                          *ProjectHTTPApplicationLimits
	Enabled                             bool
	Ephemeral, RequirePostQuantum       bool
	ExpiresAt                           *time.Time
	CreatedAt                           time.Time
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
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1 AND guest_id IS NULL AND deleted_at IS NULL`, serviceID).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlService{}, ErrServiceAccess
	}
	if err != nil {
		return controlstatedb.ControlService{}, err
	}
	_, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlService{}, ErrServiceAccess
	}
	if err != nil {
		return controlstatedb.ControlService{}, err
	}
	member, err := serviceMembershipForActor(ctx, tx, teamID, actorID, time.Now())
	if err != nil {
		return controlstatedb.ControlService{}, err
	}
	service, err := controlstatedb.New(tx).LockService(ctx, serviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return service, ErrServiceAccess
	}
	if err != nil {
		return service, err
	}
	if service.TeamID.String != teamID || service.GuestID.Valid || service.DeletedAt.Valid {
		return service, ErrServiceAccess
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
	return ServiceRecord{ServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID.String, GuestID: row.GuestID.String, DomainID: row.DomainID.String, Name: row.Name, EndpointRevision: row.EndpointRevision, Enabled: row.Enabled, Ephemeral: row.Ephemeral, RequirePostQuantum: row.RequirePostQuantum, ExpiresAt: optionalTime(row.ExpiresAt), CreatedAt: row.CreatedAt.Time, Placement: &ServicePlacement{DomainID: row.DomainID.String, Hostname: row.CertificateHostname, WorktreeKey: row.PlacementWorktreeKey, WorktreeLabel: row.PlacementWorktreeLabel}}, nil
}

func serviceManager(ctx context.Context, tx pgx.Tx, teamID, actorID string) error {
	if _, signed := serviceActor(ctx); signed {
		return serviceActorManager(ctx, tx, teamID, actorID, time.Now())
	}
	member, err := serviceMembershipForActor(ctx, tx, teamID, actorID, time.Now())
	if err != nil {
		return err
	}
	if !member.administrator() {
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

// retained feedback may read a service tombstone and its original endpoint
// receipt. ordinary management still requires the live saved service.
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
	var owned bool
	err := tx.QueryRow(ctx, `SELECT
	    NOT EXISTS(SELECT 1 FROM control.applied_project_services WHERE service_id=$1)
	    AND CASE WHEN EXISTS(SELECT 1 FROM control.publisher_namespace_allocations WHERE service_id=$1)
	    THEN
	        NOT EXISTS(SELECT 1 FROM control.local_project_services WHERE service_id=$1)
	        AND NOT EXISTS(SELECT 1 FROM control.service_endpoints
	            WHERE service_id=$1 AND (local_source_key<>'' OR deployment_id IS NOT NULL))
	        AND EXISTS(SELECT 1 FROM control.publisher_namespace_allocations allocation
	            JOIN control.publisher_grants grant_record
	              ON grant_record.id=allocation.publisher_grant_id
	              AND grant_record.publisher_identity_id=allocation.publisher_identity_id
	            JOIN control.publisher_identities publisher ON publisher.id=allocation.publisher_identity_id
	            WHERE allocation.service_id=$1 AND allocation.deployment_id IS NULL
	              AND publisher.team_id=$2 AND grant_record.kind='namespace'
	              AND grant_record.namespace_scope='member' AND grant_record.membership_id=$3)
	    ELSE
	        (SELECT count(*)=1 AND COALESCE(bool_and(
	            endpoint.hostname=$4 AND endpoint.local_source_key<>''
	            AND endpoint.deployment_id IS NULL AND claim.deployment_id IS NULL
	            AND claim.membership_id=$3 AND (claim.retired_at IS NULL OR $5)),false)
	        FROM control.service_endpoints endpoint
	        LEFT JOIN control.service_namespace_claims claim
	          ON claim.namespace=endpoint.namespace
	          AND claim.local_source_key=endpoint.local_source_key AND claim.domain_id=endpoint.domain_id
	        WHERE endpoint.service_id=$1 AND (endpoint.retired_at IS NULL OR $5 AND endpoint.hostname=$4))
	    END`, service.ID, service.TeamID, member.id, service.CertificateHostname, retained).Scan(&owned)
	if err != nil {
		return err
	}
	if !owned {
		return denied
	}
	return nil
}

func (d *Database) CreateServiceAt(ctx context.Context, teamID, actorID, name, key string, placement ServicePlacement, now time.Time, metadata ServiceMetadata, configuration *ProjectServiceConfiguration) (result ServiceRecord, retErr error) {
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
	}{teamID, name, placement, ServiceMetadata{Protocol: metadata.Protocol, TLS: metadata.TLS, PublisherPool: metadata.PublisherPool}, configuration})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(intent)
	tx, err := d.pool.Begin(ctx)
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
	if err = serviceManager(ctx, tx, teamID, actorID); err != nil {
		return result, err
	}
	var existing string
	err = tx.QueryRow(ctx, `SELECT id FROM control.services WHERE created_by_identity_id=$1 AND idempotency_key=$2`, actorID, key).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
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
			row.Name != name || row.NameScope != "member/"+actorID+"/"+placement.WorktreeKey ||
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
		previous, err := d.openServiceConfiguration(row.ID, row.Name, stored.StorageKeyID.String, stored.ConfigurationCiphertext, "")
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
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return result, nil
	}
	if err = requireNewServiceWork(ctx, controlstatedb.New(tx), MaintenanceControlServiceCreation); err != nil {
		return result, err
	}
	_, err = controlstatedb.New(tx).InsertService(ctx, controlstatedb.InsertServiceParams{
		ID: id, TeamID: text(teamID), Name: name, NameScope: "member/" + actorID + "/" + placement.WorktreeKey, CreatedByIdentityID: text(actorID),
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
	if err = d.ensureLocalServiceEndpoint(ctx, tx, id, actorID, name, placement, public, now); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).LockService(ctx, id)
	if err != nil {
		return result, err
	}
	// the initial manager receives a revocable exact-service grant. this
	// default grant still requires a current owner/admin membership.
	ownerGrantID, err := opaqueid.New(opaqueid.ServiceGrantPrefix)
	if err != nil {
		return result, err
	}
	ownerDigest := sha256.Sum256([]byte("service-owner:" + id))
	if _, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,service_id,team_id,kind,identity_id,auto_owner,created_by_identity_id,idempotency_key,request_digest,created_at)
	    VALUES($1,$2,$3,'identity',$4,true,$4,$5,$6,$7)`, ownerGrantID, id, teamID, actorID, "owner/"+id, ownerDigest[:], now); err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, id, actorID, "service.create", id, now); err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, id, actorID, "grant.create", ownerGrantID, now); err != nil {
		return result, err
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
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
