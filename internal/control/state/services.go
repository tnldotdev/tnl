package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrServiceAccess = errors.New("service access denied")
var ErrServiceRunUnavailable = errors.New("service has no ready publisher run")
var ErrServiceConflict = errors.New("service name or idempotency key conflicts")

var serviceName = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`)

type ServiceRecord struct {
	ServiceMetadata
	ID, TeamID, DomainID, Name string
	Placement                  *ServicePlacement   `json:"placement,omitempty"`
	Source                     *LocalServiceSource `json:"source,omitempty"`
	HTTPLimits                 *ProjectHTTPApplicationLimits
	Enabled                    bool
	CreatedAt                  time.Time
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
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1 AND deleted_at IS NULL`, serviceID).Scan(&teamID)
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
	if err = serviceManager(ctx, tx, teamID, actorID); err != nil {
		return controlstatedb.ControlService{}, err
	}
	service, err := controlstatedb.New(tx).LockService(ctx, serviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return service, ErrServiceAccess
	}
	if err != nil {
		return service, err
	}
	if service.TeamID != teamID || !service.Enabled || service.DeletedAt.Valid {
		return service, ErrServiceAccess
	}
	return service, nil
}

func checkedServiceRecord(row controlstatedb.ControlService) (ServiceRecord, error) {
	metadata, err := checkedServiceMetadata(row)
	if err != nil {
		return ServiceRecord{}, err
	}
	return ServiceRecord{ServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID.String, Name: row.Name, Enabled: row.Enabled, CreatedAt: row.CreatedAt.Time, Placement: &ServicePlacement{DomainID: row.DomainID.String, WorktreeKey: row.PlacementWorktreeKey, WorktreeLabel: row.PlacementWorktreeLabel}}, nil
}

func serviceManager(ctx context.Context, tx pgx.Tx, teamID, actorID string) error {
	if _, signed := serviceActor(ctx); signed {
		return serviceActorManager(ctx, tx, teamID, actorID, time.Now())
	}
	var current bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.teams team
		JOIN control.team_memberships member ON member.team_id = team.id
		JOIN control.identities person ON person.id = member.identity_id
		WHERE team.id = $1 AND person.id = $2 AND team.deleted_at IS NULL AND person.disabled_at IS NULL
		AND control.active_membership(member.id,CURRENT_TIMESTAMP) AND member.role IN ('owner','admin'))`, teamID, actorID).Scan(&current)
	if err != nil {
		return err
	}
	if !current {
		return ErrServiceAccess
	}
	if err := requireTeamSession(ctx, controlstatedb.New(tx), teamID, actorID, time.Now()); err != nil {
		if errors.Is(err, ErrAuthorityAccess) {
			return errors.Join(ErrServiceAccess, err)
		}
		return err
	}
	return nil
}

func (d *Database) CreateServiceAt(ctx context.Context, teamID, actorID, name, key string, placement ServicePlacement, now time.Time, metadata ServiceMetadata) (result ServiceRecord, retErr error) {
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
	digest := sha256.Sum256([]byte(teamID + "\x00" + name))
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
		if row.DeletedAt.Valid || row.TeamID != teamID || row.Name != name || !serviceMetadataMatches(saved, metadata) || row.PublisherPool != metadata.PublisherPool {
			return result, ErrServiceConflict
		}
		if err = d.ensureLocalServiceEndpoint(ctx, tx, row.ID, actorID, name, placement, now); err != nil {
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
	_, err = controlstatedb.New(tx).InsertService(ctx, controlstatedb.InsertServiceParams{
		ID: id, TeamID: teamID, Name: name, NameScope: "member/" + actorID + "/" + placement.WorktreeKey, CreatedByIdentityID: actorID,
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
	if _, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2, tls_metadata=convert_from($3::bytea,'UTF8')::jsonb, publisher_pool=$4 WHERE id=$1`, id, metadata.Protocol, encoded, metadata.PublisherPool); err != nil {
		return result, err
	}
	if err = d.ensureLocalServiceEndpoint(ctx, tx, id, actorID, name, placement, now); err != nil {
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
