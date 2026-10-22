package controlstate

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

var ErrPrivateServiceAccess = errors.New("private service access denied or no current run")
var ErrPrivateServiceConflict = errors.New("private service name or idempotency key conflicts")

var privateServiceName = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`)

type PrivateServiceRecord struct {
	PrivateServiceMetadata
	ID, TeamID, DomainID, Name string
	Placement                  *PrivateServicePlacement `json:"placement,omitempty"`
	Source                     *LocalServiceSource      `json:"source,omitempty"`
	HTTPLimits                 *ProjectHTTPApplicationLimits
	Enabled                    bool
	CreatedAt                  time.Time
}

type PrivateServiceGrant struct {
	ID, PrivateServiceID, Kind, IdentityID, InvitationID string
	CreatedAt                                            time.Time
	ExpiresAt, RevokedAt                                 *time.Time
}

func privateGrantRecord(row controlstatedb.ControlPrivateServiceGrant) PrivateServiceGrant {
	return PrivateServiceGrant{ID: row.ID, PrivateServiceID: row.PrivateServiceID, Kind: row.Kind,
		IdentityID: row.IdentityID.String, InvitationID: row.InvitationID.String,
		CreatedAt: row.CreatedAt.Time, ExpiresAt: optionalTime(row.ExpiresAt), RevokedAt: optionalTime(row.RevokedAt)}
}

func lockManagedPrivateService(ctx context.Context, tx pgx.Tx, serviceID, actorID string) (controlstatedb.ControlPrivateService, error) {
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.private_services WHERE id=$1 AND deleted_at IS NULL`, serviceID).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPrivateService{}, ErrPrivateServiceAccess
	}
	if err != nil {
		return controlstatedb.ControlPrivateService{}, err
	}
	_, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPrivateService{}, ErrPrivateServiceAccess
	}
	if err != nil {
		return controlstatedb.ControlPrivateService{}, err
	}
	if err = privateServiceManager(ctx, tx, teamID, actorID); err != nil {
		return controlstatedb.ControlPrivateService{}, err
	}
	service, err := controlstatedb.New(tx).LockPrivateService(ctx, serviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return service, ErrPrivateServiceAccess
	}
	if err != nil {
		return service, err
	}
	if service.TeamID != teamID || !service.Enabled || service.DeletedAt.Valid {
		return service, ErrPrivateServiceAccess
	}
	return service, nil
}

func checkedPrivateServiceRecord(row controlstatedb.ControlPrivateService) (PrivateServiceRecord, error) {
	metadata, err := checkedPrivateMetadata(row)
	if err != nil {
		return PrivateServiceRecord{}, err
	}
	return PrivateServiceRecord{PrivateServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID.String, Name: row.Name, Enabled: row.Enabled, CreatedAt: row.CreatedAt.Time, Placement: &PrivateServicePlacement{DomainID: row.DomainID.String, WorktreeKey: row.PlacementWorktreeKey, WorktreeLabel: row.PlacementWorktreeLabel}}, nil
}

func privateServiceManager(ctx context.Context, tx pgx.Tx, teamID, actorID string) error {
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
		return ErrPrivateServiceAccess
	}
	if err := requireTeamSession(ctx, controlstatedb.New(tx), teamID, actorID, time.Now()); err != nil {
		if errors.Is(err, ErrAuthorityAccess) {
			return errors.Join(ErrPrivateServiceAccess, err)
		}
		return err
	}
	return nil
}

func (d *Database) CreatePrivateService(ctx context.Context, teamID, actorID, name, key string, now time.Time, declared ...PrivateServiceMetadata) (result PrivateServiceRecord, retErr error) {
	return d.CreatePrivateServiceAt(ctx, teamID, actorID, name, key, PrivateServicePlacement{}, now, declared...)
}

func (d *Database) CreatePrivateServiceAt(ctx context.Context, teamID, actorID, name, key string, placement PrivateServicePlacement, now time.Time, declared ...PrivateServiceMetadata) (result PrivateServiceRecord, retErr error) {
	if err := placement.Validate(); err != nil {
		return result, err
	}
	metadata := PrivateServiceMetadata{Protocol: "tcp"}
	if len(declared) > 1 {
		return result, ErrPrivateServiceConflict
	}
	if len(declared) == 1 {
		metadata = declared[0]
	}
	if err := metadata.Validate(); err != nil {
		return result, err
	}
	if !privateServiceName.MatchString(name) || len(key) == 0 || len(key) > 128 {
		return result, ErrPrivateServiceAccess
	}
	id, err := opaqueid.New(opaqueid.PrivateServicePrefix)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256([]byte(teamID + "\x00" + name))
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create private service", &retErr)()
	// queue on the team advisory guard before taking its row, as apply does.
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	} else if err != nil {
		return result, err
	}
	if err = privateServiceManager(ctx, tx, teamID, actorID); err != nil {
		return result, err
	}
	var existing string
	err = tx.QueryRow(ctx, `SELECT id FROM control.private_services WHERE created_by_identity_id=$1 AND idempotency_key=$2`, actorID, key).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if existing != "" {
		row, err := controlstatedb.New(tx).LockPrivateService(ctx, existing)
		if err != nil {
			return result, err
		}
		saved, err := checkedPrivateMetadata(row)
		if err != nil {
			return result, err
		}
		if row.DeletedAt.Valid || row.TeamID != teamID || row.Name != name || !privateMetadataMatches(saved, metadata) || row.PublisherPool != metadata.PublisherPool {
			return result, ErrPrivateServiceConflict
		}
		if err = d.ensureLocalManagedEndpoint(ctx, tx, row.ID, actorID, name, placement, now); err != nil {
			return result, err
		}
		result, err = checkedPrivateServiceRecord(row)
		if err != nil {
			return result, err
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return result, nil
	}
	_, err = controlstatedb.New(tx).InsertPrivateService(ctx, controlstatedb.InsertPrivateServiceParams{
		ID: id, TeamID: teamID, Name: name, NameScope: "member/" + actorID + "/" + placement.WorktreeKey, CreatedByIdentityID: actorID,
		IdempotencyKey: key, RequestDigest: digest[:], Now: timestamptz(now),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return result, ErrPrivateServiceConflict
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
	if _, err = tx.Exec(ctx, `UPDATE control.private_services SET protocol=$2, tls_metadata=convert_from($3::bytea,'UTF8')::jsonb, publisher_pool=$4 WHERE id=$1`, id, metadata.Protocol, encoded, metadata.PublisherPool); err != nil {
		return result, err
	}
	if err = d.ensureLocalManagedEndpoint(ctx, tx, id, actorID, name, placement, now); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).LockPrivateService(ctx, id)
	if err != nil {
		return result, err
	}
	// the initial manager receives a revocable exact-service grant. this
	// default grant still requires a current owner/admin membership.
	ownerGrantID, err := opaqueid.New(opaqueid.PrivateServiceGrantPrefix)
	if err != nil {
		return result, err
	}
	ownerDigest := sha256.Sum256([]byte("private-service-owner:" + id))
	if _, err = tx.Exec(ctx, `INSERT INTO control.private_service_grants(id,private_service_id,team_id,kind,identity_id,auto_owner,created_by_identity_id,idempotency_key,request_digest,created_at)
	    VALUES($1,$2,$3,'identity',$4,true,$4,$5,$6,$7)`, ownerGrantID, id, teamID, actorID, "owner/"+id, ownerDigest[:], now); err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, id, actorID, "service.create", id, now); err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, id, actorID, "grant.create", ownerGrantID, now); err != nil {
		return result, err
	}
	result, err = checkedPrivateServiceRecord(row)
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

func privateSecretDigest(encoded string) ([]byte, error) {
	if len(encoded) != 43 {
		return nil, ErrPrivateServiceAccess
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return nil, ErrPrivateServiceAccess
	}
	digest := sha256.Sum256(secret)
	return digest[:], nil
}
