package controlstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
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
	var locked string
	err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, teamID).Scan(&locked)
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

func (d *Database) CreatePrivateServiceGrant(ctx context.Context, serviceID, actorID, key, kind, identityID string, expires *time.Time, now time.Time) (result PrivateServiceGrant, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || len(key) == 0 || len(key) > 128 ||
		(kind != "team" && kind != "identity") || (kind == "team") != (identityID == "") ||
		expires != nil && !expires.After(now) {
		return result, ErrPrivateServiceAccess
	}
	id, err := opaqueid.New(opaqueid.PrivateServiceGrantPrefix)
	if err != nil {
		return result, err
	}
	expiry := ""
	if expires != nil {
		expiry = expires.UTC().Format(time.RFC3339Nano)
	}
	digest := sha256.Sum256([]byte(serviceID + "\x00" + kind + "\x00" + identityID + "\x00" + expiry))
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create private service grant", &retErr)()
	service, err := lockManagedPrivateService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	if identityID != "" {
		var active bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.identities WHERE id=$1 AND disabled_at IS NULL)`, identityID).Scan(&active); err != nil {
			return result, err
		}
		if !active {
			return result, ErrPrivateServiceAccess
		}
	}
	var existing controlstatedb.ControlPrivateServiceGrant
	// sqlc's create source has an exact active grant constraint; query the retry key before inserting.
	var oldID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.private_service_grants WHERE created_by_identity_id=$1 AND kind=$2 AND idempotency_key=$3`, actorID, kind, key).Scan(&oldID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if oldID != "" {
		err = tx.QueryRow(ctx, `SELECT id, private_service_id, team_id, kind, identity_id, invitation_id,
			created_by_identity_id, idempotency_key, request_digest, created_at, expires_at, revoked_at
			FROM control.private_service_grants WHERE id=$1 FOR UPDATE`, oldID).Scan(&existing.ID, &existing.PrivateServiceID,
			&existing.TeamID, &existing.Kind, &existing.IdentityID, &existing.InvitationID, &existing.CreatedByIdentityID,
			&existing.IdempotencyKey, &existing.RequestDigest, &existing.CreatedAt, &existing.ExpiresAt, &existing.RevokedAt)
		if err != nil {
			return result, err
		}
		if existing.PrivateServiceID != serviceID || existing.RevokedAt.Valid || !bytes.Equal(existing.RequestDigest, digest[:]) {
			return result, ErrPrivateServiceConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return privateGrantRecord(existing), nil
	}
	row, err := controlstatedb.New(tx).InsertPrivateServiceGrant(ctx, controlstatedb.InsertPrivateServiceGrantParams{
		ID: id, PrivateServiceID: serviceID, TeamID: service.TeamID, Kind: kind, IdentityID: nullableText(identityID),
		CreatedByIdentityID: actorID, IdempotencyKey: key, RequestDigest: digest[:], Now: timestamptz(now), ExpiresAt: nullableTime(expires),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return result, ErrPrivateServiceConflict
	}
	if err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "grant.create", row.ID, now); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privateGrantRecord(row), nil
}

func (d *Database) ListPrivateServiceGrants(ctx context.Context, serviceID, actorID string) (result []PrivateServiceGrant, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list private service grants", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListPrivateServiceGrants(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	result = make([]PrivateServiceGrant, 0, len(rows))
	for _, row := range rows {
		result = append(result, privateGrantRecord(row))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (d *Database) RevokePrivateServiceGrant(ctx context.Context, serviceID, actorID, grantID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(grantID, opaqueid.PrivateServiceGrantPrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke private service grant", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return err
	}
	if err = rejectProjectManagedGrant(ctx, tx, grantID); err != nil {
		return err
	}
	count, err := controlstatedb.New(tx).RevokePrivateServiceGrant(ctx, controlstatedb.RevokePrivateServiceGrantParams{ID: grantID, PrivateServiceID: serviceID, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrPrivateServiceAccess
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "grant.revoke", grantID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func privateServiceRecord(row controlstatedb.ControlPrivateService) PrivateServiceRecord {
	return PrivateServiceRecord{PrivateServiceMetadata: privateMetadata(row), ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID.String, Name: row.Name, Enabled: row.Enabled, CreatedAt: row.CreatedAt.Time, Placement: &PrivateServicePlacement{DomainID: row.DomainID.String, WorktreeKey: row.PlacementWorktreeKey, WorktreeLabel: row.PlacementWorktreeLabel}}
}

func privateServiceManager(ctx context.Context, tx pgx.Tx, teamID, actorID string) error {
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
	// the team lock serializes policy changes and private service creation.
	var locked string
	if err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, teamID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
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
		if row.DeletedAt.Valid || row.TeamID != teamID || row.Name != name || !privateMetadataMatches(privateMetadata(row), metadata) || row.PublisherPool != metadata.PublisherPool {
			return result, ErrPrivateServiceConflict
		}
		if err = d.ensureLocalManagedEndpoint(ctx, tx, row.ID, actorID, name, placement, now); err != nil {
			return result, err
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return privateServiceRecord(row), nil
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
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privateServiceRecord(row), nil
}

func (d *Database) ListPrivateServices(ctx context.Context, teamID, actorID, after string) ([]PrivateServiceRecord, string, error) {
	if after != "" && !opaqueid.Valid(after, opaqueid.PrivateServicePrefix) {
		return nil, "", ErrPrivateServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	if err = privateServiceManager(ctx, tx, teamID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListPrivateServicesForTeam(ctx, controlstatedb.ListPrivateServicesForTeamParams{TeamID: teamID, AfterID: after})
	if err != nil {
		return nil, "", err
	}
	result := make([]PrivateServiceRecord, 0, min(100, len(rows)))
	next := ""
	for index, row := range rows {
		if index == 100 {
			next = rows[index-1].ID
			break
		}
		result = append(result, privateServiceRecord(row))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}

func (d *Database) GetPrivateService(ctx context.Context, serviceID, actorID string) (result PrivateServiceRecord, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get private service", &retErr)()
	row, err := controlstatedb.New(tx).GetPrivateService(ctx, serviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PrivateServiceRecord{}, ErrPrivateServiceAccess
	} else if err != nil {
		return PrivateServiceRecord{}, err
	}
	if err = privateServiceManager(ctx, tx, row.TeamID, actorID); err != nil {
		return PrivateServiceRecord{}, err
	}
	result = privateServiceRecord(row)
	if err = tx.Commit(ctx); err != nil {
		return PrivateServiceRecord{}, err
	}
	return result, nil
}

func (d *Database) DeletePrivateService(ctx context.Context, serviceID, actorID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "delete private service", &retErr)()
	var teamID string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.private_services WHERE id=$1 AND deleted_at IS NULL`, serviceID).Scan(&teamID); errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	} else if err != nil {
		return err
	}
	var locked string
	if err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, teamID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	} else if err != nil {
		return err
	}
	if err = privateServiceManager(ctx, tx, teamID, actorID); err != nil {
		return err
	}
	if err = lockEnabledPrivateService(ctx, tx, serviceID); err != nil {
		return err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, serviceID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err = tx.Exec(ctx, `UPDATE control.private_service_runs SET state='closed', closed_at=$2
		WHERE private_service_id=$1 AND closed_at IS NULL`, serviceID, now); err != nil {
		return err
	}
	if _, err = q.DeletePrivateService(ctx, controlstatedb.DeletePrivateServiceParams{ID: serviceID, TeamID: teamID, Now: timestamptz(now)}); err != nil {
		return err
	}
	if err = privateRoutingTombstone(ctx, q, serviceID, now); err != nil {
		return err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.delete", serviceID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func privateRoutingTombstone(ctx context.Context, q *controlstatedb.Queries, serviceID string, now time.Time) error {
	return privateRunRoutingTombstone(ctx, q, serviceID, "", 0, now)
}

func privateRunRoutingTombstone(ctx context.Context, q *controlstatedb.Queries, serviceID, runID string, number int64, now time.Time) error {
	clock, err := q.LockPrivateServiceRoutingClock(ctx)
	if err != nil {
		return err
	}
	event, err := q.InsertPrivateServiceRoutingEvent(ctx, controlstatedb.InsertPrivateServiceRoutingEventParams{
		PrivateServiceID: serviceID, Kind: "tombstone", Projection: []byte("[]"),
		PrivateRunID: nullableText(runID), RunNumber: pgtype.Int8{Int64: number, Valid: runID != ""},
		ExpiresAt: timestamptz(now.Add(24 * time.Hour)), Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if event.Revision <= clock {
		return errors.New("controlstate: private routing clock is ahead of events")
	}
	_, err = q.AdvancePrivateServiceRoutingClock(ctx, controlstatedb.AdvancePrivateServiceRoutingClockParams{Revision: event.Revision, Now: timestamptz(now)})
	return err
}

type PrivateServiceInventory struct {
	PrivateServiceMetadata
	ID, TeamID, Name, PrivateRunID string
	RunNumber                      int64
	CreatedAt                      time.Time
}

type PrivateConnectorSession struct {
	Subject                                      VisitorSubject
	ID, PrivateServiceID, IdentityID, Credential string
	DeviceID                                     string
	IngressID, IngressAddress, TLSServerName     string
	SourceIP                                     netip.Addr
	ExpiresAt                                    time.Time
}

type PrivateVisitorValidity struct {
	Allowed    bool
	Admitted   bool
	ValidUntil time.Time
}

type PrivateServiceRelay struct {
	TLSServerName                string    `json:"tls_server_name"`
	PublisherConnectionID        string    `json:"publisher_connection_id"`
	ConnectionSlot               int16     `json:"connection_slot"`
	RelayServiceID               string    `json:"relay_service_id"`
	RelayID                      string    `json:"relay_id"`
	RelayRunID                   string    `json:"relay_run_id"`
	InternalRelayAddress         string    `json:"internal_relay_address"`
	RelayLeaseRevision           int64     `json:"relay_lease_revision"`
	ConnectionAssignmentRevision int64     `json:"connection_assignment_revision"`
	LeaseExpiresAt               time.Time `json:"lease_expires_at"`
}

type PrivateServiceProjection struct {
	PrivateServiceID, PrivateRunID, Kind string
	RunNumber, Revision                  int64
	ExpiresAt                            time.Time
	ConnectedRelays                      []PrivateServiceRelay
}

type PrivateServiceRoutingSnapshot struct {
	Revision int64
	Entries  []PrivateServiceProjection
}

func privateRoutingProjection(row controlstatedb.ControlPrivateServiceRoutingEvent, now time.Time) (PrivateServiceProjection, error) {
	result := PrivateServiceProjection{PrivateServiceID: row.PrivateServiceID, PrivateRunID: row.PrivateRunID.String,
		Kind: row.Kind, RunNumber: row.RunNumber.Int64, Revision: row.Revision, ExpiresAt: row.ExpiresAt.Time}
	if row.Kind == "upsert" {
		if err := json.Unmarshal(row.Projection, &result.ConnectedRelays); err != nil || len(result.ConnectedRelays) < 1 || len(result.ConnectedRelays) > 2 {
			return PrivateServiceProjection{}, fmt.Errorf("controlstate: invalid private service routing projection")
		}
		live := result.ConnectedRelays[:0]
		for _, relay := range result.ConnectedRelays {
			if relay.LeaseExpiresAt.After(now) {
				live = append(live, relay)
			}
		}
		result.ConnectedRelays = live
		if len(live) == 0 || !row.ExpiresAt.Time.After(now) {
			result.Kind, result.ConnectedRelays = "tombstone", nil
		}
	} else if row.Kind != "tombstone" {
		return PrivateServiceProjection{}, fmt.Errorf("controlstate: invalid private service routing event")
	}
	return result, nil
}

func (d *Database) ReadPrivateServiceSnapshot(ctx context.Context, lease IngressLeaseIdentity, now time.Time) (result PrivateServiceRoutingSnapshot, retErr error) {
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read private service snapshot", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	result.Revision, err = q.ReadPrivateServiceRoutingClock(ctx)
	if err != nil {
		return result, err
	}
	rows, err := q.ListPrivateServiceRoutingSnapshot(ctx, controlstatedb.ListPrivateServiceRoutingSnapshotParams{ThroughRevision: result.Revision, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	result.Entries = make([]PrivateServiceProjection, 0, len(rows))
	for _, row := range rows {
		entry, err := privateRoutingProjection(row, now)
		if err != nil {
			return PrivateServiceRoutingSnapshot{}, err
		}
		if entry.Kind == "upsert" {
			result.Entries = append(result.Entries, entry)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return PrivateServiceRoutingSnapshot{}, err
	}
	return result, nil
}

func (d *Database) ReadPrivateServiceEvents(ctx context.Context, lease IngressLeaseIdentity, after int64, now time.Time) (result PrivateServiceRoutingSnapshot, retErr error) {
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	if after < 0 {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read private service events", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	through, err := q.ReadPrivateServiceRoutingClock(ctx)
	if err != nil {
		return result, err
	}
	rows, err := q.ListPrivateServiceRoutingEvents(ctx, controlstatedb.ListPrivateServiceRoutingEventsParams{
		AfterRevision: after, ThroughRevision: through, PageLimit: 256,
	})
	if err != nil {
		return result, err
	}
	result.Revision = after
	result.Entries = make([]PrivateServiceProjection, 0, len(rows))
	for _, row := range rows {
		entry, err := privateRoutingProjection(row, now)
		if err != nil {
			return PrivateServiceRoutingSnapshot{}, err
		}
		result.Entries = append(result.Entries, entry)
		result.Revision = row.Revision
	}
	if len(rows) == 0 {
		result.Revision = through
	}
	if err = tx.Commit(ctx); err != nil {
		return PrivateServiceRoutingSnapshot{}, err
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

func (d *Database) ListAvailablePrivateServices(ctx context.Context, identityID, cursor string, now time.Time) ([]PrivateServiceInventory, string, error) {
	if cursor != "" && !opaqueid.Valid(cursor, opaqueid.PrivateServicePrefix) {
		return nil, "", ErrPrivateServiceAccess
	}
	rows, err := controlstatedb.New(d.pool).ListAvailablePrivateServices(ctx, controlstatedb.ListAvailablePrivateServicesParams{
		ControlSessionID: companySessionID(ctx, identityID),
		IdentityID:       identityID, AfterID: cursor, Now: timestamptz(now),
	})
	if err != nil {
		return nil, "", fmt.Errorf("controlstate: list private services: %w", err)
	}
	page := make([]PrivateServiceInventory, 0, min(len(rows), 100))
	next := ""
	for i, row := range rows {
		if i == 100 {
			next = rows[i-1].ID
			break
		}
		metadata, err := decodePrivateMetadata(row.Protocol, row.TlsMetadata, row.PublisherPool, row.TrustRevision)
		if err != nil {
			return nil, "", err
		}
		metadata.ManagedTLS = managedServiceTLS(row.CertificateHostname, int(row.ServicePort.Int32), row.Public)
		page = append(page, PrivateServiceInventory{PrivateServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID, Name: row.Name, CreatedAt: row.CreatedAt.Time,
			PrivateRunID: row.PrivateRunID.String, RunNumber: row.RunNumber.Int64})
	}
	return page, next, nil
}

func lockEnabledPrivateService(ctx context.Context, tx pgx.Tx, id string) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.private_services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR UPDATE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	return err
}

// take the team lock before the saved service lock, matching grant and
// membership mutations; no claim can commit against a revoked grant snapshot.
func lockPrivateAdmission(ctx context.Context, tx pgx.Tx, id string) error {
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.private_services WHERE id=$1`, id).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	if err != nil {
		return err
	}
	var locked string
	err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, teamID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	if err != nil {
		return err
	}
	return lockEnabledPrivateService(ctx, tx, id)
}

func privateVisitorRecheckParams(lease IngressLeaseIdentity, serviceID, runID, sessionID, identityID, visitorID string,
	runNumber int64, source netip.Addr, now time.Time) controlstatedb.RecheckPrivateServiceVisitorParams {
	return controlstatedb.RecheckPrivateServiceVisitorParams{
		PrivateServiceID: serviceID, PrivateRunID: runID, ConnectorSessionID: sessionID,
		IdentityID: text(identityID), VisitorConnectionID: visitorID, RunNumber: runNumber,
		ObservedSourceIp: source.Unmap(), Now: timestamptz(now),
		IngressID: text(lease.IngressID), IngressRunID: text(lease.IngressRunID),
		IngressLeaseRevision: pgtype.Int8{Int64: int64(lease.IngressLeaseRevision), Valid: true},
	}
}

// RecheckPrivateServiceVisitor verifies the exact admitted visitor connection.
// it does not extend publisher or ingress leases or grant
// new permission; a revoked grant, stopped run, or lost ingress lease denies.
func (d *Database) RecheckPrivateServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, serviceID, runID, sessionID, identityID, visitorID string, runNumber int64, source netip.Addr, now time.Time) (result PrivateVisitorValidity, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(runID, opaqueid.PrivateRunPrefix) ||
		!opaqueid.Valid(sessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!opaqueid.Valid(identityID, opaqueid.IdentityPrefix) ||
		!opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) ||
		runNumber < 1 || !source.IsValid() || source.Zone() != "" {
		return result, ErrPrivateServiceAccess
	}
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "recheck private visitor", &retErr)()
	if err := lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		if errors.Is(err, ErrPrivateServiceAccess) {
			return PrivateVisitorValidity{ValidUntil: now}, nil
		}
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, q, lease, now); err != nil {
		if errors.Is(err, ErrIngressLeaseStale) {
			return PrivateVisitorValidity{ValidUntil: now}, nil
		}
		return result, err
	}
	row, err := q.RecheckPrivateServiceVisitor(ctx, privateVisitorRecheckParams(lease, serviceID, runID, sessionID, identityID, visitorID, runNumber, source, now))
	if err != nil {
		return result, err
	}
	if row.Allowed && (!row.ValidUntil.Valid || !row.ValidUntil.Time.After(now)) {
		return result, ErrPrivateServiceAccess
	}
	if row.Allowed {
		if _, err = tx.Exec(ctx, `UPDATE control.private_visitor_streams SET valid_until=$2 WHERE visitor_connection_id=$1 AND closed_at IS NULL`, visitorID, row.ValidUntil.Time); err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return PrivateVisitorValidity{Allowed: row.Allowed, ValidUntil: row.ValidUntil.Time}, nil
}
