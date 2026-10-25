package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type VisitorDevice struct {
	ID         string     `json:"id"`
	IdentityID string     `json:"identity_id"`
	PublicKey  string     `json:"public_key"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// release is idempotent for this person's exact device assignment. pending
// reservations stop counting immediately. the connector closes its bound path;
// visitor policy and permission deadlines fence any retained streams.
func (d *Database) ReleaseVisitorIngressAssignment(ctx context.Context, identityID, sessionID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(sessionID, opaqueid.ConnectorSessionPrefix) {
		return ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "release visitor ingress assignment", &retErr)()
	var id string
	err = tx.QueryRow(ctx, `UPDATE control.connector_sessions session SET revoked_at=COALESCE(session.revoked_at,$3)
	    FROM control.visitor_devices device,control.identities person WHERE session.id=$1 AND session.identity_id=$2
	    AND device.id=session.device_id AND device.identity_id=session.identity_id AND person.id=device.identity_id AND person.disabled_at IS NULL
	    RETURNING session.id`, sessionID, identityID, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// enrolling an existing key is retry-stable. revocation is permanent: signing
// in again cannot resurrect a stolen device key.
func (d *Database) EnrollVisitorDevice(ctx context.Context, identityID string, key ed25519.PublicKey, now time.Time) (result VisitorDevice, err error) {
	if len(key) != ed25519.PublicKeySize {
		return result, ErrServiceAccess
	}
	id, err := opaqueid.New("vdev_")
	if err != nil {
		return result, err
	}
	var public []byte
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "enroll visitor device", &err)()
	err = tx.QueryRow(ctx, `INSERT INTO control.visitor_devices(id,identity_id,public_key,created_at)
	    SELECT $1,id,$3,$4 FROM control.identities WHERE id=$2 AND disabled_at IS NULL
	    ON CONFLICT(identity_id,public_key) DO UPDATE SET public_key=EXCLUDED.public_key
	    WHERE control.visitor_devices.revoked_at IS NULL RETURNING id,identity_id,public_key,created_at`, id, identityID, []byte(key), now).
		Scan(&result.ID, &result.IdentityID, &public, &result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if err = auditDeviceMutation(ctx, tx, identityID, result.ID, "device.enroll", result.CreatedAt); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	result.PublicKey = hex.EncodeToString(public)
	return result, err
}

func (d *Database) RevokeVisitorDevice(ctx context.Context, identityID, deviceID string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke visitor device", &retErr)()
	tag, err := tx.Exec(ctx, `UPDATE control.visitor_devices SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND identity_id=$2`, deviceID, identityID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrServiceAccess
	}
	if err = auditDeviceMutation(ctx, tx, identityID, deviceID, "device.revoke", now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// both assignments authenticate the same enrolled identity, but each has an
// independent session credential and ingress claim. neither grants a service.
func (d *Database) CreateVisitorIngressAssignments(ctx context.Context, identityID, deviceID, serviceID, key string, now time.Time, preferred ...string) (result []ConnectorSession, retErr error) {
	return d.createVisitorIngressAssignments(ctx, identityID, deviceID, serviceID, 2, "", key, now, preferred)
}

// single-slot renewal reserves only one other ingress. exclusion narrows
// placement; it never grants access or revokes an existing session.
func (d *Database) CreateVisitorIngressAssignment(ctx context.Context, identityID, deviceID, serviceID, excludeIngressID, key string, now time.Time, preferred ...string) (ConnectorSession, error) {
	assignments, err := d.createVisitorIngressAssignments(ctx, identityID, deviceID, serviceID, 1, excludeIngressID, key, now, preferred)
	if err != nil {
		return ConnectorSession{}, err
	}
	return assignments[0], nil
}

func connectorIngressAssignmentContext(scope string) string {
	return "connector-ingress-assignment/" + scope
}

func (d *Database) createVisitorIngressAssignments(ctx context.Context, identityID, deviceID, serviceID string, count int, excludeIngressID, key string, now time.Time, preferred []string) (result []ConnectorSession, retErr error) {
	if !validIdempotencyKey(key) || len(excludeIngressID) > 128 || strings.ContainsAny(excludeIngressID, "\x00\r\n") {
		return nil, ErrServiceAccess
	}
	preferences, err := region.Preferences(preferred)
	if err != nil {
		return nil, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "create visitor ingress assignments", &retErr)()
	storageContext := connectorIngressAssignmentContext(identityID + "/" + key)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, storageContext); err != nil {
		return nil, err
	}
	var current string
	err = tx.QueryRow(ctx, `SELECT device.id FROM control.visitor_devices device JOIN control.identities person ON person.id=device.identity_id
	    WHERE device.id=$1 AND person.id=$2 AND person.disabled_at IS NULL AND device.revoked_at IS NULL FOR SHARE OF device,person`, deviceID, identityID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrServiceAccess
	}
	if err != nil {
		return nil, err
	}
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return nil, err
	}
	if _, _, err = privateVisitorAccess(ctx, tx, serviceID, identityID, now); err != nil {
		return nil, err
	}
	request, err := json.Marshal([]any{identityID, deviceID, serviceID, count, excludeIngressID, preferences})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(request)
	q := controlstatedb.New(tx)
	previous, err := q.GetConnectorIngressAssignmentRequest(ctx, controlstatedb.GetConnectorIngressAssignmentRequestParams{IdentityID: identityID, IdempotencyKey: key})
	if err == nil {
		if !bytes.Equal(previous.RequestDigest, digest[:]) {
			return nil, ErrServiceConflict
		}
		if !previous.ExpiresAt.Time.After(now) {
			return nil, ErrServiceAccess
		}
		plaintext, _, err := d.storageKey.Open(previous.StorageKeyID, storageContext, previous.ResultCiphertext)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(plaintext, &result); err != nil {
			return nil, err
		}
		for _, session := range result {
			var current string
			err = tx.QueryRow(ctx, `SELECT session.id FROM control.connector_sessions session
			    JOIN control.ingress_leases lease ON lease.ingress_id=session.assigned_ingress_id
			    AND lease.ingress_run_id=session.assigned_ingress_run_id AND lease.ingress_lease_revision=session.assigned_ingress_lease_revision
			    WHERE session.id=$1 AND session.identity_id=$2 AND session.device_id=$3 AND session.service_id=$4
			    AND session.bound_at IS NULL AND session.revoked_at IS NULL AND session.expires_at>$5
			    AND lease.lease_expires_at>$5 AND NOT lease.draining
			    AND lease.connector_address=$6 AND lease.connector_tls_server_name=$7
			    FOR SHARE OF session,lease`, session.ID, identityID, deviceID, serviceID, now, session.IngressAddress, session.TLSServerName).Scan(&current)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrServiceAccess
			}
			if err != nil {
				return nil, err
			}
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	placements, err := privateIngressPlacements(ctx, tx, now, count, excludeIngressID, preferences)
	if err != nil {
		return nil, err
	}
	for _, placement := range placements {
		id, err := opaqueid.New(opaqueid.ConnectorSessionPrefix)
		if err != nil {
			return nil, err
		}
		credential, digest, err := privateSecret()
		if err != nil {
			return nil, err
		}
		expires := now.Add(15 * time.Minute)
		_, err = tx.Exec(ctx, `INSERT INTO control.connector_sessions(id,credential_digest,service_id,identity_id,device_id,created_at,expires_at,control_session_id,
		    assigned_ingress_id,assigned_ingress_run_id,assigned_ingress_lease_revision)
		    VALUES($1,$2,$3,$4,$5,$6,$7,$11,$8,$9,$10)`, id, digest, serviceID, identityID, deviceID, now, expires, placement.id, placement.run, placement.revision, nullableText(companySessionID(ctx, identityID)))
		if err != nil {
			return nil, err
		}
		result = append(result, ConnectorSession{ID: id, ServiceID: serviceID, IdentityID: identityID, DeviceID: deviceID, Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identityID, DeviceID: deviceID}, Credential: credential, ExpiresAt: expires,
			Region:    placement.region,
			IngressID: placement.id, IngressAddress: placement.address, TLSServerName: placement.serverName})
	}
	plaintext, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	ciphertext, err := d.storageKey.Seal(storageContext, plaintext)
	if err != nil {
		return nil, err
	}
	if err = q.InsertConnectorIngressAssignmentRequest(ctx, controlstatedb.InsertConnectorIngressAssignmentRequestParams{
		IdentityID: identityID, IdempotencyKey: key, RequestDigest: digest[:], ResultCiphertext: ciphertext,
		StorageKeyID: d.storageKey.CurrentID(), ExpiresAt: timestamptz(result[0].ExpiresAt),
	}); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

type ServiceSelection struct {
	Subject VisitorSubject
	ServiceMetadata
	ServiceID, ServiceRunID, IdentityID, DeviceID string
	RunNumber                                     int64
	ExpiresAt                                     time.Time
}

// access is evaluated inside the team/service admission lock. the deadline
// includes the last currently valid grant, rather than the first matching one.
func privateVisitorAccess(ctx context.Context, tx pgx.Tx, serviceID, identityID string, now time.Time) (time.Time, int64, error) {
	var until time.Time
	var revision int64
	err := tx.QueryRow(ctx, `SELECT LEAST($3::timestamptz+interval '2 minutes',permission.expires_at),s.visitor_revision+t.policy_revision
	    FROM control.services s JOIN control.teams t ON t.id=s.team_id
	    CROSS JOIN LATERAL control.visitor_identity_permission('service',s.id,$2,$4,'',$3) permission
	    WHERE s.id=$1`, serviceID, identityID, now, companySessionID(ctx, identityID)).Scan(&until, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return until, 0, ErrServiceAccess
	}
	return until, revision, err
}

func (d *Database) SelectServiceRun(ctx context.Context, serviceID, identityID, deviceID string, now time.Time) (result ServiceSelection, retErr error) {
	return d.SelectVisitorServiceRun(ctx, serviceID, VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identityID, DeviceID: deviceID}, now)
}

func (d *Database) SelectVisitorServiceRun(ctx context.Context, serviceID string, subject VisitorSubject, now time.Time) (result ServiceSelection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "select service run", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	until, _, err := VisitorSubjectAccess(ctx, tx, serviceID, subject, now)
	if err != nil {
		return result, err
	}
	service, err := controlstatedb.New(tx).LockService(ctx, serviceID)
	if err != nil {
		return result, err
	}
	// publisher-reported occupancy ranks prepared runs. ingress and publisher
	// hold exact local reservations without per-visitor database rows.
	err = tx.QueryRow(ctx, `SELECT run.id,run.run_number,LEAST(run.publisher_expires_at,g.expires_at,run.certificate_expires_at)
	    FROM control.publisher_service_runs runtime JOIN control.service_runs run ON run.id=runtime.id
	    JOIN control.publisher_grants g ON g.id=runtime.publisher_grant_id
	    JOIN control.publisher_identities p ON p.id=run.publisher_identity_id
	    WHERE runtime.service_id=$1 AND runtime.state='ready' AND runtime.healthy AND runtime.closed_at IS NULL AND runtime.publisher_expires_at>$2
	    AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$2) AND p.revoked_at IS NULL
	    AND run.certificate_expires_at>$2
	    AND EXISTS(SELECT 1 FROM control.publisher_service_connection_slots slot JOIN control.relay_leases lease ON lease.relay_id=slot.connected_relay_id
	        AND lease.relay_run_id=slot.connected_relay_run_id AND lease.relay_lease_revision=slot.connected_relay_lease_revision
	        AND lease.relay_service_id=slot.relay_service_id
	        WHERE slot.run_id=run.id AND slot.state='ready' AND slot.session_open AND lease.lease_expires_at>$2 AND NOT lease.draining AND lease.reported_streams<lease.stream_capacity)
	    AND runtime.reported_streams<runtime.stream_capacity
	    ORDER BY runtime.reported_streams::numeric/runtime.stream_capacity,run.run_number LIMIT 1`, serviceID, now).
		Scan(&result.ServiceRunID, &result.RunNumber, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceRunUnavailable
	}
	if err != nil {
		return result, err
	}
	result.ServiceID, result.IdentityID, result.DeviceID = serviceID, subject.IdentityID, subject.DeviceID
	result.Subject = subject
	result.ExpiresAt = minTime(result.ExpiresAt, until)
	result.ServiceMetadata, err = checkedServiceMetadata(service)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
