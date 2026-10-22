package controlstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
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
// reservations stop counting immediately; bound sessions and their streams are
// revoked so active rechecks close them. no sibling assignment is touched.
func (d *Database) ReleaseVisitorIngressAssignment(ctx context.Context, identityID, sessionID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(sessionID, opaqueid.PrivateConnectorSessionPrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "release visitor ingress assignment", &retErr)()
	var id string
	err = tx.QueryRow(ctx, `UPDATE control.private_connector_sessions session SET revoked_at=COALESCE(session.revoked_at,$3)
	    FROM control.visitor_devices device,control.identities person WHERE session.id=$1 AND session.identity_id=$2
	    AND device.id=session.device_id AND device.identity_id=session.identity_id AND person.id=device.identity_id AND person.disabled_at IS NULL
	    RETURNING session.id`, sessionID, identityID, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.private_visitor_streams SET closed_at=COALESCE(closed_at,$2) WHERE connector_session_id=$1`, sessionID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// enrolling an existing key is retry-stable. revocation is permanent: signing
// in again cannot resurrect a stolen device key.
func (d *Database) EnrollVisitorDevice(ctx context.Context, identityID string, key ed25519.PublicKey, now time.Time) (result VisitorDevice, err error) {
	if len(key) != ed25519.PublicKeySize {
		return result, ErrPrivateServiceAccess
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
		return result, ErrPrivateServiceAccess
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
		return ErrPrivateServiceAccess
	}
	if err = auditDeviceMutation(ctx, tx, identityID, deviceID, "device.revoke", now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// both assignments authenticate the same enrolled identity, but each has an
// independent session credential and ingress claim. neither grants a service.
func (d *Database) CreateVisitorIngressAssignments(ctx context.Context, identityID, deviceID, serviceID, key string, now time.Time) (result []PrivateConnectorSession, retErr error) {
	return d.createVisitorIngressAssignments(ctx, identityID, deviceID, serviceID, 2, "", key, now)
}

// single-slot renewal reserves only one other ingress. exclusion narrows
// placement; it never grants access or revokes an existing session.
func (d *Database) CreateVisitorIngressAssignment(ctx context.Context, identityID, deviceID, serviceID, excludeIngressID, key string, now time.Time) (PrivateConnectorSession, error) {
	assignments, err := d.createVisitorIngressAssignments(ctx, identityID, deviceID, serviceID, 1, excludeIngressID, key, now)
	if err != nil {
		return PrivateConnectorSession{}, err
	}
	return assignments[0], nil
}

func privateIngressAssignmentContext(scope string) string {
	return "private-ingress-assignment/" + scope
}

func (d *Database) createVisitorIngressAssignments(ctx context.Context, identityID, deviceID, serviceID string, count int, excludeIngressID, key string, now time.Time) (result []PrivateConnectorSession, retErr error) {
	if !validIdempotencyKey(key) || len(excludeIngressID) > 128 || strings.ContainsAny(excludeIngressID, "\x00\r\n") {
		return nil, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "create visitor ingress assignments", &retErr)()
	storageContext := privateIngressAssignmentContext(identityID + "/" + key)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, storageContext); err != nil {
		return nil, err
	}
	var current string
	err = tx.QueryRow(ctx, `SELECT device.id FROM control.visitor_devices device JOIN control.identities person ON person.id=device.identity_id
	    WHERE device.id=$1 AND person.id=$2 AND person.disabled_at IS NULL AND device.revoked_at IS NULL FOR SHARE OF device,person`, deviceID, identityID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPrivateServiceAccess
	}
	if err != nil {
		return nil, err
	}
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return nil, err
	}
	if _, _, err = privateVisitorAccess(ctx, tx, serviceID, identityID, now); err != nil {
		return nil, err
	}
	request, err := json.Marshal([]any{identityID, deviceID, serviceID, count, excludeIngressID})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(request)
	q := controlstatedb.New(tx)
	previous, err := q.GetPrivateIngressAssignmentRequest(ctx, controlstatedb.GetPrivateIngressAssignmentRequestParams{IdentityID: identityID, IdempotencyKey: key})
	if err == nil {
		if !bytes.Equal(previous.RequestDigest, digest[:]) {
			return nil, ErrPrivateServiceConflict
		}
		if !previous.ExpiresAt.Time.After(now) {
			return nil, ErrPrivateServiceAccess
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
			err = tx.QueryRow(ctx, `SELECT session.id FROM control.private_connector_sessions session
			    JOIN control.ingress_leases lease ON lease.ingress_id=session.assigned_ingress_id
			    AND lease.ingress_run_id=session.assigned_ingress_run_id AND lease.ingress_lease_revision=session.assigned_ingress_lease_revision
			    WHERE session.id=$1 AND session.identity_id=$2 AND session.device_id=$3 AND session.private_service_id=$4
			    AND session.bound_at IS NULL AND session.revoked_at IS NULL AND session.expires_at>$5
			    AND lease.lease_expires_at>$5 AND NOT lease.draining
			    AND lease.private_connector_address=$6 AND lease.private_connector_tls_server_name=$7
			    FOR SHARE OF session,lease`, session.ID, identityID, deviceID, serviceID, now, session.IngressAddress, session.TLSServerName).Scan(&current)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrPrivateServiceAccess
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
	placements, err := privateIngressPlacements(ctx, tx, now, count, excludeIngressID)
	if err != nil {
		return nil, err
	}
	for _, placement := range placements {
		id, err := opaqueid.New(opaqueid.PrivateConnectorSessionPrefix)
		if err != nil {
			return nil, err
		}
		credential, digest, err := privateSecret()
		if err != nil {
			return nil, err
		}
		expires := now.Add(15 * time.Minute)
		_, err = tx.Exec(ctx, `INSERT INTO control.private_connector_sessions(id,credential_digest,private_service_id,identity_id,device_id,created_at,expires_at,control_session_id,
		    assigned_ingress_id,assigned_ingress_run_id,assigned_ingress_lease_revision)
		    VALUES($1,$2,$3,$4,$5,$6,$7,$11,$8,$9,$10)`, id, digest, serviceID, identityID, deviceID, now, expires, placement.id, placement.run, placement.revision, nullableText(companySessionID(ctx, identityID)))
		if err != nil {
			return nil, err
		}
		result = append(result, PrivateConnectorSession{ID: id, PrivateServiceID: serviceID, IdentityID: identityID, DeviceID: deviceID, Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identityID, DeviceID: deviceID}, Credential: credential, ExpiresAt: expires,
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
	if err = q.InsertPrivateIngressAssignmentRequest(ctx, controlstatedb.InsertPrivateIngressAssignmentRequestParams{
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

type PrivateServiceSelection struct {
	Subject VisitorSubject
	PrivateServiceMetadata
	PrivateServiceID, PrivateRunID, IdentityID, DeviceID string
	RunNumber                                            int64
	ExpiresAt                                            time.Time
}

// access is evaluated inside the team/service admission lock. the deadline
// includes the last currently valid grant, rather than the first matching one.
func privateVisitorAccess(ctx context.Context, tx pgx.Tx, serviceID, identityID string, now time.Time) (time.Time, int64, error) {
	var until time.Time
	var revision int64
	err := tx.QueryRow(ctx, `SELECT LEAST($3::timestamptz+interval '2 minutes',control.company_subject_deadline(s.team_id,i.id,$4,$3),CASE WHEN
	    EXISTS(SELECT 1 FROM control.private_service_grants g LEFT JOIN control.team_memberships m ON m.team_id=s.team_id AND m.identity_id=i.id AND control.active_membership(m.id,$3)
	        WHERE g.private_service_id=s.id AND g.revoked_at IS NULL AND g.expires_at IS NULL AND(NOT g.auto_owner OR m.role IN('owner','admin')) AND ((g.kind='identity' AND g.identity_id=i.id) OR(g.kind='team' AND m.id IS NOT NULL)))
	    THEN 'infinity'::timestamptz ELSE (SELECT max(g.expires_at) FROM control.private_service_grants g
	        LEFT JOIN control.team_memberships m ON m.team_id=s.team_id AND m.identity_id=i.id AND control.active_membership(m.id,$3)
	        WHERE g.private_service_id=s.id AND g.revoked_at IS NULL AND g.expires_at>$3 AND(NOT g.auto_owner OR m.role IN('owner','admin')) AND ((g.kind='identity' AND g.identity_id=i.id) OR(g.kind='team' AND m.id IS NOT NULL))) END),s.visitor_revision+t.policy_revision
	    FROM control.private_services s JOIN control.teams t ON t.id=s.team_id AND t.deleted_at IS NULL
	    JOIN control.identities i ON i.id=$2 AND i.disabled_at IS NULL WHERE s.id=$1 AND s.enabled AND s.deleted_at IS NULL
	    AND control.company_subject_session_authorized(s.team_id,i.id,$4,$3)
	    AND (EXISTS(SELECT 1 FROM control.private_service_grants g LEFT JOIN control.team_memberships m ON m.team_id=s.team_id AND m.identity_id=i.id AND control.active_membership(m.id,$3)
	        WHERE g.private_service_id=s.id AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$3) AND(NOT g.auto_owner OR m.role IN('owner','admin')) AND ((g.kind='identity' AND g.identity_id=i.id) OR(g.kind='team' AND m.id IS NOT NULL))))`, serviceID, identityID, now, companySessionID(ctx, identityID)).Scan(&until, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return until, 0, ErrPrivateServiceAccess
	}
	return until, revision, err
}

func (d *Database) SelectPrivateServiceRun(ctx context.Context, serviceID, identityID, deviceID string, now time.Time) (result PrivateServiceSelection, retErr error) {
	return d.SelectVisitorServiceRun(ctx, serviceID, VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identityID, DeviceID: deviceID}, now)
}

func (d *Database) SelectVisitorServiceRun(ctx context.Context, serviceID string, subject VisitorSubject, now time.Time) (result PrivateServiceSelection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "select private service run", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	until, _, err := VisitorSubjectAccess(ctx, tx, serviceID, subject, now)
	if err != nil {
		return result, err
	}
	service, err := controlstatedb.New(tx).LockPrivateService(ctx, serviceID)
	if err != nil {
		return result, err
	}
	// count only admitted streams with a current hard deadline. dead ingress
	// processes cannot hold capacity forever, and no established stream moves.
	err = tx.QueryRow(ctx, `SELECT run.id,run.run_number,LEAST(run.publisher_expires_at,g.expires_at,run.certificate_expires_at)
	    FROM control.publisher_service_runs runtime JOIN control.private_service_runs run ON run.id=runtime.id
	    JOIN control.publisher_grants g ON g.id=runtime.publisher_grant_id
	    JOIN control.publisher_identities p ON p.id=run.publisher_identity_id
	    WHERE runtime.service_id=$1 AND runtime.state='ready' AND runtime.healthy AND runtime.closed_at IS NULL AND runtime.publisher_expires_at>$2
	    AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$2) AND p.revoked_at IS NULL
	    AND run.certificate_expires_at>$2
	    AND EXISTS(SELECT 1 FROM control.publisher_service_connection_slots slot JOIN control.relay_leases lease ON lease.relay_id=slot.connected_relay_id
	        AND lease.relay_run_id=slot.connected_relay_run_id AND lease.relay_lease_revision=slot.connected_relay_lease_revision
	        AND lease.relay_service_id=slot.relay_service_id
	        WHERE slot.run_id=run.id AND slot.state='ready' AND slot.session_open AND lease.lease_expires_at>$2 AND NOT lease.draining AND lease.reported_streams<lease.stream_capacity)
	    AND GREATEST(runtime.reported_streams,(SELECT count(*) FROM control.private_service_visitor_capacity stream WHERE stream.private_run_id=run.id AND stream.closed_at IS NULL AND stream.valid_until>$2))<runtime.stream_capacity
	    ORDER BY GREATEST(runtime.reported_streams,(SELECT count(*) FROM control.private_service_visitor_capacity stream WHERE stream.private_run_id=run.id AND stream.closed_at IS NULL AND stream.valid_until>$2))::numeric/runtime.stream_capacity,run.run_number LIMIT 1`, serviceID, now).
		Scan(&result.PrivateRunID, &result.RunNumber, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	result.PrivateServiceID, result.IdentityID, result.DeviceID = serviceID, subject.IdentityID, subject.DeviceID
	result.Subject = subject
	result.ExpiresAt = minTime(result.ExpiresAt, until)
	result.PrivateServiceMetadata = privateMetadata(service)
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

type PrivateStreamAuthorization struct {
	PrivateServiceSelection
	ConnectorSessionID, VisitorConnectionID string
	SourceIP                                netip.Addr
	GrantRevision                           int64
	ValidUntil                              time.Time
}

func (d *Database) AuthorizePrivateServiceStream(ctx context.Context, lease IngressLeaseIdentity, serviceID, runID, sessionID, visitorID string, number int64, source netip.Addr, now time.Time) (result PrivateStreamAuthorization, retErr error) {
	if !opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) || number < 1 || !source.IsValid() || source.Zone() != "" {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize private service stream", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	current, err := lockCurrentIngressLease(ctx, q, lease, now)
	if err != nil {
		return result, err
	}
	if current.Draining {
		return result, ErrPrivateServiceAccess
	}
	var identity, device, controlSession, workload string
	var sessionExpires, ingressExpires time.Time
	err = tx.QueryRow(ctx, `SELECT COALESCE(session.identity_id,''),COALESCE(session.device_id,''),session.expires_at,ingress.lease_expires_at,COALESCE(session.control_session_id,''),COALESCE(session.workload_session_id,'') FROM control.private_connector_sessions session
	    JOIN control.ingress_leases ingress ON ingress.ingress_id=session.ingress_id AND ingress.ingress_run_id=session.ingress_run_id AND ingress.ingress_lease_revision=session.ingress_lease_revision
	    WHERE session.id=$1 AND session.bound_at IS NOT NULL AND session.revoked_at IS NULL AND session.expires_at>$2
	    AND session.source_ip=$3 AND session.ingress_id=$4 AND session.ingress_run_id=$5 AND session.ingress_lease_revision=$6 AND session.private_service_id=$7
	    FOR SHARE OF session`, sessionID, now, source.Unmap(), lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), serviceID).Scan(&identity, &device, &sessionExpires, &ingressExpires, &controlSession, &workload)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: identity, SessionID: controlSession})
	subject := VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identity, DeviceID: device}
	if workload != "" {
		subject = workloadSubject(workload)
	}
	until, revision, err := VisitorSubjectAccess(ctx, tx, serviceID, subject, now)
	if err != nil {
		return result, err
	}
	run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if run.State != "ready" || !run.Healthy || run.ClosedAt.Valid || run.RunNumber != number || !run.PublisherExpiresAt.Time.After(now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrPrivateServiceAccess
	}
	if _, err = q.GetPrivateRunPublisherIdentity(ctx, controlstatedb.GetPrivateRunPublisherIdentityParams{ID: run.ID, PrivateServiceID: serviceID, RunNumber: number, PublisherIdentityID: run.PublisherIdentityID, PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now)}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrPrivateServiceAccess
		}
		return result, err
	}
	var grantExpiry pgtype.Timestamptz
	if err = tx.QueryRow(ctx, `SELECT expires_at FROM control.publisher_grants WHERE id=$1`, run.PublisherGrantID).Scan(&grantExpiry); err != nil {
		return result, err
	}
	if grantExpiry.Valid && grantExpiry.Time.Before(until) {
		until = grantExpiry.Time
	}
	var capacity int
	var relayExpires time.Time
	err = tx.QueryRow(ctx, `SELECT count(*),max(lease.lease_expires_at) FROM control.private_service_connection_slots slot JOIN control.relay_leases lease
	    ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
	    WHERE slot.private_run_id=$1 AND slot.state='ready' AND slot.session_open AND lease.lease_expires_at>$2 AND NOT lease.draining AND lease.reported_streams<lease.stream_capacity`, runID, now).Scan(&capacity, &relayExpires)
	if err != nil {
		return result, ErrPrivateServiceAccess
	}
	if capacity < 1 {
		return result, ErrPrivateServiceAccess
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.private_service_visitor_capacity WHERE private_run_id=$1 AND valid_until>$2 AND closed_at IS NULL`, runID, now).Scan(&capacity); err != nil {
		return result, err
	}
	if max(capacity, int(run.ReportedStreams)) >= int(run.StreamCapacity) {
		return result, ErrPrivateServiceAccess
	}
	for _, deadline := range []time.Time{sessionExpires, ingressExpires, run.PublisherExpiresAt.Time, run.CertificateExpiresAt.Time, relayExpires} {
		if deadline.Before(until) {
			until = deadline
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.private_visitor_streams(visitor_connection_id,private_service_id,private_run_id,run_number,connector_session_id,identity_id,device_id,source_ip,grant_revision,valid_until,created_at,workload_session_id)
	    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, visitorID, serviceID, runID, number, sessionID, nullableText(identity), nullableText(device), source.Unmap(), revision, until, now, nullableText(workload))
	var constraint *pgconn.PgError
	if errors.As(err, &constraint) && constraint.Code == "23505" {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	result.PrivateServiceSelection = PrivateServiceSelection{PrivateServiceID: serviceID, PrivateRunID: runID, IdentityID: identity, DeviceID: device, RunNumber: number, ExpiresAt: until}
	result.Subject = subject
	result.ConnectorSessionID, result.VisitorConnectionID, result.SourceIP, result.GrantRevision, result.ValidUntil = sessionID, visitorID, source.Unmap(), revision, until
	return result, nil
}

func (d *Database) ClosePrivateServiceStream(ctx context.Context, lease IngressLeaseIdentity, sessionID, visitorID string, now time.Time) error {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) {
		return ErrPrivateServiceAccess
	}
	_, err := d.pool.Exec(ctx, `UPDATE control.private_visitor_streams stream SET closed_at=COALESCE(stream.closed_at,$3)
	    FROM control.private_connector_sessions session WHERE stream.visitor_connection_id=$1 AND stream.connector_session_id=$2 AND session.id=stream.connector_session_id
	    AND session.ingress_id=$4 AND session.ingress_run_id=$5 AND session.ingress_lease_revision=$6`, visitorID, sessionID, now, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision))
	return err
}
