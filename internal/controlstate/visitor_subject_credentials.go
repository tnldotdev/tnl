package controlstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// AuthenticateVisitorConnector binds one assigned session once, with the exact
// subject's key and ingress-observed source. both visitor variants use this seam.
func (d *Database) AuthenticateVisitorConnector(ctx context.Context, lease IngressLeaseIdentity, claim tunnelv1.VisitorConnectorClaim, source netip.Addr, now time.Time) (result PrivateConnectorSession, retErr error) {
	proof, err := claim.Digest()
	if err != nil || !source.IsValid() || source.Zone() != "" {
		return result, ErrPrivateServiceAccess
	}
	digest, err := privateSecretDigest(claim.Credential)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authenticate visitor connector", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, claim.ServiceID); err != nil {
		return result, err
	}
	current, err := lockCurrentIngressLease(ctx, controlstatedb.New(tx), lease, now)
	if err != nil {
		return result, err
	}
	if current.Draining {
		return result, ErrPrivateServiceAccess
	}
	var stored []byte
	var identity, device, workload, controlSession string
	err = tx.QueryRow(ctx, `SELECT credential_digest,COALESCE(identity_id,''),COALESCE(device_id,''),COALESCE(workload_session_id,''),expires_at,COALESCE(control_session_id,'') FROM control.private_connector_sessions WHERE id=$1 AND private_service_id=$2 AND assigned_ingress_id=$3 AND assigned_ingress_run_id=$4 AND assigned_ingress_lease_revision=$5 AND revoked_at IS NULL AND bound_at IS NULL AND expires_at>$6 FOR UPDATE`, claim.SessionID, claim.ServiceID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now).Scan(&stored, &identity, &device, &workload, &result.ExpiresAt, &controlSession)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if identity != claim.Subject.IdentityID || device != claim.Subject.DeviceID || workload != claim.Subject.WorkloadSessionID || !bytes.Equal(stored, digest) {
		return result, ErrPrivateServiceAccess
	}
	if identity != "" {
		ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: identity, SessionID: controlSession})
	}
	key, until, err := AuthenticateVisitorSubjectKey(ctx, tx, claim.Subject, claim.ServiceID, now)
	if err != nil {
		return result, err
	}
	if len(key) != ed25519.PublicKeySize || len(claim.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, proof, claim.Signature) {
		return result, ErrPrivateServiceAccess
	}
	if _, err = tx.Exec(ctx, `UPDATE control.private_connector_sessions SET bound_at=$2,source_ip=$3,ingress_id=$4,ingress_run_id=$5,ingress_lease_revision=$6 WHERE id=$1`, claim.SessionID, now, source.Unmap(), lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision)); err != nil {
		return result, err
	}
	result.ID, result.PrivateServiceID, result.Subject, result.IdentityID, result.DeviceID, result.SourceIP = claim.SessionID, claim.ServiceID, claim.Subject, identity, device, source.Unmap()
	if claim.Subject.Kind == tunnelv1.VisitorHumanDevice {
		result.ExpiresAt = minTime(result.ExpiresAt, until)
	}
	return result, tx.Commit(ctx)
}

// RecheckVisitorServiceStream is the subject-aware counterpart to the current
// human wire adapter. it never treats a workload session ID as an identity ID.
func (d *Database) RecheckVisitorServiceStream(ctx context.Context, lease IngressLeaseIdentity, service, run, session, visitor string, subject VisitorSubject, number int64, source netip.Addr, now time.Time) (result PrivateVisitorValidity, retErr error) {
	if subject.Validate() != nil {
		return result, ErrPrivateServiceAccess
	}
	if subject.WorkloadSessionID == "" {
		// the human decision also binds the device carried by the new tagged
		// request. session identity/device fields are immutable after creation.
		var matches bool
		if err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.private_connector_sessions WHERE id=$1 AND identity_id=$2 AND device_id=$3 AND workload_session_id IS NULL)`, session, subject.IdentityID, subject.DeviceID).Scan(&matches); err != nil {
			return result, err
		}
		if !matches {
			return result, ErrPrivateServiceAccess
		}
		return d.RecheckPrivateServiceVisitor(ctx, lease, service, run, session, subject.IdentityID, visitor, number, source, now)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "recheck workload stream", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	if _, err = lockCurrentIngressLease(ctx, controlstatedb.New(tx), lease, now); err != nil {
		return result, err
	}
	result, err = recheckWorkloadServiceStream(ctx, tx, lease, service, run, session, visitor, subject, number, source, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func recheckWorkloadServiceStream(ctx context.Context, tx pgx.Tx, lease IngressLeaseIdentity, service, run, session, visitor string, subject VisitorSubject, number int64, source netip.Addr, now time.Time) (result PrivateVisitorValidity, err error) {
	until, _, err := VisitorSubjectAccess(ctx, tx, service, subject, now)
	if err != nil {
		return PrivateVisitorValidity{ValidUntil: now}, nil
	}
	var deadline time.Time
	err = tx.QueryRow(ctx, `SELECT LEAST(w.expires_at,r.publisher_expires_at,r.certificate_expires_at,i.lease_expires_at,g.expires_at,
        (SELECT max(l.lease_expires_at) FROM control.private_service_connection_slots slot JOIN control.relay_leases l ON l.relay_id=slot.relay_id AND l.relay_run_id=slot.relay_run_id AND l.relay_lease_revision=slot.relay_lease_revision AND l.relay_service_id=slot.relay_service_id WHERE slot.private_run_id=r.id AND slot.state='ready' AND slot.session_open AND l.lease_expires_at>$10 AND NOT l.draining))
        FROM control.private_visitor_streams v JOIN control.private_connector_sessions w ON w.id=v.connector_session_id AND w.private_service_id=v.private_service_id AND w.workload_session_id=v.workload_session_id
        JOIN control.ingress_leases i ON i.ingress_id=w.ingress_id AND i.ingress_run_id=w.ingress_run_id AND i.ingress_lease_revision=w.ingress_lease_revision AND i.lease_expires_at>$10
        JOIN control.private_service_runs r ON r.id=v.private_run_id AND r.private_service_id=v.private_service_id AND r.run_number=v.run_number AND r.state='ready' AND r.healthy AND r.closed_at IS NULL AND r.publisher_expires_at>$10 AND r.certificate_expires_at>$10
        JOIN control.publisher_grants g ON g.id=r.publisher_grant_id AND g.private_service_id=v.private_service_id AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$10)
        JOIN control.publisher_identities p ON p.id=r.publisher_identity_id AND p.id=g.publisher_identity_id AND p.revoked_at IS NULL
        WHERE v.visitor_connection_id=$1 AND v.private_service_id=$2 AND v.private_run_id=$3 AND v.connector_session_id=$4 AND v.workload_session_id=$5 AND v.run_number=$6 AND v.source_ip=$7 AND w.source_ip=$7 AND w.ingress_id=$8 AND w.ingress_run_id=$9 AND w.ingress_lease_revision=$11
        AND w.bound_at IS NOT NULL AND w.revoked_at IS NULL AND w.expires_at>$10 AND v.closed_at IS NULL AND v.valid_until>$10
        AND EXISTS(SELECT 1 FROM control.private_service_connection_slots slot JOIN control.relay_leases l ON l.relay_id=slot.relay_id AND l.relay_run_id=slot.relay_run_id AND l.relay_lease_revision=slot.relay_lease_revision AND l.relay_service_id=slot.relay_service_id WHERE slot.private_run_id=r.id AND slot.state='ready' AND slot.session_open AND l.lease_expires_at>$10 AND NOT l.draining)`, visitor, service, run, session, subject.WorkloadSessionID, number, source.Unmap(), lease.IngressID, lease.IngressRunID, now, int64(lease.IngressLeaseRevision)).Scan(&deadline)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	result.Allowed, result.Admitted, result.ValidUntil = true, true, minTime(until, deadline)
	if _, err = tx.Exec(ctx, `UPDATE control.private_visitor_streams SET valid_until=$2 WHERE visitor_connection_id=$1`, visitor, result.ValidUntil); err != nil {
		return result, err
	}
	return result, nil
}

type SubjectConnectorVisitor struct {
	Subject                 VisitorSubject
	SessionID, ConnectionID string
	Source                  netip.Addr
	GrantRevision           int64
}

// AuthorizeVisitorServiceConnector is the publisher-facing subject-aware
// authorization API. a current run token and the exact admitted stream are both
// required; a workload credential cannot impersonate a publisher.
func (d *Database) AuthorizeVisitorServiceConnector(ctx context.Context, service, run, token string, number int64, v SubjectConnectorVisitor, now time.Time) (result PrivateVisitorValidity, retErr error) {
	if v.Subject.Validate() != nil || v.GrantRevision < 1 || !opaqueid.Valid(v.ConnectionID, opaqueid.VisitorConnectionPrefix) || !opaqueid.Valid(v.SessionID, opaqueid.PrivateConnectorSessionPrefix) || !v.Source.IsValid() || v.Source.Zone() != "" {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize visitor service connector", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if err = d.managedHTTPSourceAllowed(ctx, q, service, v.Source); err != nil {
		return result, err
	}
	current, err := privateRunAuthorization(ctx, tx, q, service, run, token, now)
	if err != nil {
		return result, err
	}
	if current.RunNumber != number {
		return result, ErrPrivateServiceAccess
	}
	var revisionMatch bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.private_visitor_streams WHERE visitor_connection_id=$1 AND private_service_id=$2 AND private_run_id=$3 AND connector_session_id=$4 AND run_number=$5 AND grant_revision=$6)`, v.ConnectionID, service, run, v.SessionID, number, v.GrantRevision).Scan(&revisionMatch); err != nil {
		return result, err
	}
	if !revisionMatch {
		return result, ErrPrivateServiceAccess
	}
	if v.Subject.Kind == tunnelv1.VisitorHumanDevice {
		result, err = recheckServiceConnector(ctx, tx, service, run, number, ConnectorVisitor{IdentityID: v.Subject.IdentityID, DeviceID: v.Subject.DeviceID, SessionID: v.SessionID, ConnectionID: v.ConnectionID, Source: v.Source}, now)
		if err != nil {
			return result, err
		}
		result.Admitted = result.Allowed
		return result, tx.Commit(ctx)
	}
	var lease IngressLeaseIdentity
	var revision int64
	err = tx.QueryRow(ctx, `SELECT ingress_id,ingress_run_id,ingress_lease_revision FROM control.private_connector_sessions WHERE id=$1 AND private_service_id=$2 AND workload_session_id=$3 AND bound_at IS NOT NULL AND revoked_at IS NULL`, v.SessionID, service, v.Subject.WorkloadSessionID).Scan(&lease.IngressID, &lease.IngressRunID, &revision)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	lease.IngressLeaseRevision = uint64(revision)
	result, err = recheckWorkloadServiceStream(ctx, tx, lease, service, run, v.SessionID, v.ConnectionID, v.Subject, number, v.Source, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
