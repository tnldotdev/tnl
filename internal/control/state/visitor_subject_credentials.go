package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// AuthenticateVisitorConnector binds one assigned session once, with the exact
// subject's key and ingress-observed source. both visitor variants use this seam.
func (d *Database) AuthenticateVisitorConnector(ctx context.Context, lease IngressLeaseIdentity, claim tunnelv1.VisitorConnectorClaim, source netip.Addr, now time.Time) (result ConnectorSession, retErr error) {
	proof, err := claim.Digest()
	if err != nil || !source.IsValid() || source.Zone() != "" {
		return result, ErrServiceAccess
	}
	digest, err := serviceSecretDigest(claim.Credential)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authenticate visitor connector", &retErr)()
	if err = lockServiceAdmission(ctx, tx, claim.ServiceID); err != nil {
		return result, err
	}
	current, err := lockCurrentIngressLease(ctx, controlstatedb.New(tx), lease, now)
	if err != nil {
		return result, err
	}
	if current.Draining {
		return result, ErrServiceAccess
	}
	var stored []byte
	var identity, device, workload, controlSession string
	err = tx.QueryRow(ctx, `SELECT credential_digest,COALESCE(identity_id,''),COALESCE(device_id,''),COALESCE(workload_session_id,''),expires_at,COALESCE(control_session_id,'') FROM control.connector_sessions WHERE id=$1 AND service_id=$2 AND assigned_ingress_id=$3 AND assigned_ingress_run_id=$4 AND assigned_ingress_lease_revision=$5 AND revoked_at IS NULL AND bound_at IS NULL AND expires_at>$6 FOR UPDATE`, claim.SessionID, claim.ServiceID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now).Scan(&stored, &identity, &device, &workload, &result.ExpiresAt, &controlSession)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if identity != claim.Subject.IdentityID || device != claim.Subject.DeviceID || workload != claim.Subject.WorkloadSessionID || !bytes.Equal(stored, digest) {
		return result, ErrServiceAccess
	}
	if identity != "" {
		ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: identity, SessionID: controlSession})
	}
	key, until, err := AuthenticateVisitorSubjectKey(ctx, tx, claim.Subject, claim.ServiceID, now)
	if err != nil {
		return result, err
	}
	if len(key) != ed25519.PublicKeySize || len(claim.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, proof, claim.Signature) {
		return result, ErrServiceAccess
	}
	if _, err = tx.Exec(ctx, `UPDATE control.connector_sessions SET bound_at=$2,source_ip=$3,ingress_id=$4,ingress_run_id=$5,ingress_lease_revision=$6 WHERE id=$1`, claim.SessionID, now, source.Unmap(), lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision)); err != nil {
		return result, err
	}
	result.ID, result.ServiceID, result.Subject, result.IdentityID, result.DeviceID, result.SourceIP = claim.SessionID, claim.ServiceID, claim.Subject, identity, device, source.Unmap()
	if claim.Subject.Kind == tunnelv1.VisitorHumanDevice {
		result.ExpiresAt = minTime(result.ExpiresAt, until)
	}
	return result, tx.Commit(ctx)
}
