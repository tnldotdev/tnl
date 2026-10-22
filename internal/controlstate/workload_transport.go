package controlstate

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// selection authenticates only the workload credential, never a human session.
// the selected run still needs a new source-bound admission at ingress.
func (d *Database) SelectWorkloadServiceRun(ctx context.Context, credential, service string, now time.Time) (PrivateServiceSelection, error) {
	auth, err := d.CheckWorkloadService(ctx, credential, service, now)
	if err != nil {
		return PrivateServiceSelection{}, err
	}
	return d.SelectVisitorServiceRun(ctx, service, auth.Subject, now)
}

func (d *Database) GetWorkloadIngressTransportTrust(ctx context.Context, credential, session string, now time.Time) (result IngressTransportTrust, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read workload ingress trust", &retErr)()
	id, err := lockWorkloadCredential(ctx, tx, credential, now)
	if err != nil {
		return result, err
	}
	var lease IngressLeaseIdentity
	var revision int64
	var service string
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT private_service_id,assigned_ingress_id,assigned_ingress_run_id,assigned_ingress_lease_revision,expires_at FROM control.private_connector_sessions WHERE id=$1 AND workload_session_id=$2 AND revoked_at IS NULL AND expires_at>$3 FOR SHARE`, session, id, now).Scan(&service, &lease.IngressID, &lease.IngressRunID, &revision, &expires)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	until, _, err := VisitorSubjectAccess(ctx, tx, service, workloadSubject(id), now)
	if err != nil {
		return result, err
	}
	lease.IngressLeaseRevision = uint64(revision)
	current, err := lockCurrentIngressLease(ctx, controlstatedb.New(tx), lease, now)
	if err != nil {
		return result, err
	}
	if current.Draining {
		return result, ErrPrivateServiceAccess
	}
	material, err := d.ingressTransportMaterial(ctx, tx, current, now)
	if err != nil {
		return result, err
	}
	result = material.IngressTransportTrust
	result.ValidUntil = minTime(result.ValidUntil, minTime(expires, until))
	return result, tx.Commit(ctx)
}

func (d *Database) ReleaseWorkloadIngressAssignment(ctx context.Context, credential, session string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "release workload ingress assignment", &retErr)()
	// cleanup can retire an exact owned handle after revocation or expiry. this
	// credential lookup is deliberately private to deletion, never admission.
	if len(credential) != 47 || credential[:4] != "wlc_" {
		return ErrWorkloadDenied
	}
	digest := sha256.Sum256([]byte(credential))
	var id string
	err = tx.QueryRow(ctx, `SELECT id FROM control.workload_sessions WHERE credential_digest=$1 FOR SHARE`, digest[:]).Scan(&id)
	if err != nil {
		return publisherLookupError(err, ErrWorkloadDenied)
	}
	var released string
	err = tx.QueryRow(ctx, `UPDATE control.private_connector_sessions SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND workload_session_id=$2 RETURNING id`, session, id, now).Scan(&released)
	if err != nil {
		return publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if _, err = tx.Exec(ctx, `UPDATE control.private_visitor_streams SET closed_at=COALESCE(closed_at,$2) WHERE connector_session_id=$1`, session, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
