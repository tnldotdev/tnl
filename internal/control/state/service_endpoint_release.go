package state

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrServiceEndpointPublic = errors.New("disable public endpoint access before releasing its reservation")
var ErrServiceEndpointDNSPending = errors.New("wait for managed endpoint DNS cleanup before releasing its reservation")

// releasing capacity does not delete the service or its captured tls hostname.
// the caller must already have disabled exposure; exact binding checks prevent a
// delayed request from releasing a replacement reservation.
func (d *Database) ReleaseServiceEndpoint(ctx context.Context, service, actor string, revision int64, port int, now time.Time) (result ServiceRecord, retErr error) {
	if !opaqueid.Valid(service, opaqueid.ServicePrefix) {
		return result, ErrServiceAccess
	}
	if revision < 1 || port < 1024 || port > 65535 || now.IsZero() {
		return result, ErrServiceConflict
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "release service endpoint", &retErr)()
	row, err := lockService(ctx, tx, service, actor)
	if err != nil {
		return result, err
	}
	if row.TrustRevision != revision || !row.ServicePort.Valid || int(row.ServicePort.Int32) != port {
		return result, ErrServiceConflict
	}
	if row.Public {
		return result, ErrServiceEndpointPublic
	}
	if _, err = nextPrivateRevision(revision); err != nil {
		return result, err
	}
	// control has no dns work for unmanaged names. managed names must have
	// completed the private loopback replacement, and old names must be removed.
	// lock the receipts so a concurrent dns update cannot change this proof.
	endpoints, err := tx.Query(ctx, `SELECT hostname,public,dns_state,retired_at IS NOT NULL
	    FROM control.service_endpoints WHERE service_id=$1 ORDER BY hostname FOR UPDATE`, service)
	if err != nil {
		return result, err
	}
	cleared, current := true, false
	for endpoints.Next() {
		var hostname, state string
		var public, retired bool
		if err = endpoints.Scan(&hostname, &public, &state, &retired); err != nil {
			endpoints.Close()
			return result, err
		}
		if hostname == row.CertificateHostname && !retired {
			current = true
			cleared = cleared && !public && (state == "published" || state == "unmanaged")
		} else {
			cleared = cleared && retired && state == "removed"
		}
	}
	err = endpoints.Err()
	endpoints.Close()
	if err != nil {
		return result, err
	}
	if !cleared || !current {
		return result, ErrServiceEndpointDNSPending
	}
	// membership mutations share the team lock. session/assertion deadlines can
	// still expire while this operation waits for the service or dns rows.
	if proof, signed := serviceActor(ctx); signed {
		if !proof.identity.AssertionExpiry.After(time.Now()) {
			return result, ErrControlAuthentication
		}
	} else if err = requireTeamSession(ctx, controlstatedb.New(tx), row.TeamID, actor, time.Now()); err != nil {
		return result, errors.Join(ErrServiceAccess, err)
	}
	claim, err := tx.Exec(ctx, `UPDATE control.service_port_claims SET state='quarantined',
	    retired_run_number=$4,dns_cleared_at=$5,
	    reusable_after=GREATEST($5::timestamptz+interval '7 days',COALESCE(
	      (SELECT max(not_after) FROM control.acme_orders WHERE certificate_scope=$6),$5::timestamptz))
	    WHERE service_id=$1 AND ingress_pool_id=$2 AND port=$3 AND state='held'`,
		service, row.IngressPoolID, port, row.NextRunNumber-1, now, row.CertificateScope)
	if err != nil {
		return result, err
	}
	if claim.RowsAffected() != 1 {
		return result, ErrServiceConflict
	}
	if err = bindServicePort(ctx, tx, service, 0, false, now); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.services SET updated_at=$2 WHERE id=$1`, service, now); err != nil {
		return result, err
	}
	row, err = controlstatedb.New(tx).LockService(ctx, service)
	if err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, service, actor, "service.update", "endpoint-release/"+strconv.FormatInt(row.TrustRevision, 10), now); err != nil {
		return result, err
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = serviceSource(ctx, controlstatedb.New(tx), &result); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
