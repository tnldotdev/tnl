package state

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrInsufficientPrivateIngresses = errors.New("controlstate: two live private connector ingress addresses are required")
var ErrPrivateIngressUnavailable = errors.New("private connector ingress assignment is unavailable")

type privateIngressPlacement struct {
	id, run, address, serverName string
	revision, capacity, load     int64
}

// lock in identity order, then count outstanding assignments in a fresh
// statement. concurrent setup cannot overbook the same advertised capacity.
func privateIngressPlacements(ctx context.Context, tx pgx.Tx, now time.Time, count int, exclude string) ([]privateIngressPlacement, error) {
	rows, err := tx.Query(ctx, `SELECT ingress_id,ingress_run_id,ingress_lease_revision,connector_address,connector_tls_server_name,connection_capacity,reported_connections
	    FROM control.ingress_leases ingress WHERE lease_expires_at>$1 AND NOT draining AND protocol_version=$3 AND connection_capacity>0
	    AND connector_address<>'' AND connector_tls_server_name<>'' AND ingress_id<>$2
	    AND NOT EXISTS(SELECT 1 FROM control.ingress_leases excluded WHERE excluded.ingress_id=$2 AND excluded.connector_address=ingress.connector_address)
	    ORDER BY ingress_id LIMIT 256 FOR UPDATE`, now, exclude, tunnelv1.Version)
	if err != nil {
		return nil, err
	}
	var candidates []privateIngressPlacement
	for rows.Next() {
		var p privateIngressPlacement
		if err = rows.Scan(&p.id, &p.run, &p.revision, &p.address, &p.serverName, &p.capacity, &p.load); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, p)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range candidates {
		p := &candidates[index]
		var assigned int64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.connector_sessions session
		    WHERE session.assigned_ingress_id=$1 AND session.assigned_ingress_run_id=$2
		    AND session.assigned_ingress_lease_revision=$3 AND session.bound_at IS NULL AND session.revoked_at IS NULL AND session.expires_at>$4
		    AND (EXISTS(SELECT 1 FROM control.visitor_devices device JOIN control.identities person ON person.id=device.identity_id AND person.disabled_at IS NULL WHERE device.id=session.device_id AND device.identity_id=session.identity_id AND device.revoked_at IS NULL)
		      OR EXISTS(SELECT 1 FROM control.workload_sessions workload JOIN control.workload_session_services rights ON rights.workload_session_id=workload.id AND rights.service_id=session.service_id WHERE workload.id=session.workload_session_id AND workload.revoked_at IS NULL AND workload.lease_expires_at>$4 AND workload.expires_at>$4))`, p.id, p.run, p.revision, now).Scan(&assigned); err != nil {
			return nil, err
		}
		if p.load >= p.capacity || assigned >= p.capacity-p.load {
			p.load = p.capacity
		} else {
			p.load += assigned
		}
	}
	slices.SortStableFunc(candidates, func(a, b privateIngressPlacement) int {
		left, right := float64(a.load)/float64(a.capacity), float64(b.load)/float64(b.capacity)
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
		return 0
	})
	var selected []privateIngressPlacement
	for _, p := range candidates {
		if p.load >= p.capacity || len(selected) > 0 && selected[0].address == p.address {
			continue
		}
		selected = append(selected, p)
		if len(selected) == count {
			return selected, nil
		}
	}
	if count == 1 {
		return nil, ErrPrivateIngressUnavailable
	}
	return nil, ErrInsufficientPrivateIngresses
}
