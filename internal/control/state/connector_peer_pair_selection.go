package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type connectorRunSelection struct {
	id, hostname string
	number       int64
	until        time.Time
	pair         *ConnectorPeerPairReady
}

// select the run, its hostname, and both relay hints in one statement. a
// concurrent disconnect may make the hint stale but cannot mix two snapshots.
// the left join retains a routable run with just one ready connection.
func readConnectorRunSelection(ctx context.Context, tx pgx.Tx, candidate string, args ...any) (result connectorRunSelection, err error) {
	rows, err := tx.Query(ctx, `WITH candidate AS (`+candidate+`)
		SELECT r.id,r.run_number,r.certificate_hostname,c.valid_until,r.publisher_identity_id,
			COALESCE(leg.connection_slot,-1),COALESCE(leg.publisher_connection_id,''),
			COALESCE(leg.connection_assignment_revision,0),COALESCE(leg.relay_service_id,''),
			COALESCE(leg.relay_id,''),COALESCE(leg.relay_run_id,''),COALESCE(leg.relay_lease_revision,0),
			COALESCE(leg.relay_address,''),COALESCE(leg.tls_server_name,'')
		FROM candidate c JOIN control.service_runs r ON r.id=c.id AND r.run_number=c.run_number
		LEFT JOIN LATERAL (
			SELECT slot.* FROM control.service_connection_slots slot
			JOIN control.relay_leases l USING(relay_id,relay_run_id,relay_lease_revision,relay_service_id)
			JOIN control.relay_services s ON s.relay_service_id=slot.relay_service_id
			WHERE slot.service_run_id=r.id AND slot.service_id=r.service_id AND slot.run_number=r.run_number
			  AND slot.state='ready' AND slot.session_open AND l.serving_until>$2 AND NOT l.draining
			  AND s.enabled AND s.relay_address=slot.relay_address AND s.tls_server_name=slot.tls_server_name
		) leg ON true ORDER BY leg.connection_slot`, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	var pair ConnectorPeerPairReady
	var present [2]bool
	for rows.Next() {
		var slot int
		var leg ConnectorPeerPairRelay
		lease := &leg.RelayLease
		if err := rows.Scan(&result.id, &result.number, &result.hostname, &result.until, &pair.PublisherIdentityID,
			&slot, &leg.PublisherConnectionID, &leg.AssignmentRevision, &lease.RelayServiceID, &lease.RelayID,
			&lease.RelayRunID, &lease.RelayLeaseRevision, &leg.RelayAddress, &leg.TLSServerName); err != nil {
			return result, err
		}
		if slot >= 0 && slot < len(present) && opaqueid.Valid(leg.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) &&
			leg.AssignmentRevision > 0 && lease.RelayLeaseRevision > 0 {
			pair.Relays[slot], present[slot] = leg, true
		}
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if result.id == "" {
		return result, pgx.ErrNoRows
	}
	if present[0] && present[1] && pair.Relays[0].RelayLease.RelayServiceID != pair.Relays[1].RelayLease.RelayServiceID {
		result.pair = &pair
	}
	return result, nil
}

func connectorPairReadySelection(ctx context.Context, tx pgx.Tx, runID, serviceID string, number int64, now time.Time) (*ConnectorPeerPairReady, error) {
	const exact = `SELECT id,run_number,certificate_expires_at AS valid_until FROM control.service_runs
		WHERE id=$1 AND certificate_expires_at>$2 AND service_id=$3 AND run_number=$4`
	result, err := readConnectorRunSelection(ctx, tx, exact, runID, now, serviceID, number)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return result.pair, err
}
