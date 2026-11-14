package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func connectorPairReadySelection(ctx context.Context, tx pgx.Tx, runID, serviceID string, number int64, now time.Time) (*ConnectorPeerPairReady, error) {
	var publisher string
	err := tx.QueryRow(ctx, `SELECT publisher_identity_id FROM control.service_runs
	    WHERE id=$1 AND service_id=$2 AND run_number=$3 AND certificate_expires_at>$4`, runID, serviceID, number, now).Scan(&publisher)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := connectorPeerPublication{scope: visitorscope.Scope{Kind: visitorscope.Service, ID: serviceID}, runID: runID, number: number, publisherID: publisher}
	ready, _, err := p.readyRelays(ctx, tx, now, false)
	return ready, err
}

func (p connectorPeerPublication) readyRelays(ctx context.Context, tx pgx.Tx, now time.Time, lockLeases bool) (*ConnectorPeerPairReady, time.Time, error) {
	slots, err := p.connections(ctx, controlstatedb.New(tx))
	if err != nil || len(slots) != 2 {
		return nil, time.Time{}, err
	}
	if slots[0].relayService == slots[1].relayService {
		return nil, time.Time{}, nil
	}
	ready := &ConnectorPeerPairReady{PublisherIdentityID: p.publisherID}
	var until time.Time
	for i, slot := range slots {
		if !slot.ready(p, i) {
			return nil, time.Time{}, nil
		}
		var relay ConnectorPeerPairRelay
		var revision int64
		var leaseUntil time.Time
		query := `SELECT lease.relay_service_id,lease.relay_id,lease.relay_run_id,lease.relay_lease_revision,service.relay_address,service.tls_server_name,lease.lease_expires_at
		    FROM control.relay_leases lease JOIN control.relay_services service ON service.relay_service_id=lease.relay_service_id
		    WHERE lease.relay_id=$1 AND lease.relay_run_id=$2 AND lease.relay_lease_revision=$3 AND lease.relay_service_id=$4
		    AND lease.lease_expires_at>$5 AND NOT lease.draining AND service.enabled`
		if lockLeases {
			query += ` FOR SHARE OF lease,service`
		}
		err := tx.QueryRow(ctx, query, slot.relayID.String, slot.relayRunID.String, slot.leaseRevision.Int64, slot.relayService, now).
			Scan(&relay.RelayLease.RelayServiceID, &relay.RelayLease.RelayID, &relay.RelayLease.RelayRunID, &revision, &relay.RelayAddress, &relay.TLSServerName, &leaseUntil)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (slot.address != relay.RelayAddress || slot.serverName != relay.TLSServerName) {
			return nil, time.Time{}, nil
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		relay.RelayLease.RelayLeaseRevision = uint64(revision)
		relay.PublisherConnectionID, relay.AssignmentRevision = slot.connectionID, slot.assignment
		ready.Relays[i] = relay
		if until.IsZero() || leaseUntil.Before(until) {
			until = leaseUntil
		}
	}
	return ready, until, nil
}
