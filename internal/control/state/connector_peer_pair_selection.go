package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
	slots, err := controlstatedb.New(tx).ListServiceConnectionSlots(ctx, runID)
	if err != nil || len(slots) != 2 {
		return nil, err
	}
	if slots[0].RelayServiceID == slots[1].RelayServiceID {
		return nil, nil
	}
	ready := &ConnectorPeerPairReady{PublisherIdentityID: publisher}
	for i, slot := range slots {
		if int(slot.ConnectionSlot) != i || slot.ServiceID != serviceID || slot.RunNumber != number || slot.State != "ready" || !slot.SessionOpen ||
			!opaqueid.Valid(slot.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || slot.ConnectionAssignmentRevision < 1 ||
			!slot.RelayID.Valid || !slot.RelayRunID.Valid || !slot.RelayLeaseRevision.Valid || slot.RelayLeaseRevision.Int64 < 1 {
			return nil, nil
		}
		var relay ConnectorPeerPairRelay
		var revision int64
		err := tx.QueryRow(ctx, `SELECT lease.relay_service_id,lease.relay_id,lease.relay_run_id,lease.relay_lease_revision,service.relay_address,service.tls_server_name
		    FROM control.relay_leases lease JOIN control.relay_services service ON service.relay_service_id=lease.relay_service_id
		    WHERE lease.relay_id=$1 AND lease.relay_run_id=$2 AND lease.relay_lease_revision=$3 AND lease.relay_service_id=$4
		    AND lease.lease_expires_at>$5 AND NOT lease.draining AND service.enabled`, slot.RelayID.String, slot.RelayRunID.String, slot.RelayLeaseRevision.Int64, slot.RelayServiceID, now).
			Scan(&relay.RelayLease.RelayServiceID, &relay.RelayLease.RelayID, &relay.RelayLease.RelayRunID, &revision, &relay.RelayAddress, &relay.TLSServerName)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (slot.RelayAddress != relay.RelayAddress || slot.TlsServerName != relay.TLSServerName) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		relay.RelayLease.RelayLeaseRevision = uint64(revision)
		relay.PublisherConnectionID, relay.AssignmentRevision = slot.PublisherConnectionID, slot.ConnectionAssignmentRevision
		ready.Relays[i] = relay
	}
	return ready, nil
}
