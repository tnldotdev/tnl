package controlstate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type relayProcessLeaseIdentity struct {
	relayServiceID     string
	relayID            string
	relayRunID         string
	relayLeaseRevision int64
}

func replenishRouteSessionConnections(
	ctx context.Context,
	queries *controlstatedb.Queries,
	session controlstatedb.ControlRouteSession,
	routeSessionToken credentials.RouteSessionToken,
	validConnections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	now time.Time,
	credentialDuration time.Duration,
) (bool, error) {
	rows, err := queries.ListRouteSessionConnections(ctx, session.ID)
	if err != nil {
		return false, fmt.Errorf("controlstate: replenish route-session connections: list slots: %w", err)
	}
	if len(rows) != routeSessionConnectionCount {
		return false, errors.New("controlstate: replenish route-session connections: invalid slot count")
	}
	removedReady := false
	needsPlacement := false
	for index, row := range rows {
		if row.State != "ready" {
			needsPlacement = true
			continue
		}
		valid := false
		for _, connection := range validConnections {
			valid = valid || connection.PublisherConnectionID == row.PublisherConnectionID
		}
		if valid {
			continue
		}
		// Reuse a failed ready slot's reservation before considering a new
		// allocation. The SQL checks current service capacity and failed lease
		// identity, and changes ready -> assigned without an expired intermediate
		// state. The trigger therefore neither writes totals nor takes their guard.
		updated, err := replaceRouteSessionConnection(ctx, queries, row, routeSessionToken, relayServicePlacement{
			relayServiceID: row.RelayServiceID, relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
		}, now, credentialDuration)
		if errors.Is(err, pgx.ErrNoRows) {
			needsPlacement = true
			continue
		}
		if err != nil {
			return false, err
		}
		rows[index] = updated
		removedReady = true
	}
	if !needsPlacement {
		return removedReady, nil
	}
	// No broad locks were taken by reservation reuse, so a remaining allocation
	// can still acquire reservation -> service -> lease guards in normal order.
	availableServices, leases, err := availableRelayServicePlacements(ctx, queries, now)
	if err != nil {
		return false, fmt.Errorf("controlstate: replenish route-session connections: %w", err)
	}
	leaseIdentities := make(map[relayProcessLeaseIdentity]struct{}, len(leases))
	serviceConfigurations := make(map[string]relayServicePlacement, len(availableServices))
	for _, service := range availableServices {
		serviceConfigurations[service.relayServiceID] = service
	}
	for _, lease := range leases {
		leaseIdentities[relayProcessLeaseIdentity{
			relayServiceID: lease.RelayServiceID, relayID: lease.RelayID,
			relayRunID: lease.RelayRunID, relayLeaseRevision: lease.RelayLeaseRevision,
		}] = struct{}{}
	}

	reservedServices := make(map[string]bool, routeSessionConnectionCount)
	for _, row := range rows {
		reservedServices[row.RelayServiceID] = true
	}
	replace := make([]bool, len(rows))
	for index, row := range rows {
		valid := true
		switch row.State {
		case "assigned":
			_, serviceAvailable := serviceConfigurations[row.RelayServiceID]
			valid = row.PublisherConnectionCredentialExpiresAt.Valid &&
				row.PublisherConnectionCredentialExpiresAt.Time.After(now) && serviceAvailable
		case "connected", "ready":
			if !row.ConnectedRelayID.Valid || !row.ConnectedRelayRunID.Valid ||
				!row.ConnectedRelayLeaseRevision.Valid {
				valid = false
				break
			}
			_, leaseAvailable := leaseIdentities[relayProcessLeaseIdentity{
				relayServiceID: row.RelayServiceID, relayID: row.ConnectedRelayID.String,
				relayRunID:         row.ConnectedRelayRunID.String,
				relayLeaseRevision: row.ConnectedRelayLeaseRevision.Int64,
			}]
			valid = valid && leaseAvailable
			if row.State == "connected" {
				valid = valid && row.PublisherConnectionCredentialExpiresAt.Valid &&
					row.PublisherConnectionCredentialExpiresAt.Time.After(now)
			}
		default:
			valid = false
		}
		if valid {
			continue
		}
		replace[index] = true
		removedReady = removedReady || row.State == "ready"
		if row.State != "closed" && row.State != "expired" {
			if _, err := queries.ExpirePublisherConnection(ctx, controlstatedb.ExpirePublisherConnectionParams{
				ExpiredAt: timestamptz(now), PublisherConnectionID: row.PublisherConnectionID,
				RouteSessionID: row.RouteSessionID, ConnectionAssignmentRevision: row.ConnectionAssignmentRevision,
			}); errors.Is(err, pgx.ErrNoRows) {
				return false, ErrConnectionAssignmentStale
			} else if err != nil {
				return false, fmt.Errorf("controlstate: replenish route-session connections: expire slot %d: %w", row.ConnectionSlot, err)
			}
			if service, found := serviceConfigurations[row.RelayServiceID]; found {
				service.assignments--
				serviceConfigurations[row.RelayServiceID] = service
			}
		}
	}

	// Stored service IDs remain unique even on expired slots. Reserve both while
	// planning, so a returning service stays in its original slot and each write
	// is safe without temporarily weakening that constraint.
	placements := make([]relayServicePlacement, len(rows))
	for index, row := range rows {
		if !replace[index] {
			continue
		}
		if service := serviceConfigurations[row.RelayServiceID]; service.assignments < service.capacity {
			placements[index] = service
		} else {
			for _, candidate := range availableServices {
				service := serviceConfigurations[candidate.relayServiceID]
				if !reservedServices[service.relayServiceID] && service.assignments < service.capacity {
					placements[index] = service
					reservedServices[service.relayServiceID] = true
					break
				}
			}
		}
	}
	for index, row := range rows {
		placement := placements[index]
		if placement.relayServiceID == "" {
			continue
		}
		_, err := replaceRouteSessionConnection(ctx, queries, row, routeSessionToken, placement, now, credentialDuration)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrConnectionAssignmentStale
		}
		if err != nil {
			return false, err
		}
	}
	return removedReady, nil
}

func replaceRouteSessionConnection(
	ctx context.Context,
	queries *controlstatedb.Queries,
	row controlstatedb.ControlRouteSessionConnection,
	token credentials.RouteSessionToken,
	placement relayServicePlacement,
	now time.Time,
	credentialDuration time.Duration,
) (controlstatedb.ControlRouteSessionConnection, error) {
	if row.ConnectionAssignmentRevision <= 0 || row.ConnectionAssignmentRevision == math.MaxInt64 {
		return controlstatedb.ControlRouteSessionConnection{}, errors.New("controlstate: replenish route-session connections: assignment revision is exhausted")
	}
	publisherConnectionID, err := opaqueid.New("connection_")
	if err != nil {
		return controlstatedb.ControlRouteSessionConnection{}, fmt.Errorf("controlstate: replenish route-session connections: generate publisher connection ID: %w", err)
	}
	revision := row.ConnectionAssignmentRevision + 1
	credential, hash, err := credentials.DerivePublisherConnectionCredential(token, publisherConnectionCredentialContext(publisherConnectionID, revision))
	if err != nil {
		return controlstatedb.ControlRouteSessionConnection{}, fmt.Errorf("controlstate: replenish route-session connections: derive credential: %w", err)
	}
	updated, err := queries.ReplaceRouteSessionConnection(ctx, controlstatedb.ReplaceRouteSessionConnectionParams{
		NewPublisherConnectionID: publisherConnectionID, NewConnectionAssignmentRevision: revision,
		RelayServiceID: placement.relayServiceID, RelayAddress: placement.relayAddress,
		TlsServerName: placement.tlsServerName, PublisherConnectionCredentialDigest: hash[:],
		PublisherConnectionCredentialExpiresAt: timestamptz(now.Add(credentialDuration)), AssignedAt: timestamptz(now),
		RouteSessionID: row.RouteSessionID, ConnectionSlot: row.ConnectionSlot,
		PreviousPublisherConnectionID: row.PublisherConnectionID, PreviousConnectionAssignmentRevision: row.ConnectionAssignmentRevision,
	})
	if err != nil {
		return controlstatedb.ControlRouteSessionConnection{}, fmt.Errorf("controlstate: replenish route-session connections: replace slot %d: %w", row.ConnectionSlot, err)
	}
	if _, err := connectionAssignment(updated, credential); err != nil {
		return controlstatedb.ControlRouteSessionConnection{}, err
	}
	return updated, nil
}
