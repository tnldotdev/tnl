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
	removedReady := false
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
		if row.ConnectionAssignmentRevision <= 0 || row.ConnectionAssignmentRevision == math.MaxInt64 {
			return false, errors.New("controlstate: replenish route-session connections: assignment revision is exhausted")
		}
		publisherConnectionID, err := opaqueid.New("connection_")
		if err != nil {
			return false, fmt.Errorf("controlstate: replenish route-session connections: generate publisher connection ID: %w", err)
		}
		revision := row.ConnectionAssignmentRevision + 1
		credential, hash, err := credentials.DerivePublisherConnectionCredential(
			routeSessionToken, publisherConnectionCredentialContext(publisherConnectionID, revision),
		)
		if err != nil {
			return false, fmt.Errorf("controlstate: replenish route-session connections: derive credential: %w", err)
		}
		updated, err := queries.ReplaceRouteSessionConnection(ctx, controlstatedb.ReplaceRouteSessionConnectionParams{
			NewPublisherConnectionID: publisherConnectionID, NewConnectionAssignmentRevision: revision,
			RelayServiceID: placement.relayServiceID, RelayAddress: placement.relayAddress,
			TlsServerName: placement.tlsServerName, PublisherConnectionCredentialDigest: hash[:],
			PublisherConnectionCredentialExpiresAt: timestamptz(now.Add(credentialDuration)), AssignedAt: timestamptz(now),
			RouteSessionID: session.ID, ConnectionSlot: row.ConnectionSlot,
			PreviousPublisherConnectionID:        row.PublisherConnectionID,
			PreviousConnectionAssignmentRevision: row.ConnectionAssignmentRevision,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrConnectionAssignmentStale
		}
		if err != nil {
			return false, fmt.Errorf("controlstate: replenish route-session connections: replace slot %d: %w", row.ConnectionSlot, err)
		}
		if _, err := connectionAssignment(updated, credential); err != nil {
			return false, err
		}
	}
	return removedReady, nil
}
