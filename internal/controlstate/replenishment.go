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
	sessionToken credentials.SessionToken,
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

	activeServices := make(map[string]bool, routeSessionConnectionCount)
	replace := make([]bool, len(rows))
	removedReady := false
	for index, row := range rows {
		valid := row.PublisherConnectionCredentialExpiresAt.Valid &&
			row.PublisherConnectionCredentialExpiresAt.Time.After(now)
		switch row.State {
		case "assigned":
			_, serviceAvailable := serviceConfigurations[row.RelayServiceID]
			valid = valid && serviceAvailable
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
		default:
			valid = false
		}
		if valid && activeServices[row.RelayServiceID] {
			valid = false
		}
		if valid {
			activeServices[row.RelayServiceID] = true
			continue
		}
		replace[index] = true
		removedReady = removedReady || row.State == "ready"
	}

	for index, row := range rows {
		if !replace[index] {
			continue
		}
		placement, found := replacementRelayServicePlacement(
			row.RelayServiceID, availableServices, serviceConfigurations, activeServices,
		)
		if !found {
			continue
		}
		if row.ConnectionAssignmentRevision <= 0 || row.ConnectionAssignmentRevision == math.MaxInt64 {
			return false, errors.New("controlstate: replenish route-session connections: assignment revision is exhausted")
		}
		if row.State != "closed" && row.State != "expired" {
			if _, err := queries.ExpirePublisherConnection(ctx, controlstatedb.ExpirePublisherConnectionParams{
				ExpiredAt: timestamptz(now), PublisherConnectionID: row.PublisherConnectionID,
				RouteSessionID: row.RouteSessionID, ConnectionAssignmentRevision: row.ConnectionAssignmentRevision,
			}); errors.Is(err, pgx.ErrNoRows) {
				return false, ErrConnectionAssignmentStale
			} else if err != nil {
				return false, fmt.Errorf("controlstate: replenish route-session connections: expire slot %d: %w", row.ConnectionSlot, err)
			}
		}
		publisherConnectionID, err := opaqueid.New("connection_")
		if err != nil {
			return false, fmt.Errorf("controlstate: replenish route-session connections: generate publisher connection ID: %w", err)
		}
		revision := row.ConnectionAssignmentRevision + 1
		credential, hash, err := credentials.DerivePublisherConnectionCredential(
			sessionToken, publisherConnectionCredentialContext(publisherConnectionID, revision),
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
		if _, err := publisherConnectionPlan(updated, credential); err != nil {
			return false, err
		}
		activeServices[placement.relayServiceID] = true
	}
	return removedReady, nil
}

func replacementRelayServicePlacement(
	currentRelayServiceID string,
	available []relayServicePlacement,
	configurations map[string]relayServicePlacement,
	activeServices map[string]bool,
) (relayServicePlacement, bool) {
	if placement, found := configurations[currentRelayServiceID]; found && !activeServices[currentRelayServiceID] {
		return placement, true
	}
	for _, placement := range available {
		if !activeServices[placement.relayServiceID] {
			return placement, true
		}
	}
	return relayServicePlacement{}, false
}
