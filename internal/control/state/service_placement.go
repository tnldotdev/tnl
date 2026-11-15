package state

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/region"
)

func publisherConnectionCredentialContext(id string, revision int64) string {
	return id + "/" + strconv.FormatInt(revision, 10)
}

var (
	ErrInsufficientRelayServices = errors.New("controlstate: insufficient relay services")
	errRelayPlacementCapacity    = errors.New("controlstate: relay connection capacity exhausted")
)

type relayServicePlacement struct {
	region         region.ID
	relayServiceID string
	relayAddress   string
	tlsServerName  string
	capacity       int64
	assignments    int64
}

func selectRelayServicePlacements(ctx context.Context, q *controlstatedb.Queries, now time.Time, preferences ...string) ([2]relayServicePlacement, error) {
	services, _, err := availableRelayServicePlacements(ctx, q, now)
	if err != nil {
		return [2]relayServicePlacement{}, fmt.Errorf("controlstate: place service run: %w", err)
	}
	rankRelayPlacements(services, preferences)
	var placed [2]relayServicePlacement
	count := 0
	for _, service := range services {
		if service.assignments >= service.capacity {
			continue
		}
		placed[count] = service
		count++
		if count == len(placed) {
			return placed, nil
		}
	}
	if len(services) >= len(placed) {
		return placed, fmt.Errorf("%w: %w", ErrInsufficientRelayServices, errRelayPlacementCapacity)
	}
	return placed, ErrInsufficientRelayServices
}

// service guards precede relay lease locks, matching registration and renewal.
func availableRelayServicePlacements(ctx context.Context, q *controlstatedb.Queries, now time.Time) ([]relayServicePlacement, []controlstatedb.LockEligibleRelayLeasesRow, error) {
	ids, err := q.LockRelayServicesForPlacement(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("lock relay services: %w", err)
	}
	leases, err := q.LockEligibleRelayLeases(ctx, controlstatedb.LockEligibleRelayLeasesParams{
		Now: timestamptz(now), ProtocolVersion: 1, RelayServiceIds: ids,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("lock relay leases: %w", err)
	}
	counts, err := q.ListRelayServiceAssignmentTotals(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read relay-service assignment totals: %w", err)
	}
	assignments := make(map[string]int64, len(counts))
	for _, count := range counts {
		assignments[count.RelayServiceID] = count.AssignmentCount
	}
	byID := make(map[string]*relayServicePlacement, len(leases))
	for _, lease := range leases {
		service := byID[lease.RelayServiceID]
		if service == nil {
			service = &relayServicePlacement{
				region: region.ID(lease.Region), relayServiceID: lease.RelayServiceID,
				relayAddress: lease.RelayAddress, tlsServerName: lease.TlsServerName,
				assignments: assignments[lease.RelayServiceID],
			}
			byID[lease.RelayServiceID] = service
		}
		if lease.ConnectionCapacity > math.MaxInt64-service.capacity {
			service.capacity = math.MaxInt64
		} else {
			service.capacity += lease.ConnectionCapacity
		}
	}
	services := make([]relayServicePlacement, 0, len(byID))
	for _, service := range byID {
		services = append(services, *service)
	}
	sort.Slice(services, func(i, j int) bool {
		left := float64(services[i].assignments) / float64(services[i].capacity)
		right := float64(services[j].assignments) / float64(services[j].capacity)
		if left == right {
			return services[i].relayServiceID < services[j].relayServiceID
		}
		return left < right
	})
	return services, leases, nil
}
