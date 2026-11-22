package state

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
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

func selectRelayServicePlacements(ctx context.Context, tx pgx.Tx, now time.Time, preferences ...string) ([2]relayServicePlacement, []relayServicePlacement, error) {
	freePair := func(services []relayServicePlacement) []relayServicePlacement {
		var pair []relayServicePlacement
		for _, s := range services {
			if s.assignments < s.capacity {
				pair = append(pair, s)
				if len(pair) == 2 {
					return pair
				}
			}
		}
		return nil
	}
	services, err := lockRankedRelayPlacements(ctx, tx, now, preferences, freePair)
	if err != nil {
		return [2]relayServicePlacement{}, nil, fmt.Errorf("controlstate: place service run: %w", err)
	}
	if pair := freePair(services); len(pair) == 2 {
		return [2]relayServicePlacement(pair), nil, nil
	}
	if len(services) >= 2 {
		return [2]relayServicePlacement{}, services, fmt.Errorf("%w: %w", ErrInsufficientRelayServices, errRelayPlacementCapacity)
	}
	return [2]relayServicePlacement{}, nil, ErrInsufficientRelayServices
}

// rank without locking unrelated relays. read the current slot counts again
// after locking the winners. all new reservations on these relays wait for
// those locks; concurrent releases can only add capacity. if the winners lost
// capacity, release those locks before acquiring the full set in order.
func lockRankedRelayPlacements(ctx context.Context, tx pgx.Tx, now time.Time, preferences []string, choose func([]relayServicePlacement) []relayServicePlacement) ([]relayServicePlacement, error) {
	clock := newAuthorizationClock(now)
	q := controlstatedb.New(tx)
	rows, err := q.ReadRelayPlacementCandidates(ctx, timestamptz(clock.current()))
	if err != nil {
		return nil, err
	}
	hints := make([]relayServicePlacement, len(rows))
	for i, row := range rows {
		hints[i] = relayServicePlacement{region: region.ID(row.Region), relayServiceID: row.RelayServiceID, capacity: row.Capacity, assignments: row.Assignments}
	}
	sortRelayPlacements(hints)
	rankRelayPlacements(hints, preferences)
	selected := choose(hints)
	if len(selected) > 0 {
		ids := make([]string, len(selected))
		for i, r := range selected {
			ids[i] = r.relayServiceID
		}
		attempt, err := tx.Begin(ctx)
		if err != nil {
			return nil, err
		}
		locked, _, err := lockedRelayPlacements(ctx, controlstatedb.New(attempt), clock.current(), ids)
		if err == nil {
			rankRelayPlacements(locked, preferences)
			if len(choose(locked)) == len(selected) {
				return locked, attempt.Commit(ctx)
			}
		}
		if err = errors.Join(err, attempt.Rollback(ctx)); err != nil {
			return nil, err
		}
	}
	all, _, err := lockedRelayPlacements(ctx, q, clock.current(), nil)
	rankRelayPlacements(all, preferences)
	return all, err
}

// service guards precede relay lease locks, matching registration and renewal.
func availableRelayServicePlacements(ctx context.Context, q *controlstatedb.Queries, now time.Time) ([]relayServicePlacement, []controlstatedb.LockEligibleRelayLeasesRow, error) {
	return lockedRelayPlacements(ctx, q, now, nil)
}

func lockedRelayPlacements(ctx context.Context, q *controlstatedb.Queries, now time.Time, candidates []string) ([]relayServicePlacement, []controlstatedb.LockEligibleRelayLeasesRow, error) {
	clock := newAuthorizationClock(now)
	ids, err := q.LockRelayServicesForPlacement(ctx, candidates)
	if err != nil {
		return nil, nil, fmt.Errorf("lock relay services: %w", err)
	}
	leases, err := q.LockEligibleRelayLeases(ctx, controlstatedb.LockEligibleRelayLeasesParams{
		Now: timestamptz(clock.current()), ProtocolVersion: 1, RelayServiceIds: ids,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("lock relay leases: %w", err)
	}
	counts, err := q.ReadPlacementAssignmentTotals(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("read relay-service assignment totals: %w", err)
	}
	// a row lock fences drain and capacity changes, not the passage of time.
	at := clock.current()
	leases = slices.DeleteFunc(leases, func(lease controlstatedb.LockEligibleRelayLeasesRow) bool {
		return !lease.LeaseExpiresAt.Time.After(at)
	})
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
	sortRelayPlacements(services)
	return services, leases, nil
}

func sortRelayPlacements(services []relayServicePlacement) {
	sort.Slice(services, func(i, j int) bool {
		left := float64(services[i].assignments) / float64(services[i].capacity)
		right := float64(services[j].assignments) / float64(services[j].capacity)
		if left == right {
			return services[i].relayServiceID < services[j].relayServiceID
		}
		return left < right
	})
}
