package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var ErrTunnelCursorExpired = errors.New("TCP tunnel event cursor expired; read a new status snapshot")

type TunnelEvent struct {
	Sequence         uint64
	TunnelID         string
	Service          string
	ServiceProtocol  controlv1.PublicURLServiceProtocol
	State            TunnelState
	Target           string
	Hostname         string
	PublicPort       uint16
	PublishRunNumber uint64
	At               time.Time
}

func (d *Database) LatestTunnelEventCursor(ctx context.Context, project string) (uint64, error) {
	sequence, err := d.queries.LatestTunnelEventCursor(ctx, project)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return uint64(sequence), err
}

func (d *Database) TunnelEventsAfter(ctx context.Context, project string, after uint64) ([]TunnelEvent, error) {
	latest, err := d.LatestTunnelEventCursor(ctx, project)
	if err != nil {
		return nil, err
	}
	if after > latest || after > math.MaxInt64 {
		return nil, ErrTunnelCursorExpired
	}
	oldest, err := d.queries.OldestTunnelEventCursor(ctx, project)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && uint64(oldest) > after+1 {
		return nil, ErrTunnelCursorExpired
	}
	rows, err := d.queries.ListTunnelEventsAfter(ctx, clientstatedb.ListTunnelEventsAfterParams{ProjectRoot: project, After: int64(after), Latest: int64(latest)})
	if err != nil {
		return nil, err
	}
	events := make([]TunnelEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, TunnelEvent{
			Sequence: uint64(row.Sequence), TunnelID: row.TunnelID, Service: row.Service,
			ServiceProtocol: controlv1.PublicURLServiceProtocol(row.ServiceProtocol), State: TunnelState(row.State),
			Target: row.Target, Hostname: row.Hostname, PublicPort: uint16(row.PublicPort),
			PublishRunNumber: uint64(row.PublishRunNumber), At: unixNanoTime(row.CreatedAt),
		})
	}
	return events, nil
}
