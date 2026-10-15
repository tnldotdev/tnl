package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
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

// these numeric reads retain the intermediate CLI's TCP-only observation API.
// the project journal is the source of truth for both app and publication events.
func (d *Database) LatestTunnelEventCursor(ctx context.Context, project string) (uint64, error) {
	journal, err := d.queries.GetRuntimeProject(ctx, project)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return uint64(journal.LastSequence), nil
}

func (d *Database) TunnelEventsAfter(ctx context.Context, project string, after uint64) ([]TunnelEvent, error) {
	latest, err := d.LatestTunnelEventCursor(ctx, project)
	if err != nil {
		return nil, err
	}
	if after > latest || after > math.MaxInt64 {
		return nil, ErrTunnelCursorExpired
	}
	oldest, err := d.queries.OldestRuntimeEvent(ctx, project)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && uint64(oldest) > after+1 || errors.Is(err, sql.ErrNoRows) && after != latest {
		return nil, ErrTunnelCursorExpired
	}
	rows, err := d.queries.ListRuntimeEvents(ctx, clientstatedb.ListRuntimeEventsParams{ProjectRoot: project, After: int64(after)})
	if err != nil {
		return nil, err
	}
	events := make([]TunnelEvent, 0, len(rows))
	for _, row := range rows {
		if row.EventType != "publication.started" && row.EventType != "publication.changed" {
			continue
		}
		var payload struct {
			Publication struct {
				TunnelID         string `json:"tunnel_id"`
				Service          string `json:"service"`
				ServiceProtocol  string `json:"service_protocol"`
				State            string `json:"state"`
				Target           string `json:"target"`
				Hostname         string `json:"hostname"`
				PublicPort       uint16 `json:"public_port"`
				PublishRunNumber uint64 `json:"publish_run_number"`
			} `json:"publication"`
		}
		if err := json.Unmarshal([]byte(row.PayloadJson), &payload); err != nil {
			return nil, err
		}
		publication := payload.Publication
		if publication.Service == "" || publication.ServiceProtocol == "" || publication.ServiceProtocol == "http" {
			continue
		}
		events = append(events, TunnelEvent{
			Sequence: uint64(row.Sequence), TunnelID: publication.TunnelID, Service: publication.Service,
			ServiceProtocol: controlv1.PublicURLServiceProtocol(publication.ServiceProtocol), State: TunnelState(publication.State),
			Target: publication.Target, Hostname: publication.Hostname, PublicPort: publication.PublicPort,
			PublishRunNumber: publication.PublishRunNumber, At: unixNanoTime(row.OccurredAt),
		})
	}
	return events, nil
}
