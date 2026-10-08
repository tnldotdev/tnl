package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const telemetryOutboxMax = 1000
const telemetryOutboxLifetime = 7 * 24 * time.Hour

type TelemetryOutboxEvent struct {
	ID   string
	JSON json.RawMessage
}

func (d *Database) QueueTelemetryEvent(ctx context.Context, id string, event json.RawMessage) error {
	if !opaqueid.Valid(id, opaqueid.TelemetryEventPrefix) || !json.Valid(event) || len(event) > 2048 {
		return errors.New("clientstate: invalid telemetry event")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clientstate: begin telemetry queue: %w", err)
	}
	defer tx.Rollback()
	if err := clientstatedb.New(tx).InsertTelemetryEvent(ctx, clientstatedb.InsertTelemetryEventParams{
		EventID: id, CreatedAt: d.now().UTC().UnixNano(), EventJson: string(event),
	}); err != nil {
		return fmt.Errorf("clientstate: queue telemetry: %w", err)
	}
	if err := d.pruneTelemetryOutbox(ctx, tx); err != nil {
		return fmt.Errorf("clientstate: prune telemetry queue: %w", err)
	}
	return tx.Commit()
}

func (d *Database) PruneTelemetryOutbox(ctx context.Context) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := d.pruneTelemetryOutbox(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *Database) pruneTelemetryOutbox(ctx context.Context, tx *sql.Tx) error {
	queries := clientstatedb.New(tx)
	if err := queries.DeleteExpiredTelemetryEvents(ctx, d.now().Add(-telemetryOutboxLifetime).UnixNano()); err != nil {
		return err
	}
	return queries.PruneTelemetryEventsToLimit(ctx, telemetryOutboxMax)
}

func (d *Database) PendingTelemetryEvents(ctx context.Context, limit int) ([]TelemetryOutboxEvent, error) {
	if limit < 1 || limit > 25 {
		return nil, errors.New("clientstate: invalid telemetry batch limit")
	}
	rows, err := d.queries.SelectPendingTelemetryEvents(ctx, int64(limit))
	if err != nil {
		return nil, err
	}
	result := make([]TelemetryOutboxEvent, 0, limit)
	for _, row := range rows {
		result = append(result, TelemetryOutboxEvent{ID: row.EventID, JSON: json.RawMessage(row.EventJson)})
	}
	return result, nil
}

func (d *Database) DeleteTelemetryEvents(ctx context.Context, events []TelemetryOutboxEvent) error {
	if len(events) == 0 {
		return nil
	}
	ids := make([]string, 0, len(events))
	for _, event := range events {
		if !opaqueid.Valid(event.ID, opaqueid.TelemetryEventPrefix) {
			return errors.New("clientstate: invalid acknowledged telemetry event")
		}
		ids = append(ids, event.ID)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return d.queries.DeleteAcknowledgedTelemetryEvents(ctx, string(encoded))
}

func (d *Database) ClearTelemetryOutbox(ctx context.Context) error {
	return d.queries.ClearTelemetryEvents(ctx)
}
