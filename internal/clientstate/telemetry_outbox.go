package clientstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	if _, err := d.db.ExecContext(ctx, `INSERT INTO telemetry_outbox (event_id, created_at, event_json) VALUES (?, ?, ?)`, id, d.now().UTC().UnixNano(), string(event)); err != nil {
		return fmt.Errorf("clientstate: queue telemetry: %w", err)
	}
	return d.PruneTelemetryOutbox(ctx)
}

func (d *Database) PruneTelemetryOutbox(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM telemetry_outbox WHERE created_at < ?`, d.now().Add(-telemetryOutboxLifetime).UnixNano()); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `DELETE FROM telemetry_outbox WHERE event_id NOT IN
		(SELECT event_id FROM telemetry_outbox ORDER BY created_at DESC, event_id DESC LIMIT ?)`, telemetryOutboxMax)
	return err
}

func (d *Database) PendingTelemetryEvents(ctx context.Context, limit int) ([]TelemetryOutboxEvent, error) {
	if limit < 1 || limit > 25 {
		return nil, errors.New("clientstate: invalid telemetry batch limit")
	}
	rows, err := d.db.QueryContext(ctx, `SELECT event_id, event_json FROM telemetry_outbox ORDER BY created_at, event_id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TelemetryOutboxEvent, 0, limit)
	for rows.Next() {
		var event TelemetryOutboxEvent
		var raw string
		if err := rows.Scan(&event.ID, &raw); err != nil {
			return nil, err
		}
		event.JSON = json.RawMessage(raw)
		result = append(result, event)
	}
	return result, rows.Err()
}

func (d *Database) DeleteTelemetryEvents(ctx context.Context, events []TelemetryOutboxEvent) error {
	for _, event := range events {
		if _, err := d.db.ExecContext(ctx, `DELETE FROM telemetry_outbox WHERE event_id = ?`, event.ID); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) ClearTelemetryOutbox(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM telemetry_outbox`)
	return err
}
