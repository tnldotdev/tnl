-- +goose Up
CREATE TABLE telemetry_outbox (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 26 AND substr(event_id, 1, 4) = 'tev_'),
    created_at INTEGER NOT NULL,
    event_json TEXT NOT NULL CHECK (json_valid(event_json))
) STRICT;
CREATE INDEX telemetry_outbox_oldest_idx ON telemetry_outbox (created_at, event_id);

-- +goose Down
DROP TABLE telemetry_outbox;
