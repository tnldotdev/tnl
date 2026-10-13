-- +goose Up
CREATE TABLE local_ready_telemetry (
    invocation_key TEXT PRIMARY KEY CHECK (length(invocation_key) = 64),
    created_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE local_ready_telemetry;
