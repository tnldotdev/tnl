-- +goose Up
CREATE TABLE webhook_catalog (
    provider TEXT PRIMARY KEY,
    source_json TEXT NOT NULL CHECK (length(source_json) BETWEEN 1 AND 16384),
    etag TEXT NOT NULL CHECK (length(etag) <= 128),
    checked_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE webhook_catalog;
