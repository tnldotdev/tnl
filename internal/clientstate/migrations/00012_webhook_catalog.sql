-- +goose Up
CREATE TABLE webhook_catalog (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    source_json TEXT NOT NULL CHECK (length(source_json) BETWEEN 1 AND 16384),
    etag TEXT NOT NULL CHECK (length(etag) <= 128),
    checked_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, provider)
) STRICT;

-- +goose Down
DROP TABLE webhook_catalog;
