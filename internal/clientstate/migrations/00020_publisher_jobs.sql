-- +goose Up
CREATE TABLE publisher_jobs (
    public_url_id TEXT PRIMARY KEY NOT NULL,
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE RESTRICT,
    target TEXT NOT NULL CHECK (target <> ''),
    service_protocol TEXT NOT NULL CHECK (service_protocol <> ''),
    stored_identity BLOB NOT NULL CHECK (length(stored_identity) > 29),
    created_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE publisher_jobs;
