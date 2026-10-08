-- +goose Up
CREATE TABLE local_requests (
    row_id INTEGER PRIMARY KEY,
    request_number INTEGER NOT NULL,
    primary_checkout_root TEXT NOT NULL,
    tunnel_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    shared_project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('local_service', 'tnl')),
    capture_mode TEXT NOT NULL CHECK (capture_mode IN ('summary', 'detailed')),
    detail_json TEXT CHECK (detail_json IS NULL OR json_valid(detail_json)),
    UNIQUE (primary_checkout_root, request_number)
) STRICT;

CREATE TABLE local_request_counters (
    primary_checkout_root TEXT PRIMARY KEY,
    last_number INTEGER NOT NULL CHECK (last_number > 0)
) STRICT;

CREATE INDEX local_requests_project_idx ON local_requests (project_root, received_at DESC, row_id DESC);
CREATE INDEX local_requests_shared_project_idx ON local_requests (shared_project_root, received_at DESC, row_id DESC);

-- +goose Down
DROP TABLE local_requests;
DROP TABLE local_request_counters;
