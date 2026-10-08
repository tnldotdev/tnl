-- +goose Up
CREATE TABLE local_requests (
    id INTEGER PRIMARY KEY,
    tunnel_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('local_service', 'tnl'))
) STRICT;

CREATE INDEX local_requests_project_idx ON local_requests (project_root, received_at DESC, id DESC);

-- +goose Down
DROP TABLE local_requests;
