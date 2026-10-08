-- +goose Up
CREATE TABLE webhook_endpoints (
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    service TEXT NOT NULL,
    path TEXT NOT NULL,
    definition BLOB NOT NULL,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    PRIMARY KEY (tunnel_id, name)
) STRICT;

-- +goose Down
DROP TABLE webhook_endpoints;
