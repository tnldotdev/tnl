-- +goose Up
CREATE TABLE webhook_owners (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    integration_group TEXT NOT NULL,
    name TEXT NOT NULL,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    PRIMARY KEY (server_origin, integration_group, name)
) STRICT;

-- +goose Down
DROP TABLE webhook_owners;
