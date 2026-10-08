-- +goose Up
ALTER TABLE local_tunnels ADD COLUMN integration_group TEXT NOT NULL DEFAULT '';
CREATE INDEX local_tunnels_integration_group_idx ON local_tunnels (integration_group, lease_expires_at)
    WHERE stopped_at IS NULL;

CREATE TABLE integration_url_hostnames (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    project_key TEXT NOT NULL,
    namespace TEXT NOT NULL,
    purpose TEXT NOT NULL,
    hostname TEXT NOT NULL,
    PRIMARY KEY (server_origin, project_key, namespace, purpose)
) STRICT;

CREATE TABLE oauth_callbacks (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    state_digest BLOB NOT NULL,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    callback_path TEXT NOT NULL,
    callback_query TEXT NOT NULL,
    public_url_id TEXT NOT NULL,
    publish_run_number INTEGER NOT NULL CHECK (publish_run_number > 0),
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, hostname, state_digest)
) STRICT;
CREATE INDEX oauth_callbacks_expiry_idx ON oauth_callbacks (expires_at);

-- +goose Down
DROP TABLE oauth_callbacks;
DROP TABLE integration_url_hostnames;
DROP INDEX local_tunnels_integration_group_idx;
ALTER TABLE local_tunnels DROP COLUMN integration_group;
