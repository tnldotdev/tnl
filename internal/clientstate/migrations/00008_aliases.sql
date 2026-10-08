-- +goose Up
CREATE TABLE project_aliases (
    id TEXT PRIMARY KEY,
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    project_key TEXT NOT NULL,
    team_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    service TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    selected_project TEXT NOT NULL,
    selection_revision INTEGER NOT NULL CHECK (selection_revision > 0),
    UNIQUE (server_origin, project_key, team_id, membership_id, namespace, name),
    UNIQUE (server_origin, hostname)
) STRICT;

CREATE TABLE alias_declarations (
    alias_id TEXT NOT NULL REFERENCES project_aliases(id) ON DELETE CASCADE,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    PRIMARY KEY (alias_id, tunnel_id)
) STRICT;

-- +goose Down
DROP TABLE alias_declarations;
DROP TABLE project_aliases;
