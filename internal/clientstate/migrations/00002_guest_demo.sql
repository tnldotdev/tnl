-- +goose Up
CREATE TABLE guest_sessions (
    server_origin TEXT PRIMARY KEY REFERENCES server_profiles (origin) ON DELETE CASCADE,
    guest_id TEXT NOT NULL,
    stored_access_token BLOB NOT NULL,
    team_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE guest_sessions;
