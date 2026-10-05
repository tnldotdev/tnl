-- +goose Up
CREATE TABLE previews (
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE CASCADE,
    team_id TEXT NOT NULL CHECK (team_id <> ''),
    project_root TEXT NOT NULL CHECK (project_root <> ''),
    preview_id TEXT NOT NULL CHECK (preview_id <> ''),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, team_id, project_root)
) STRICT;

-- +goose Down
DROP TABLE previews;
