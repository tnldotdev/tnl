-- +goose Up
CREATE TABLE local_runtime_snapshots (
    project_root TEXT PRIMARY KEY,
    cursor INTEGER NOT NULL CHECK (cursor >= 0),
    snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json))
) STRICT;

CREATE TABLE local_runtime_events (
    project_root TEXT NOT NULL REFERENCES local_runtime_snapshots(project_root) ON DELETE CASCADE,
    cursor INTEGER NOT NULL CHECK (cursor > 0),
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    PRIMARY KEY (project_root, cursor)
) STRICT;

-- +goose Down
DROP TABLE local_runtime_events;
DROP TABLE local_runtime_snapshots;
