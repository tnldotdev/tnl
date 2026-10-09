-- +goose Up
ALTER TABLE control_sessions ADD COLUMN refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK (refresh_pending IN (0, 1));
CREATE TABLE auth_operations (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'redeeming', 'credential_received', 'exchanging', 'issued', 'completed', 'cancelled', 'denied', 'expired', 'recovery_required')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    public_json TEXT NOT NULL CHECK (length(public_json) BETWEEN 1 AND 32768),
    stored_private BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, operation_id)
) STRICT;

-- +goose Down
DROP TABLE auth_operations;
ALTER TABLE control_sessions DROP COLUMN refresh_pending;
