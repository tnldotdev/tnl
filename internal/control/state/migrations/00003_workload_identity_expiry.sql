-- +goose Up
ALTER TABLE control.workload_sessions ADD COLUMN identity_expires_at timestamptz;
UPDATE control.workload_sessions
    SET identity_expires_at=to_timestamp((claims->>'exp')::bigint),
        lease_expires_at=LEAST(lease_expires_at,to_timestamp((claims->>'exp')::bigint));
ALTER TABLE control.workload_sessions
    ALTER COLUMN identity_expires_at SET NOT NULL,
    ADD CONSTRAINT workload_identity_expiry CHECK (identity_expires_at>created_at AND lease_expires_at<=identity_expires_at);

-- +goose Down
ALTER TABLE control.workload_sessions DROP CONSTRAINT workload_identity_expiry;
ALTER TABLE control.workload_sessions DROP COLUMN identity_expires_at;
