-- +goose Up
ALTER TABLE control.workload_sessions
    ALTER COLUMN expires_at DROP NOT NULL,
    DROP CONSTRAINT workload_sessions_check2,
    ADD CONSTRAINT workload_session_hard_expiry CHECK (expires_at IS NULL OR expires_at>created_at);
DROP INDEX control.workload_sessions_retention;
CREATE INDEX workload_sessions_retention ON control.workload_sessions(COALESCE(expires_at,identity_expires_at),id);

-- +goose Down
UPDATE control.workload_sessions
    SET expires_at=LEAST(COALESCE(expires_at,identity_expires_at),created_at+interval '6 hours'),
        lease_expires_at=LEAST(lease_expires_at,COALESCE(expires_at,identity_expires_at),created_at+interval '6 hours');
DROP INDEX control.workload_sessions_retention;
CREATE INDEX workload_sessions_retention ON control.workload_sessions(expires_at,id);
ALTER TABLE control.workload_sessions
    DROP CONSTRAINT workload_session_hard_expiry,
    ALTER COLUMN expires_at SET NOT NULL,
    ADD CONSTRAINT workload_sessions_check2 CHECK (expires_at>created_at AND expires_at<=created_at+interval '6 hours');
