-- +goose Up
ALTER TABLE control.workload_sessions
    ADD COLUMN renewal_sequence bigint NOT NULL DEFAULT 0 CHECK (renewal_sequence >= 0);

-- +goose Down
ALTER TABLE control.workload_sessions DROP COLUMN renewal_sequence;
