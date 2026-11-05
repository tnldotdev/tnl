-- +goose Up
ALTER TABLE control.workload_sessions DROP CONSTRAINT workload_sessions_provider_check;
ALTER TABLE control.workload_sessions ADD CONSTRAINT workload_sessions_provider_check
    CHECK (provider IN ('github', 'vercel', 'fly', 'oidc', 'google'));

-- +goose Down
ALTER TABLE control.workload_sessions DROP CONSTRAINT workload_sessions_provider_check;
ALTER TABLE control.workload_sessions ADD CONSTRAINT workload_sessions_provider_check
    CHECK (provider IN ('github', 'vercel', 'fly', 'oidc'));
