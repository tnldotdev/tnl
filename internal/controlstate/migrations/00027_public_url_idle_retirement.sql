-- +goose Up
-- saved URLs can be kept explicitly; otherwise control gives an idle URL a
-- recovery window before deleting it. existing rows remain eligible based on
-- their creation time and latest closed publish run.
ALTER TABLE control.public_urls
    ADD COLUMN keep_saved boolean NOT NULL DEFAULT false,
    ADD COLUMN idle_recovery_started_at timestamptz;

CREATE INDEX public_urls_idle_recovery_due
    ON control.public_urls (idle_recovery_started_at, id)
    WHERE lifecycle_state = 'enabled' AND NOT ephemeral AND NOT keep_saved;

-- +goose Down
DROP INDEX control.public_urls_idle_recovery_due;
ALTER TABLE control.public_urls
    DROP COLUMN idle_recovery_started_at,
    DROP COLUMN keep_saved;
