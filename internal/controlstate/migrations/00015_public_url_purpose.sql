-- +goose Up
-- apply after older control and standalone processes have stopped serving.
ALTER TABLE control.public_urls ADD COLUMN purpose text NOT NULL DEFAULT 'unknown'
    CHECK (purpose IN ('unknown', 'app', 'alias', 'demo', 'oauth', 'webhooks'));
CREATE INDEX public_urls_purpose_created ON control.public_urls (purpose, created_at DESC, id)
    WHERE purpose <> 'unknown';

-- +goose Down
DROP INDEX control.public_urls_purpose_created;
ALTER TABLE control.public_urls DROP COLUMN purpose;
