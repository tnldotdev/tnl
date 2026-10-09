-- +goose Up
-- label saved urls as apps, then require an explicit purpose for every new url.
ALTER TABLE control.public_urls ADD COLUMN purpose text NOT NULL DEFAULT 'app'
    CHECK (purpose IN ('app', 'alias', 'demo', 'oauth', 'webhooks'));
ALTER TABLE control.public_urls ALTER COLUMN purpose DROP DEFAULT;
CREATE INDEX public_urls_purpose_created ON control.public_urls (purpose, created_at DESC, id);

-- +goose Down
DROP INDEX control.public_urls_purpose_created;
ALTER TABLE control.public_urls DROP COLUMN purpose;
