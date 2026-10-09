-- +goose Up
-- keep old SELECT * readers compatible while new writers store a purpose.
CREATE TABLE control.public_url_purposes (
    public_url_id text PRIMARY KEY REFERENCES control.public_urls(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('app', 'alias', 'demo', 'oauth', 'webhooks'))
);
CREATE INDEX public_url_purposes_kind ON control.public_url_purposes (purpose, public_url_id);

-- +goose Down
DROP TABLE control.public_url_purposes;
