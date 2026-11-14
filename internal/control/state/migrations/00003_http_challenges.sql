-- +goose Up
CREATE TABLE control.http_challenges (
    id text PRIMARY KEY,
    resource_kind text NOT NULL CHECK (resource_kind IN ('public_url', 'service')),
    resource_id text NOT NULL,
    hostname text NOT NULL,
    port integer NOT NULL CHECK (port > 0 AND port <= 65535),
    browser_binding_hash bytea NOT NULL CHECK (octet_length(browser_binding_hash) = 32),
    publisher_binding_hash bytea NOT NULL CHECK (octet_length(publisher_binding_hash) = 32),
    expires_at timestamptz NOT NULL,
    verification_started_at timestamptz,
    verified_at timestamptz,
    handoff_hash bytea UNIQUE CHECK (handoff_hash IS NULL OR octet_length(handoff_hash) = 32),
    handoff_expires_at timestamptz,
    redeemed_at timestamptz
);
CREATE INDEX http_challenges_resource ON control.http_challenges (resource_kind, resource_id);
CREATE INDEX http_challenges_expiration ON control.http_challenges (expires_at);

-- +goose Down
DROP TABLE control.http_challenges;
