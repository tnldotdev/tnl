-- +goose Up
ALTER TABLE control.publish_runs
    ADD COLUMN share_capable boolean NOT NULL DEFAULT false;

CREATE TABLE control.share_cookies (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    share_id text NOT NULL,
    public_url_id text NOT NULL,
    team_id text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (share_id, team_id) REFERENCES control.shares(id, team_id) ON DELETE CASCADE,
    FOREIGN KEY (public_url_id, team_id) REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);

CREATE INDEX share_cookies_by_public_url
    ON control.share_cookies (public_url_id, expires_at);

CREATE TABLE control.share_handoffs (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    share_id text NOT NULL,
    public_url_id text NOT NULL,
    team_id text NOT NULL,
    next_url text NOT NULL CHECK (next_url LIKE 'https://%'),
    bridge boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (share_id, team_id) REFERENCES control.shares(id, team_id) ON DELETE CASCADE,
    FOREIGN KEY (public_url_id, team_id) REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);

CREATE INDEX share_handoffs_by_expiry
    ON control.share_handoffs (expires_at, token_digest);

-- +goose Down
DROP TABLE control.share_handoffs;
DROP TABLE control.share_cookies;
ALTER TABLE control.publish_runs DROP COLUMN share_capable;
