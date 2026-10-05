-- +goose Up
CREATE TABLE control.shares (
    id text PRIMARY KEY CHECK (id <> ''),
    preview_id text NOT NULL,
    team_id text NOT NULL CHECK (team_id <> ''),
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    secret_fingerprint bytea NOT NULL CHECK (octet_length(secret_fingerprint) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    UNIQUE (id, team_id),
    UNIQUE (created_by_identity_id, idempotency_key),
    FOREIGN KEY (preview_id, team_id)
        REFERENCES control.previews(id, team_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
    CHECK ((revoked_at IS NULL) = (revoked_by_identity_id IS NULL))
);

CREATE INDEX shares_by_preview
    ON control.shares (preview_id, id);
CREATE INDEX shares_expiring
    ON control.shares (expires_at, id)
    WHERE revoked_at IS NULL;

CREATE TABLE control.share_public_urls (
    share_id text NOT NULL,
    team_id text NOT NULL,
    public_url_id text NOT NULL,
    PRIMARY KEY (share_id, public_url_id),
    FOREIGN KEY (share_id, team_id)
        REFERENCES control.shares(id, team_id) ON DELETE CASCADE,
    FOREIGN KEY (public_url_id, team_id)
        REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT
);

CREATE INDEX share_public_urls_by_url
    ON control.share_public_urls (public_url_id, share_id);

-- +goose Down
DROP TABLE control.share_public_urls;
DROP TABLE control.shares;
