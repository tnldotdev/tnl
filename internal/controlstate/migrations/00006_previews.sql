-- +goose Up
CREATE TABLE control.previews (
    id text PRIMARY KEY CHECK (id <> ''),
    schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    team_id text NOT NULL CHECK (team_id <> ''),
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    created_at timestamptz NOT NULL,
    UNIQUE (id, team_id),
    UNIQUE (team_id, created_by_identity_id, idempotency_key)
);

CREATE TABLE control.preview_public_urls (
    preview_id text NOT NULL,
    team_id text NOT NULL,
    public_url_id text NOT NULL,
    added_at timestamptz NOT NULL,
    PRIMARY KEY (preview_id, public_url_id),
    FOREIGN KEY (preview_id, team_id)
        REFERENCES control.previews(id, team_id) ON DELETE CASCADE,
    FOREIGN KEY (public_url_id, team_id)
        REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT
);

CREATE INDEX preview_public_urls_by_url
    ON control.preview_public_urls (public_url_id, preview_id);

-- +goose Down
DROP TABLE control.preview_public_urls;
DROP TABLE control.previews;
