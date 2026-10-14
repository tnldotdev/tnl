-- +goose Up
-- separate visitor grants from publish authority and existing anonymous preview links.
CREATE TABLE control.visitor_access_grants (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('team_preview', 'team_url', 'identity_url')),
    preview_id text,
    public_url_id text,
    identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    revoked_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    UNIQUE (id, team_id),
    UNIQUE (created_by_identity_id, idempotency_key),
    FOREIGN KEY (preview_id, team_id) REFERENCES control.previews(id, team_id) ON DELETE RESTRICT,
    FOREIGN KEY (public_url_id, team_id) REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT,
    CHECK ((kind = 'team_preview' AND preview_id IS NOT NULL AND public_url_id IS NULL AND identity_id IS NULL)
        OR (kind = 'team_url' AND preview_id IS NULL AND public_url_id IS NOT NULL AND identity_id IS NULL)
        OR (kind = 'identity_url' AND preview_id IS NULL AND public_url_id IS NOT NULL AND identity_id IS NOT NULL)),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK ((revoked_at IS NULL) = (revoked_by_identity_id IS NULL))
);
CREATE INDEX visitor_access_grants_by_url
    ON control.visitor_access_grants (public_url_id, kind, identity_id)
    WHERE revoked_at IS NULL;
CREATE INDEX visitor_access_grants_by_preview
    ON control.visitor_access_grants (preview_id)
    WHERE revoked_at IS NULL;
CREATE INDEX visitor_access_grants_by_identity
    ON control.visitor_access_grants (identity_id, public_url_id)
    WHERE kind = 'identity_url' AND revoked_at IS NULL;

-- +goose Down
DROP TABLE control.visitor_access_grants;
