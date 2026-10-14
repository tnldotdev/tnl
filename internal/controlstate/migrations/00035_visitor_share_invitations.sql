-- +goose Up
-- pending named invitations grant nothing until the verified recipient accepts.
CREATE TABLE control.visitor_share_invitations (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    public_url_id text NOT NULL,
    normalized_email text NOT NULL CHECK (char_length(normalized_email) BETWEEN 3 AND 320),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
    accepted_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    accepted_at timestamptz,
    revoked_at timestamptz,
    revoked_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    UNIQUE (id, team_id),
    UNIQUE (created_by_identity_id, idempotency_key),
    FOREIGN KEY (public_url_id, team_id) REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT,
    CHECK ((accepted_identity_id IS NULL) = (accepted_at IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by_identity_id IS NULL))
);
CREATE INDEX visitor_share_invitations_team ON control.visitor_share_invitations (team_id, id);
CREATE INDEX visitor_share_invitations_expiring ON control.visitor_share_invitations (expires_at, id)
    WHERE revoked_at IS NULL AND accepted_at IS NULL;

-- +goose Down
DROP TABLE control.visitor_share_invitations;
