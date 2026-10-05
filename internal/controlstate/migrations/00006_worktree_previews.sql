-- +goose Up
CREATE TABLE control.worktree_previews (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL CHECK (team_id <> ''),
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    created_at timestamptz NOT NULL,
    UNIQUE (id, team_id),
    UNIQUE (team_id, created_by_identity_id, idempotency_key)
);

CREATE TABLE control.worktree_preview_public_urls (
    worktree_preview_id text NOT NULL,
    team_id text NOT NULL,
    public_url_id text NOT NULL,
    added_at timestamptz NOT NULL,
    PRIMARY KEY (worktree_preview_id, public_url_id),
    FOREIGN KEY (worktree_preview_id, team_id)
        REFERENCES control.worktree_previews(id, team_id) ON DELETE CASCADE,
    FOREIGN KEY (public_url_id, team_id)
        REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT
);

CREATE INDEX worktree_preview_public_urls_by_url
    ON control.worktree_preview_public_urls (public_url_id, worktree_preview_id);

-- +goose Down
DROP TABLE control.worktree_preview_public_urls;
DROP TABLE control.worktree_previews;
