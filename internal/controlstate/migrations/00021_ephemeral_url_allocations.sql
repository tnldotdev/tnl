-- +goose Up
-- keep ownership after the allocation response so only the issuing
-- credential can maintain the temporary public URL and its publish runs.
CREATE TABLE control.ephemeral_public_url_allocations (
    public_url_id text PRIMARY KEY REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    credential_id text NOT NULL REFERENCES control.public_url_publish_credentials(id) ON DELETE RESTRICT,
    invocation_id text NOT NULL CHECK (invocation_id <> ''),
    UNIQUE (credential_id, invocation_id)
);

-- +goose Down
DROP TABLE control.ephemeral_public_url_allocations;
