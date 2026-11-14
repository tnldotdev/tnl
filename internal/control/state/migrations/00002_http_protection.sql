-- +goose Up
ALTER TABLE control.publish_runs
    ADD COLUMN http_protection jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(http_protection) = 'object');

CREATE TABLE control.http_temporary_blocks (
    resource_kind text NOT NULL CHECK (resource_kind IN ('public_url', 'service')),
    resource_id text NOT NULL,
    source_ip text NOT NULL,
    expires_at timestamptz NOT NULL,
    evidence_ended_at timestamptz NOT NULL,
    PRIMARY KEY (resource_kind, resource_id, source_ip)
);
CREATE INDEX http_temporary_blocks_expiration
    ON control.http_temporary_blocks (expires_at);

-- +goose Down
DROP TABLE control.http_temporary_blocks;
ALTER TABLE control.publish_runs DROP COLUMN http_protection;
