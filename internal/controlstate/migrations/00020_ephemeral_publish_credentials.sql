-- +goose Up
-- add ad-hoc scope without requiring currently serving controls to change
-- their saved-URL credential inserts or reads.
ALTER TABLE control.public_url_publish_credentials
    ADD COLUMN kind text NOT NULL DEFAULT 'saved_url'
        CHECK (kind IN ('saved_url', 'ephemeral')),
    ADD COLUMN team_id text REFERENCES control.teams(id) ON DELETE RESTRICT,
    ADD COLUMN domain_id text REFERENCES control.domains(id) ON DELETE RESTRICT,
    ADD COLUMN namespace text,
    ADD COLUMN issued_role text CHECK (issued_role IN ('member', 'admin', 'owner'));

ALTER TABLE control.public_url_publish_credentials
    ALTER COLUMN public_url_id DROP NOT NULL,
    DROP CONSTRAINT public_url_publish_credentials_target_check;

ALTER TABLE control.public_url_publish_credentials
    ADD CONSTRAINT public_url_publish_credentials_scope_check CHECK (
        (kind = 'saved_url' AND public_url_id IS NOT NULL AND namespace IS NULL)
        OR (kind = 'ephemeral' AND public_url_id IS NULL AND target = ''
            AND team_id IS NOT NULL AND domain_id IS NOT NULL AND namespace IS NOT NULL AND namespace <> ''
            AND issued_role IS NOT NULL AND certificate_challenge_method = 'dns-01')
    );

CREATE INDEX public_url_publish_credentials_ephemeral_team
    ON control.public_url_publish_credentials (team_id, id)
    WHERE kind = 'ephemeral';

-- +goose Down
DROP INDEX control.public_url_publish_credentials_ephemeral_team;
ALTER TABLE control.public_url_publish_credentials
    DROP CONSTRAINT public_url_publish_credentials_scope_check,
    DROP COLUMN issued_role,
    DROP COLUMN namespace,
    DROP COLUMN domain_id,
    DROP COLUMN team_id,
    DROP COLUMN kind,
    ALTER COLUMN public_url_id SET NOT NULL,
    ADD CONSTRAINT public_url_publish_credentials_target_check CHECK (target <> '' OR public_url_id IS NOT NULL);
