-- +goose Up
ALTER TABLE control.acme_authorizations
    ALTER COLUMN challenge_type DROP NOT NULL,
    ALTER COLUMN challenge_url DROP NOT NULL,
    ALTER COLUMN challenge_token DROP NOT NULL,
    ALTER COLUMN challenge_digest DROP NOT NULL,
    DROP CONSTRAINT acme_authorizations_authorization_url_key,
    ADD UNIQUE (order_id, authorization_url),
    ADD CONSTRAINT acme_authorizations_challenge_material CHECK (
        (challenge_type IS NOT NULL AND challenge_url IS NOT NULL AND challenge_token IS NOT NULL AND challenge_digest IS NOT NULL)
        OR
        (challenge_type IS NULL AND challenge_url IS NULL AND challenge_token IS NULL AND challenge_digest IS NULL
            AND presentation_reference IS NULL AND state = 'complete' AND validated_at IS NOT NULL
            AND cleanup_completed_at IS NOT NULL AND presented_at IS NULL AND attempts = 0
            AND expires_at IS NOT NULL AND expires_at > validated_at)
    );
