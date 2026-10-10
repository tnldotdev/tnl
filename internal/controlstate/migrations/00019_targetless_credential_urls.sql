-- +goose Up
-- a saved app URL may leave its target to the publisher; all other URLs keep a target.
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_target_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_target_check
    CHECK (target <> '' OR (purpose = 'app' AND NOT ephemeral));

ALTER TABLE control.public_url_publish_credentials DROP CONSTRAINT public_url_publish_credentials_target_check;
ALTER TABLE control.public_url_publish_credentials ADD CONSTRAINT public_url_publish_credentials_target_check
    CHECK (target <> '' OR public_url_id IS NOT NULL);

-- +goose Down
ALTER TABLE control.public_url_publish_credentials DROP CONSTRAINT public_url_publish_credentials_target_check;
ALTER TABLE control.public_url_publish_credentials ADD CONSTRAINT public_url_publish_credentials_target_check
    CHECK (target <> '');

ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_target_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_target_check CHECK (target <> '');
