-- +goose Up
-- existing URLs keep their HTTP behavior. database endpoints reuse the saved
-- hostname and policy but choose their private target on the publisher host.
ALTER TABLE control.public_urls ADD COLUMN service_protocol text NOT NULL DEFAULT 'http'
    CHECK (service_protocol IN ('http', 'postgres', 'mysql'));
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_database_protocol_check
    CHECK (service_protocol = 'http' OR (purpose = 'app' AND target = '' AND NOT ephemeral));

-- +goose Down
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_database_protocol_check;
ALTER TABLE control.public_urls DROP COLUMN service_protocol;
