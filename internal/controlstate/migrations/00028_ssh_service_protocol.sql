-- +goose Up
-- retain certificate issuance and publish-run readiness for SSH public URLs.
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_service_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_service_protocol_check
    CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis', 'ssh'));

-- +goose Down
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_service_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_service_protocol_check
    CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis'));
