-- +goose Up
-- the public URL addresses one mongodb endpoint, not an entire replica set.
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_service_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_service_protocol_check
    CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis', 'ssh', 'mongodb'));

-- +goose Down
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_service_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_service_protocol_check
    CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis', 'ssh'));
