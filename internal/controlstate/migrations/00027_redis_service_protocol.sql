-- +goose Up
-- add Redis without changing existing public URL rows or the TCP port pool.
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_service_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_service_protocol_check
    CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis'));

-- +goose Down
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_service_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_service_protocol_check
    CHECK (service_protocol IN ('http', 'postgres', 'mysql'));
