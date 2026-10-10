-- +goose Up
-- add the customer-facing TCP port without changing HTTP URLs. creation sets
-- the port and its claim in one transaction before exposing a new endpoint.
ALTER TABLE control.public_urls ADD COLUMN public_port integer
    CHECK (public_port IS NULL OR public_port BETWEEN 1024 AND 65535);
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_http_without_tcp_port
    CHECK (service_protocol <> 'http' OR public_port IS NULL);
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_target_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_target_check
    CHECK (target <> '' OR (purpose = 'app' AND (NOT ephemeral OR service_protocol <> 'http')));
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_database_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_database_protocol_check
    CHECK (service_protocol = 'http' OR (purpose = 'app' AND target = ''));

-- +goose Down
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_database_protocol_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_database_protocol_check
    CHECK (service_protocol = 'http' OR (purpose = 'app' AND target = '' AND NOT ephemeral));
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_target_check;
ALTER TABLE control.public_urls ADD CONSTRAINT public_urls_target_check
    CHECK (target <> '' OR (purpose = 'app' AND NOT ephemeral));
ALTER TABLE control.public_urls DROP CONSTRAINT public_urls_http_without_tcp_port;
ALTER TABLE control.public_urls DROP COLUMN public_port;
