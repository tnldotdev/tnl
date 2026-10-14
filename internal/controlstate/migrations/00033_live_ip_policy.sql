-- +goose Up
ALTER TABLE control.public_urls ADD COLUMN next_operator_ip_expiry timestamptz;
CREATE INDEX public_urls_due_operator_ip_expiry
    ON control.public_urls (next_operator_ip_expiry, id)
    WHERE next_operator_ip_expiry IS NOT NULL AND lifecycle_state = 'enabled';

-- +goose Down
DROP INDEX control.public_urls_due_operator_ip_expiry;
ALTER TABLE control.public_urls DROP COLUMN next_operator_ip_expiry;
