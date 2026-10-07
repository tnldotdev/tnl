-- +goose Up
-- managed domains use the configured zone and need no claimed DNS authority.
ALTER TABLE control.guest_trials DROP CONSTRAINT guest_trials_dns_authority_reference_check;

-- +goose Down
ALTER TABLE control.guest_trials ADD CONSTRAINT guest_trials_dns_authority_reference_check CHECK (dns_authority_reference <> '');
