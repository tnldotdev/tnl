-- +goose Up
ALTER TABLE control.relay_certificate_orders
    ADD COLUMN authorization_expires_at timestamptz;

ALTER TABLE control.public_url_usage_deliveries
    DROP CONSTRAINT public_url_usage_deliveries_state_check,
    DROP CONSTRAINT public_url_usage_deliveries_check3,
    ADD CONSTRAINT public_url_usage_deliveries_state_check
        CHECK (state IN ('pending', 'delivering', 'delivered', 'failed', 'rejected')),
    ADD CONSTRAINT public_url_usage_deliveries_error_state_check
        CHECK ((state IN ('failed', 'rejected')) = (last_error IS NOT NULL));
