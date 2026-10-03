-- +goose Up
-- drop pre-encryption usage so sketches from different master keys cannot mix.
DELETE FROM control.public_url_usage_deliveries;
DELETE FROM control.public_url_usage_buckets;
DELETE FROM control.ingress_usage_reports;
DELETE FROM control.ingress_usage_runs;
DELETE FROM control.public_url_usage_configuration;

ALTER TABLE control.public_url_usage_configuration
    DROP COLUMN visitor_network_hash_master_key,
    ADD COLUMN visitor_network_hash_master_key_ciphertext bytea NOT NULL
        CHECK (octet_length(visitor_network_hash_master_key_ciphertext) > 29),
    ADD COLUMN visitor_network_hash_master_key_storage_key_id text NOT NULL
        CHECK (visitor_network_hash_master_key_storage_key_id <> '');
