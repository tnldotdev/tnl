-- +goose Up
ALTER TABLE control.public_url_usage_configuration
    ALTER COLUMN visitor_network_hash_master_key DROP NOT NULL,
    ADD COLUMN visitor_network_hash_master_key_ciphertext bytea,
    ADD COLUMN visitor_network_hash_master_key_storage_key_id text,
    ADD CONSTRAINT visitor_network_hash_master_key_storage CHECK (
        (visitor_network_hash_master_key IS NOT NULL
            AND visitor_network_hash_master_key_ciphertext IS NULL
            AND visitor_network_hash_master_key_storage_key_id IS NULL)
        OR (visitor_network_hash_master_key IS NULL
            AND visitor_network_hash_master_key_ciphertext IS NOT NULL
            AND octet_length(visitor_network_hash_master_key_ciphertext) > 29
            AND visitor_network_hash_master_key_storage_key_id IS NOT NULL
            AND visitor_network_hash_master_key_storage_key_id <> '')
    );
