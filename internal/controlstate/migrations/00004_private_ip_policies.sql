-- +goose Up
TRUNCATE TABLE control.public_urls CASCADE;
TRUNCATE TABLE control.guest_trials CASCADE;

-- +goose StatementBegin
DO $$
DECLARE constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'control.public_urls'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%allowed_ip_prefixes%'
    LOOP
        EXECUTE format('ALTER TABLE control.public_urls DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END;
$$;
-- +goose StatementEnd

ALTER TABLE control.public_urls
    DROP COLUMN allowed_ip_prefixes,
    DROP COLUMN request_digest,
    ADD COLUMN allowed_ip_policy_ciphertext bytea,
    ADD COLUMN allowed_ip_policy_storage_key_id text,
    ADD COLUMN allowed_ip_hashes bytea,
    ADD COLUMN allowed_ip_hash_key_id text,
    ADD COLUMN request_digest_ciphertext bytea,
    ADD COLUMN request_digest_storage_key_id text,
    ADD CONSTRAINT public_urls_private_digest_check CHECK (
        (lifecycle_state = 'deleted' AND request_digest_ciphertext IS NULL AND request_digest_storage_key_id IS NULL)
        OR (lifecycle_state <> 'deleted' AND request_digest_ciphertext IS NOT NULL AND request_digest_storage_key_id IS NOT NULL)
    ),
    ADD CONSTRAINT public_urls_private_policy_check CHECK (
        (ip_policy = 'allow_all' AND allowed_ip_policy_ciphertext IS NULL
            AND allowed_ip_policy_storage_key_id IS NULL AND allowed_ip_hashes IS NULL
            AND allowed_ip_hash_key_id IS NULL)
        OR (ip_policy = 'allowlist' AND allowed_ip_hashes IS NOT NULL
            AND allowed_ip_hash_key_id IS NOT NULL
            AND (allowed_ip_policy_ciphertext IS NULL) = (allowed_ip_policy_storage_key_id IS NULL))
    );

ALTER TABLE control.publish_runs
    DROP COLUMN request_digest,
    ADD COLUMN request_digest_ciphertext bytea,
    ADD COLUMN request_digest_storage_key_id text,
    ADD CONSTRAINT publish_runs_private_digest_check CHECK (
        (request_digest_ciphertext IS NULL) = (request_digest_storage_key_id IS NULL)
        AND (closed_at IS NOT NULL OR request_digest_ciphertext IS NOT NULL)
    );

ALTER TABLE control.ingress_routing_table_events
    ADD COLUMN policy_ciphertext bytea,
    ADD COLUMN policy_storage_key_id text;

-- +goose Down
ALTER TABLE control.ingress_routing_table_events
    DROP COLUMN policy_storage_key_id,
    DROP COLUMN policy_ciphertext;
ALTER TABLE control.publish_runs
    DROP CONSTRAINT publish_runs_private_digest_check,
    DROP COLUMN request_digest_storage_key_id,
    DROP COLUMN request_digest_ciphertext,
    ADD COLUMN request_digest bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex');
ALTER TABLE control.public_urls
    DROP CONSTRAINT public_urls_private_digest_check,
    DROP CONSTRAINT public_urls_private_policy_check,
    DROP COLUMN request_digest_storage_key_id,
    DROP COLUMN request_digest_ciphertext,
    DROP COLUMN allowed_ip_hash_key_id,
    DROP COLUMN allowed_ip_hashes,
    DROP COLUMN allowed_ip_policy_storage_key_id,
    DROP COLUMN allowed_ip_policy_ciphertext,
    ADD COLUMN allowed_ip_prefixes cidr[] NOT NULL DEFAULT '{}'::cidr[],
    ADD COLUMN request_digest bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex');
