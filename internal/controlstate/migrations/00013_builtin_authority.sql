-- +goose Up
DROP TABLE control.authority_revision_states;
ALTER TABLE control.runtime_secret RENAME COLUMN external_retry_master_key_ciphertext TO guest_retry_master_key_ciphertext;
ALTER TABLE control.runtime_secret RENAME COLUMN external_retry_master_key_storage_key_id TO guest_retry_master_key_storage_key_id;

-- +goose Down
-- this prelaunch authority boundary requires a fresh database.
