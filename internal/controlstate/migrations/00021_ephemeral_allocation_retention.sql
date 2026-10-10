-- +goose Up
-- the allocation owner follows the temporary public URL through soft deletion
-- and is removed if retention later removes the URL row.
ALTER TABLE control.ephemeral_public_url_allocations
    DROP CONSTRAINT ephemeral_public_url_allocations_public_url_id_fkey,
    ADD CONSTRAINT ephemeral_public_url_allocations_public_url_id_fkey
        FOREIGN KEY (public_url_id) REFERENCES control.public_urls(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE control.ephemeral_public_url_allocations
    DROP CONSTRAINT ephemeral_public_url_allocations_public_url_id_fkey,
    ADD CONSTRAINT ephemeral_public_url_allocations_public_url_id_fkey
        FOREIGN KEY (public_url_id) REFERENCES control.public_urls(id) ON DELETE RESTRICT;
