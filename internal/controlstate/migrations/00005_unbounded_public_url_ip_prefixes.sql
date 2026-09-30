-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    prefix_constraint text;
BEGIN
    SELECT conname INTO prefix_constraint
    FROM pg_constraint
    WHERE conrelid = 'control.public_urls'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%cardinality(allowed_ip_prefixes) <= 64%';

    IF prefix_constraint IS NULL THEN
        RAISE EXCEPTION 'public URL IP prefix count constraint not found';
    END IF;

    EXECUTE format('ALTER TABLE control.public_urls DROP CONSTRAINT %I', prefix_constraint);
END $$;
-- +goose StatementEnd
