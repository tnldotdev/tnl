-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'control.domains'::regclass AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%claimed%'
    LOOP
        EXECUTE format('ALTER TABLE control.domains DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END $$;
-- +goose StatementEnd

UPDATE control.domains SET kind = 'custom' WHERE kind = 'claimed';
ALTER TABLE control.domains
    ADD CONSTRAINT domains_kind_check CHECK (kind IN ('managed', 'custom')),
    ADD CONSTRAINT domains_kind_team_check CHECK (
        (kind = 'managed' AND team_id IS NULL) OR
        (kind = 'custom' AND team_id IS NOT NULL)
    );
ALTER INDEX control.domains_managed_deployment_domain RENAME TO domains_managed_domain;

-- +goose Down
-- domain kind is intentionally not rolled back.
