-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control.require_publisher_certificate_state() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE publisher text; plan jsonb; digest text;
BEGIN
    SELECT publisher_identity_id INTO publisher FROM control.service_runs WHERE id=NEW.service_run_id;
    IF publisher IS NOT NULL THEN
        IF TG_TABLE_NAME='service_supplied_certificates' THEN
            SELECT jsonb_build_object('cache_key',certificate_cache_key,'scope',certificate_scope,
                'identifiers',certificate_identifiers,'challenge_method','dns-01') INTO plan
                FROM control.service_runs WHERE id=NEW.service_run_id;
        ELSE
            plan := jsonb_build_object('cache_key',NEW.certificate_cache_key,'scope',NEW.certificate_scope,
                'identifiers',NEW.certificate_identifiers,'challenge_method',NEW.challenge_method);
        END IF;
        digest := encode(sha256(convert_to(plan::text,'UTF8')),'hex');
        INSERT INTO control.publisher_certificate_checkpoints VALUES(publisher,digest,plan)
            ON CONFLICT (publisher_identity_id,plan_digest) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
