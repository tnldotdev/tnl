-- +goose Up
ALTER TABLE control.service_endpoints
    ADD COLUMN dns_consecutive_errors bigint NOT NULL DEFAULT 0 CHECK (dns_consecutive_errors>=0);

-- the endpoint lifecycle can change in application code or in database
-- functions. a replacement operation never inherits a previous error streak.
-- +goose StatementBegin
CREATE FUNCTION control.reset_service_endpoint_dns_errors() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.dns_consecutive_errors=0;
    NEW.dns_last_error=NULL;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER reset_service_endpoint_dns_errors
    BEFORE UPDATE OF service_id,service_run_id,deployment_id,domain_id,ingress_pool_id,public,dns_automation,dns_authority_reference,retired_at
    ON control.service_endpoints FOR EACH ROW
    WHEN ((OLD.service_id,OLD.service_run_id,OLD.deployment_id,OLD.domain_id,OLD.ingress_pool_id,OLD.public,OLD.dns_automation,
           OLD.dns_authority_reference,OLD.retired_at,OLD.dns_state) IS DISTINCT FROM
          (NEW.service_id,NEW.service_run_id,NEW.deployment_id,NEW.domain_id,NEW.ingress_pool_id,NEW.public,NEW.dns_automation,
           NEW.dns_authority_reference,NEW.retired_at,NEW.dns_state))
    EXECUTE FUNCTION control.reset_service_endpoint_dns_errors();
