-- +goose Up
SET LOCAL lock_timeout = '2s';

-- publication permission and wildcard DNS depend on these shared authorities.
-- their edits are rare; invalidate all projections rather than guessing which
-- services a membership, namespace claim, or conflicting wildcard parent affects.
-- +goose StatementBegin
DO $$
DECLARE relation text;
BEGIN
    FOREACH relation IN ARRAY ARRAY['teams','identities','team_memberships','identity_connections','company_eligibility',
        'member_slug_reservations','domains','deployment_management_grants','deployment_management_services',
        'deployment_management_deployments','project_services','applied_projects','deployments','service_namespace_claims',
        'ingress_pools','dns_authorities'] LOOP
        EXECUTE format('CREATE TRIGGER invalidate_ingress AFTER INSERT OR UPDATE OR DELETE ON control.%I
            FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency(''ingress'')',relation);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- allocating the next run number doesn't change a routing or permission fact.
CREATE TRIGGER invalidate_ingress_service AFTER INSERT OR DELETE OR UPDATE OF
    id,team_id,guest_id,public,enabled,deleted_at,ephemeral,protocol,expires_at,domain_id,
    ingress_pool_id,certificate_hostname,certificate_scope,run_alias_parent,service_port,endpoint_revision ON control.services
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','id');
-- a service can become or stop being a conflicting candidate for siblings'
-- wildcard proofs. ordinary services have no wildcard parent.
CREATE TRIGGER invalidate_ingress_parent_insert AFTER INSERT ON control.services
    FOR EACH ROW WHEN (NEW.run_alias_parent<>'') EXECUTE FUNCTION control.invalidate_read_dependency('ingress','run_alias_parent');
CREATE TRIGGER invalidate_ingress_parent_delete AFTER DELETE ON control.services
    FOR EACH ROW WHEN (OLD.run_alias_parent<>'') EXECUTE FUNCTION control.invalidate_read_dependency('ingress','run_alias_parent');
CREATE TRIGGER invalidate_ingress_parent_update AFTER UPDATE OF id,run_alias_parent,certificate_scope,certificate_hostname,
    domain_id,team_id,ingress_pool_id,public,enabled,deleted_at,protocol ON control.services
    FOR EACH ROW WHEN (OLD.run_alias_parent<>'' OR NEW.run_alias_parent<>'') EXECUTE FUNCTION control.invalidate_read_dependency('ingress','run_alias_parent');
CREATE TRIGGER invalidate_ingress_wildcard AFTER INSERT OR DELETE OR UPDATE OF parent,team_id,domain_id,domain_revision,
    ingress_pool_id,zone_id,ipv4_address,ipv6_address,shadowed_labels,verified_until ON control.publisher_alias_wildcards
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','parent');
CREATE TRIGGER invalidate_ingress_endpoint AFTER INSERT OR DELETE OR UPDATE OF hostname,service_id,service_run_id,publisher_alias_parent,
    deployment_id,local_source_key,domain_id,namespace,ingress_pool_id,public,dns_automation,dns_state,wildcard_dns,retired_at ON control.service_endpoints
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','hostname');
-- canonical bindings participate in cross-service wildcard conflict detection.
CREATE TRIGGER invalidate_ingress_endpoint_insert AFTER INSERT ON control.service_endpoints
    FOR EACH ROW WHEN (NEW.service_run_id IS NULL) EXECUTE FUNCTION control.invalidate_read_dependency('ingress');
CREATE TRIGGER invalidate_ingress_endpoint_delete AFTER DELETE ON control.service_endpoints
    FOR EACH ROW WHEN (OLD.service_run_id IS NULL) EXECUTE FUNCTION control.invalidate_read_dependency('ingress');
CREATE TRIGGER invalidate_ingress_endpoint_update AFTER UPDATE OF hostname,service_id,service_run_id,domain_id,namespace,ingress_pool_id,
    deployment_id,public,dns_automation,retired_at ON control.service_endpoints
    FOR EACH ROW WHEN (OLD.service_run_id IS NULL OR NEW.service_run_id IS NULL) EXECUTE FUNCTION control.invalidate_read_dependency('ingress');

CREATE TRIGGER invalidate_ingress_run AFTER INSERT OR DELETE OR UPDATE OF id,service_id,run_number,publisher_identity_id,
    publisher_grant_id,publisher_key_id,certificate_domain_id,certificate_hostname,certificate_identifiers,
    run_hostname,run_alias_parent,traffic_limits ON control.service_runs
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','id');
CREATE TRIGGER invalidate_ingress_policy AFTER INSERT OR UPDATE OR DELETE ON control.visitor_policies
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','resource_id');
CREATE TRIGGER invalidate_ingress_identity AFTER INSERT OR UPDATE OR DELETE ON control.publisher_identities
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','id');
CREATE TRIGGER invalidate_ingress_grant AFTER INSERT OR UPDATE OR DELETE ON control.publisher_grants
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','id');
CREATE TRIGGER invalidate_ingress_key AFTER INSERT OR UPDATE OR DELETE ON control.publisher_identity_keys
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','id');
CREATE TRIGGER invalidate_ingress_guest AFTER INSERT OR UPDATE OR DELETE ON control.guest_trials
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','id');
CREATE TRIGGER invalidate_ingress_allocation AFTER INSERT OR UPDATE OR DELETE ON control.publisher_namespace_allocations
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','service_id');
CREATE TRIGGER invalidate_ingress_opaque_host AFTER INSERT OR UPDATE OR DELETE ON control.opaque_service_hosts
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','service_id');
CREATE TRIGGER invalidate_ingress_binding AFTER INSERT OR UPDATE OR DELETE ON control.applied_project_services
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('ingress','service_id');

-- +goose StatementBegin
DO $$
DECLARE relation text;
BEGIN
    FOR relation IN SELECT DISTINCT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relnamespace='control'::regnamespace AND t.tgname LIKE 'invalidate_ingress%' LOOP
        EXECUTE format('CREATE TRIGGER invalidate_ingress_truncate AFTER TRUNCATE ON control.%I
            FOR EACH STATEMENT EXECUTE FUNCTION control.invalidate_read_dependency(''ingress'')',relation);
    END LOOP;
END;
$$;
-- +goose StatementEnd
