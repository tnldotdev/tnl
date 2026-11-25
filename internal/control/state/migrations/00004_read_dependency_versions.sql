-- +goose Up
SET LOCAL lock_timeout = '2s';

-- a collision only makes another reader check its source rows. fixed buckets
-- bound the table even after deleting the services that changed it.
CREATE TABLE control.read_dependency_versions (
    topic text NOT NULL, bucket integer NOT NULL CHECK (bucket BETWEEN -1 AND 255),
    revision bigint NOT NULL DEFAULT 1, PRIMARY KEY(topic,bucket)
);

-- each trigger names a topic and optionally a column containing its scope.
-- the empty scope covers shared facts. changing a key invalidates both sides.
-- +goose StatementBegin
CREATE FUNCTION control.invalidate_read_dependency() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old_key text; new_key text; slot integer;
BEGIN
    IF TG_OP='TRUNCATE' OR TG_NARGS=1 THEN
        INSERT INTO control.read_dependency_versions AS v(topic,bucket) VALUES(TG_ARGV[0],-1)
        ON CONFLICT(topic,bucket) DO UPDATE SET revision=v.revision+1;
        RETURN NULL;
    END IF;
    IF TG_OP<>'INSERT' THEN old_key:=COALESCE(to_jsonb(OLD)->>TG_ARGV[1],''); END IF;
    IF TG_OP<>'DELETE' THEN new_key:=COALESCE(to_jsonb(NEW)->>TG_ARGV[1],''); END IF;
    FOR slot IN SELECT DISTINCT CASE WHEN k='' THEN -1 ELSE hashtext(k)&255 END
        FROM unnest(ARRAY[old_key,new_key]) k WHERE k IS NOT NULL ORDER BY 1 LOOP
        INSERT INTO control.read_dependency_versions AS v(topic,bucket) VALUES(TG_ARGV[0],slot)
        ON CONFLICT(topic,bucket) DO UPDATE SET revision=v.revision+1;
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION control.invalidate_read_dependency() FROM PUBLIC;

-- carry forward read access; only the migration owner's trigger writes versions.
-- +goose StatementBegin
DO $$
DECLARE reader record;
BEGIN
    -- default privileges can grant more than this table needs. replace its
    -- non-owner grants rather than adding select to an existing write grant.
    FOR reader IN SELECT DISTINCT acl.grantee FROM pg_class c,
        LATERAL aclexplode(c.relacl) acl WHERE c.oid='control.read_dependency_versions'::regclass
        AND acl.grantee<>c.relowner LOOP
        EXECUTE format('REVOKE ALL ON control.read_dependency_versions FROM %s',
            CASE WHEN reader.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(reader.grantee)) END);
    END LOOP;
    FOR reader IN SELECT DISTINCT acl.grantee FROM pg_class c,
        LATERAL aclexplode(c.relacl) acl WHERE c.oid='control.connector_peer_watch_versions'::regclass
        AND acl.privilege_type='SELECT' AND acl.grantee<>c.relowner LOOP
        EXECUTE format('GRANT SELECT ON control.read_dependency_versions TO %s',
            CASE WHEN reader.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(reader.grantee)) END);
    END LOOP;
    -- a runtime provisioned before v3 may lack the wildcard DNS reads used by
    -- endpoint readiness. limit this to existing endpoint writers that already
    -- read the corresponding DNS, deployment and service authorities.
    FOR reader IN SELECT DISTINCT acl.grantee FROM pg_class c,
        LATERAL aclexplode(c.relacl) acl WHERE c.oid='control.service_endpoints'::regclass
        AND acl.privilege_type='UPDATE' AND acl.grantee NOT IN (0,c.relowner)
        AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['services','service_runs','teams','domains','deployments',
            'service_namespace_claims','ingress_pools','dns_authorities','service_endpoints']) source
            WHERE NOT has_table_privilege(acl.grantee,'control.'||source,'SELECT')) LOOP
        EXECUTE format('GRANT SELECT ON control.publisher_alias_wildcards, control.publisher_alias_wildcard_facts TO %I',
            pg_get_userbyid(reader.grantee));
        EXECUTE format('GRANT EXECUTE ON FUNCTION control.publisher_alias_dns_until(control.service_endpoints,timestamptz) TO %I',
            pg_get_userbyid(reader.grantee));
    END LOOP;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER invalidate_policy AFTER INSERT OR UPDATE OR DELETE ON control.visitor_policies
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch','resource_id');
CREATE TRIGGER invalidate_policy_hint AFTER INSERT OR UPDATE OR DELETE ON control.visitor_policy_watch_versions
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch','service_id');
CREATE TRIGGER invalidate_service_revision AFTER UPDATE ON control.services
    FOR EACH ROW WHEN (OLD.service_revision IS DISTINCT FROM NEW.service_revision)
    EXECUTE FUNCTION control.invalidate_read_dependency('watch','id');
CREATE TRIGGER invalidate_issuer_revision AFTER INSERT OR UPDATE OR DELETE ON control.visitor_verification_key_revision
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch');
-- registered key revisions already cover binding moves and connect selections.
-- a project or team revision has an empty service_id and wakes all scopes.
CREATE TRIGGER invalidate_key_revision AFTER INSERT OR UPDATE OR DELETE ON control.registered_key_watch_versions
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch','service_id');
CREATE TRIGGER invalidate_deployment_revision AFTER UPDATE ON control.deployments
    FOR EACH ROW WHEN (OLD.revision IS DISTINCT FROM NEW.revision)
    EXECUTE FUNCTION control.invalidate_read_dependency('watch');

CREATE TRIGGER invalidate_connector_watch AFTER INSERT OR UPDATE OR DELETE ON control.connector_peer_watch_versions
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch','service_run_id');
CREATE TRIGGER invalidate_alias_watch AFTER INSERT OR UPDATE OR DELETE ON control.run_alias_watch_versions
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch','service_run_id');
CREATE TRIGGER invalidate_watch_run_lifetime AFTER INSERT OR DELETE OR UPDATE OF started_at,closed_at,service_id,id ON control.service_runs
    FOR EACH ROW EXECUTE FUNCTION control.invalidate_read_dependency('watch','id');

-- +goose StatementBegin
DO $$
DECLARE relation text;
BEGIN
    FOREACH relation IN ARRAY ARRAY['visitor_policies','visitor_policy_watch_versions','services','visitor_verification_key_revision',
        'registered_key_watch_versions','deployments','applied_project_services','deployment_management_services',
        'connector_peer_watch_versions','run_alias_watch_versions','service_runs'] LOOP
        EXECUTE format('CREATE TRIGGER invalidate_watch_truncate AFTER TRUNCATE ON control.%I
            FOR EACH STATEMENT EXECUTE FUNCTION control.invalidate_read_dependency(''watch'')',relation);
    END LOOP;
END;
$$;
-- +goose StatementEnd
