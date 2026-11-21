-- +goose Up
-- a policy-read hint is independent of the revision signed into visitor
-- tokens. a new workload or a longer workload lease needs a new snapshot;
-- it must not invalidate an unrelated visitor's signed permission.
CREATE TABLE control.visitor_policy_watch_versions (
    service_id text PRIMARY KEY REFERENCES control.services(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1)
);

-- +goose StatementBegin
CREATE FUNCTION control.touch_visitor_policy_watch(resource text) RETURNS void LANGUAGE sql AS $$
    INSERT INTO control.visitor_policy_watch_versions AS v(service_id,revision)
    SELECT id,1 FROM control.services WHERE id=resource
    ON CONFLICT (service_id) DO UPDATE SET revision=v.revision+1;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION control.watch_visitor_policy_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN PERFORM control.touch_visitor_policy_watch(OLD.service_id); END IF;
    IF TG_OP='INSERT' OR (TG_OP='UPDATE' AND NEW.service_id IS DISTINCT FROM OLD.service_id) THEN
        PERFORM control.touch_visitor_policy_watch(NEW.service_id);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER watch_workload_binding AFTER INSERT OR UPDATE OR DELETE ON control.workload_session_services
    FOR EACH ROW EXECUTE FUNCTION control.watch_visitor_policy_binding();
CREATE TRIGGER watch_endpoint_binding AFTER INSERT OR DELETE OR UPDATE OF service_id,service_run_id,hostname,domain_id,retired_at,public ON control.service_endpoints
    FOR EACH ROW EXECUTE FUNCTION control.watch_visitor_policy_binding();
CREATE TRIGGER watch_local_binding AFTER INSERT OR DELETE OR UPDATE OF service_id,service ON control.local_project_services
    FOR EACH ROW EXECUTE FUNCTION control.watch_visitor_policy_binding();
CREATE TRIGGER watch_allocation_binding AFTER INSERT ON control.publisher_namespace_allocations
    FOR EACH ROW EXECUTE FUNCTION control.watch_visitor_policy_binding();

-- +goose StatementBegin
CREATE FUNCTION control.watch_workload_lease() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource text;
BEGIN
    FOR resource IN SELECT service_id FROM control.workload_session_services WHERE workload_session_id=NEW.id ORDER BY service_id LOOP
        PERFORM control.touch_visitor_policy_watch(resource);
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER watch_workload_lease AFTER UPDATE ON control.workload_sessions FOR EACH ROW
    WHEN ((OLD.public_key,OLD.revoked_at,OLD.created_at,OLD.lease_expires_at,OLD.identity_expires_at,OLD.expires_at) IS DISTINCT FROM
          (NEW.public_key,NEW.revoked_at,NEW.created_at,NEW.lease_expires_at,NEW.identity_expires_at,NEW.expires_at))
    EXECUTE FUNCTION control.watch_workload_lease();

-- +goose StatementBegin
CREATE FUNCTION control.watch_guest_policy() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource text;
BEGIN
    FOR resource IN SELECT id FROM control.services WHERE guest_id=NEW.id ORDER BY id LOOP
        PERFORM control.touch_visitor_policy_watch(resource);
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER watch_guest_policy AFTER UPDATE ON control.guest_trials FOR EACH ROW
    WHEN ((OLD.active_service_run_id,OLD.ready_deadline,OLD.used_ready_ns,OLD.ended_at,OLD.expires_at) IS DISTINCT FROM
          (NEW.active_service_run_id,NEW.ready_deadline,NEW.used_ready_ns,NEW.ended_at,NEW.expires_at))
    EXECUTE FUNCTION control.watch_guest_policy();

CREATE TRIGGER watch_visitor_issuer AFTER INSERT OR UPDATE OR DELETE ON control.visitor_token_issuer
    FOR EACH ROW EXECUTE FUNCTION control.visitor_verification_keys_changed();

CREATE VIEW control.publisher_policy_watch_bookmarks AS
SELECT s.id AS service_id,
    encode(sha256(convert_to(concat_ws(':',s.id,p.revision,k.revision,s.service_revision,COALESCE(v.revision,0),COALESCE(binding.revision,0),
        COALESCE(project.revision,0),COALESCE(team.revision,0),COALESCE(deployment.revision,0)),'UTF8')),'hex') AS bookmark
FROM control.services s
JOIN control.visitor_policies p ON p.resource_id=s.id
JOIN control.visitor_verification_key_revision k ON k.id=1
LEFT JOIN control.visitor_policy_watch_versions v ON v.service_id=s.id
LEFT JOIN control.applied_project_services b ON b.service_id=s.id
LEFT JOIN control.deployments deployment ON deployment.id=b.deployment_id
LEFT JOIN control.registered_key_watch_versions binding ON (binding.team_id,binding.project_key,binding.service_id)=('','',s.id)
LEFT JOIN control.registered_key_watch_versions project ON (project.team_id,project.project_key,project.service_id)=(b.team_id,b.project_key,'')
LEFT JOIN control.registered_key_watch_versions team ON (team.team_id,team.project_key,team.service_id)=(b.team_id,'','');

-- +goose Down
DROP VIEW control.publisher_policy_watch_bookmarks;
DROP TRIGGER watch_visitor_issuer ON control.visitor_token_issuer;
DROP TRIGGER watch_guest_policy ON control.guest_trials;
DROP FUNCTION control.watch_guest_policy();
DROP TRIGGER watch_workload_lease ON control.workload_sessions;
DROP FUNCTION control.watch_workload_lease();
DROP TRIGGER watch_allocation_binding ON control.publisher_namespace_allocations;
DROP TRIGGER watch_local_binding ON control.local_project_services;
DROP TRIGGER watch_endpoint_binding ON control.service_endpoints;
DROP TRIGGER watch_workload_binding ON control.workload_session_services;
DROP FUNCTION control.watch_visitor_policy_binding();
DROP FUNCTION control.touch_visitor_policy_watch(text);
DROP TABLE control.visitor_policy_watch_versions;
