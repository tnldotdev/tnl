-- +goose Up
-- a deployment credential depends on its project, on team-owned signing
-- identities, and on the particular service binding. keep separate counters:
-- two transactions can commit in either order, including the first binding
-- racing a change to a grant. no trigger has to find the subscribers.
CREATE TABLE control.registered_key_watch_versions (
    team_id text NOT NULL,
    project_key text NOT NULL,
    service_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    CHECK ((team_id <> '' AND service_id = '') OR
           (team_id = '' AND project_key = '' AND service_id <> '')),
    PRIMARY KEY(team_id,project_key,service_id)
);

-- +goose StatementBegin
CREATE FUNCTION control.registered_key_watch_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    facts jsonb;
    versions jsonb[];
    team text;
    project text;
    service text;
    previous text[];
BEGIN
    IF TG_OP='INSERT' THEN versions:=ARRAY[to_jsonb(NEW)];
    ELSIF TG_OP='DELETE' THEN versions:=ARRAY[to_jsonb(OLD)];
    ELSE versions:=ARRAY[to_jsonb(OLD),to_jsonb(NEW)]; END IF;
    FOREACH facts IN ARRAY versions LOOP
        team:=''; project:=''; service:='';
        CASE TG_ARGV[0]
        WHEN 'project' THEN team:=facts->>'team_id'; project:=facts->>'project_key';
        WHEN 'binding' THEN service:=facts->>'service_id';
        WHEN 'service' THEN service:=facts->>'id';
        WHEN 'team' THEN team:=facts->>'id';
        WHEN 'grant' THEN
            IF facts->>'kind'<>'deployment_credential' THEN CONTINUE; END IF;
            team:=facts->>'team_id';
        WHEN 'identity' THEN
            IF facts->>'ownership'<>'team' THEN CONTINUE; END IF;
            team:=facts->>'team_id';
        WHEN 'key' THEN
            -- an identity must exist before a key can be attached. transferring
            -- the identity itself also changes the old and new team counters.
            SELECT p.team_id INTO team FROM control.publisher_identities p
            WHERE p.id=facts->>'publisher_identity_id' AND p.ownership='team';
        ELSE RAISE EXCEPTION 'unknown registered key watch scope';
        END CASE;
        IF team IS NULL OR service IS NULL OR ARRAY[team,project,service]=previous THEN CONTINUE; END IF;
        INSERT INTO control.registered_key_watch_versions AS v(team_id,project_key,service_id,revision)
        VALUES(team,project,service,1)
        ON CONFLICT ON CONSTRAINT registered_key_watch_versions_pkey DO UPDATE SET revision=v.revision+1;
        previous:=ARRAY[team,project,service];
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER registered_key_project_service AFTER INSERT OR DELETE OR UPDATE OF team_id,project_key,name,protocol ON control.project_services
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('project');
CREATE TRIGGER registered_key_approval AFTER INSERT OR UPDATE OR DELETE ON control.deployment_management_grants
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('project');
-- losing a manage or publish selection also fails deployment_credential_available.
CREATE TRIGGER registered_key_selection AFTER INSERT OR UPDATE OR DELETE ON control.deployment_management_services
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('project');
CREATE TRIGGER registered_key_deployment_selection AFTER INSERT OR UPDATE OR DELETE ON control.deployment_management_deployments
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('project');
CREATE TRIGGER registered_key_deployment AFTER UPDATE OF deleted_at,team_id,project_key ON control.deployments
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('project');
CREATE TRIGGER registered_key_binding AFTER INSERT OR DELETE OR UPDATE OF service_id,service,deployment_id,team_id,project_key ON control.applied_project_services
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('binding');
CREATE TRIGGER registered_key_service AFTER UPDATE ON control.services FOR EACH ROW
    WHEN ((OLD.team_id,OLD.protocol,OLD.enabled,OLD.deleted_at) IS DISTINCT FROM (NEW.team_id,NEW.protocol,NEW.enabled,NEW.deleted_at))
    EXECUTE FUNCTION control.registered_key_watch_changed('service');
CREATE TRIGGER registered_key_team AFTER UPDATE OF deleted_at ON control.teams
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('team');
CREATE TRIGGER registered_key_grant AFTER INSERT OR UPDATE OR DELETE ON control.publisher_grants
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('grant');
CREATE TRIGGER registered_key_identity AFTER UPDATE OF team_id,ownership,revoked_at ON control.publisher_identities
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('identity');
CREATE TRIGGER registered_key_signing_key AFTER INSERT OR UPDATE OR DELETE ON control.publisher_identity_keys
    FOR EACH ROW EXECUTE FUNCTION control.registered_key_watch_changed('key');

-- +goose Down
DROP TRIGGER registered_key_signing_key ON control.publisher_identity_keys;
DROP TRIGGER registered_key_identity ON control.publisher_identities;
DROP TRIGGER registered_key_grant ON control.publisher_grants;
DROP TRIGGER registered_key_team ON control.teams;
DROP TRIGGER registered_key_service ON control.services;
DROP TRIGGER registered_key_binding ON control.applied_project_services;
DROP TRIGGER registered_key_deployment ON control.deployments;
DROP TRIGGER registered_key_deployment_selection ON control.deployment_management_deployments;
DROP TRIGGER registered_key_selection ON control.deployment_management_services;
DROP TRIGGER registered_key_approval ON control.deployment_management_grants;
DROP TRIGGER registered_key_project_service ON control.project_services;
DROP FUNCTION control.registered_key_watch_changed();
DROP TABLE control.registered_key_watch_versions;
