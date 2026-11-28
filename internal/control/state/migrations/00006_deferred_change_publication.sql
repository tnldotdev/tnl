-- +goose Up
SET LOCAL lock_timeout = '5s';

-- keep shared projection writes out of the operation's lock lifetime. each
-- transaction queues its own changes and publishes them together at commit.
-- the queue is emptied in that same transaction; rollback leaves nothing behind.
CREATE TABLE control.pending_change_publications (
    transaction_id xid8 NOT NULL,
    kind text NOT NULL CHECK (kind IN ('audit','registered_key','read_dependency')),
    scope text[] NOT NULL,
    PRIMARY KEY(transaction_id,kind,scope)
);

-- the migration owner's triggers are the only queue readers and writers,
-- including installations with permissive default table grants.
-- +goose StatementBegin
DO $$
DECLARE grantee oid;
BEGIN
    FOR grantee IN SELECT DISTINCT acl.grantee FROM pg_class c,
        LATERAL aclexplode(c.relacl) acl WHERE c.oid='control.pending_change_publications'::regclass
        AND acl.grantee<>c.relowner LOOP
        EXECUTE format('REVOKE ALL ON control.pending_change_publications FROM %s',
            CASE WHEN grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(grantee)) END);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION control.queue_change_publication(kind text, scope text[]) RETURNS void
LANGUAGE sql SET search_path=pg_catalog AS $$
    INSERT INTO control.pending_change_publications(transaction_id,kind,scope)
    VALUES(pg_current_xact_id(),kind,scope) ON CONFLICT DO NOTHING;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION control.queue_change_publication(text,text[]) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION control.queue_service_audit_cursor() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM control.queue_change_publication('audit',ARRAY[COALESCE(NEW.team_id,'guest/'||NEW.guest_id),NEW.id]);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION control.queue_service_audit_cursor() FROM PUBLIC;

CREATE TRIGGER queue_service_audit_cursor
AFTER INSERT ON control.service_audit_events
FOR EACH ROW EXECUTE FUNCTION control.queue_service_audit_cursor();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control.invalidate_read_dependency() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old_key text; new_key text; slot integer;
BEGIN
    IF TG_OP='TRUNCATE' OR TG_NARGS=1 THEN
        PERFORM control.queue_change_publication('read_dependency',ARRAY[TG_ARGV[0],'-1']);
        RETURN NULL;
    END IF;
    IF TG_OP<>'INSERT' THEN old_key:=COALESCE(to_jsonb(OLD)->>TG_ARGV[1],''); END IF;
    IF TG_OP<>'DELETE' THEN new_key:=COALESCE(to_jsonb(NEW)->>TG_ARGV[1],''); END IF;
    FOR slot IN SELECT DISTINCT CASE WHEN k='' THEN -1 ELSE hashtext(k)&255 END
        FROM unnest(ARRAY[old_key,new_key]) k WHERE k IS NOT NULL ORDER BY 1 LOOP
        PERFORM control.queue_change_publication('read_dependency',ARRAY[TG_ARGV[0],slot::text]);
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control.registered_key_watch_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE facts jsonb; versions jsonb[]; team text; project text; service text;
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
            SELECT p.team_id INTO team FROM control.publisher_identities p
            WHERE p.id=facts->>'publisher_identity_id' AND p.ownership='team';
        ELSE RAISE EXCEPTION 'unknown registered key watch scope';
        END CASE;
        IF team IS NULL OR service IS NULL THEN CONTINUE; END IF;
        PERFORM control.queue_change_publication('registered_key',ARRAY[team,project,service]);
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- one deferred callback drains the whole transaction in a fixed order. audit
-- guards precede counters to match previous binaries that still take those
-- guards before inserting events. subsequent queued callbacks are no-ops.
-- +goose StatementBegin
CREATE FUNCTION control.publish_pending_changes() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE change record; owner text;
BEGIN
    IF NEW.transaction_id<>pg_current_xact_id() THEN
        RAISE EXCEPTION 'change publication transaction does not match';
    END IF;
    FOR owner IN SELECT DISTINCT scope[1] COLLATE "C" FROM control.pending_change_publications
        WHERE transaction_id=NEW.transaction_id AND kind='audit' ORDER BY 1 LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended('tnl:service-audit:'||owner,0));
    END LOOP;
    FOR change IN SELECT scope FROM control.pending_change_publications
        WHERE transaction_id=NEW.transaction_id AND kind='registered_key' ORDER BY scope COLLATE "C" LOOP
        INSERT INTO control.registered_key_watch_versions AS v(team_id,project_key,service_id,revision)
        VALUES(change.scope[1],change.scope[2],change.scope[3],1)
        ON CONFLICT ON CONSTRAINT registered_key_watch_versions_pkey DO UPDATE SET revision=v.revision+1;
    END LOOP;
    -- registered-key changes enqueue read invalidations too. take this snapshot
    -- after publishing them, before deleting the transaction's queue.
    FOR change IN SELECT scope FROM control.pending_change_publications
        WHERE transaction_id=NEW.transaction_id AND kind='read_dependency'
        ORDER BY scope[1] COLLATE "C",scope[2]::integer LOOP
        INSERT INTO control.read_dependency_versions AS v(topic,bucket)
        VALUES(change.scope[1],change.scope[2]::integer)
        ON CONFLICT(topic,bucket) DO UPDATE SET revision=v.revision+1;
    END LOOP;
    -- insert-time identity values stay private. readers see only the final
    -- cursor, ordered by commit for each owner and by insertion within a batch.
    FOR change IN SELECT event.id FROM control.pending_change_publications pending
        JOIN control.service_audit_events event ON event.id=pending.scope[2]
        WHERE pending.transaction_id=NEW.transaction_id AND pending.kind='audit'
        ORDER BY pending.scope[1] COLLATE "C",event.cursor LOOP
        UPDATE control.service_audit_events SET cursor=DEFAULT WHERE id=change.id;
    END LOOP;
    DELETE FROM control.pending_change_publications WHERE transaction_id=NEW.transaction_id;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION control.publish_pending_changes() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER publish_pending_changes
AFTER INSERT ON control.pending_change_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION control.publish_pending_changes();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control.append_service_audit(event_id text, team text, service text, operation text,
    happened timestamptz, actor_id text DEFAULT NULL, device text DEFAULT NULL, publisher text DEFAULT NULL,
    run text DEFAULT NULL, revision bigint DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE guest text; stored_team text;
BEGIN
    SELECT s.team_id,s.guest_id INTO stored_team,guest FROM control.services s WHERE s.id=service;
    IF NOT FOUND OR stored_team IS DISTINCT FROM team THEN
        RAISE EXCEPTION 'service audit ownership does not match' USING ERRCODE='23514';
    END IF;
    INSERT INTO control.service_audit_events(id,team_id,guest_id,service_id,event_type,occurred_at,
        actor_identity_id,device_id,publisher_identity_id,run_id,configuration_revision)
    VALUES(event_id,team,guest,service,operation,happened,actor_id,device,publisher,run,revision)
    ON CONFLICT(id) DO NOTHING;
END;
$$;
-- +goose StatementEnd
