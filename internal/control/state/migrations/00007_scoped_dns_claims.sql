-- +goose Up
SET LOCAL lock_timeout = '2s';

-- siblings share ancestors; a claim excludes descendants only at its exact
-- name. there is no exclusive lock on a suffix shared by unrelated domains.
-- +goose StatementBegin
CREATE FUNCTION control.lock_dns_claim_name(hostname text, exclusive boolean) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE labels text[]:=string_to_array(hostname,'.'); position integer; name text;
BEGIN
    FOR position IN REVERSE cardinality(labels)..1 LOOP
        name:=array_to_string(labels[position:cardinality(labels)],'.');
        IF exclusive AND position=1 THEN
            PERFORM pg_advisory_xact_lock(hashtextextended('tnl:dns-claim:'||name,0));
        ELSE
            PERFORM pg_advisory_xact_lock_shared(hashtextextended('tnl:dns-claim:'||name,0));
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- enforce the same scoped fence for writes from previous serving binaries.
-- the check follows the lock in its own statement so a waited-for commit is
-- visible before accepting the new claim.
-- +goose StatementBegin
CREATE FUNCTION control.guard_custom_domain_name() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.kind<>'custom' OR NEW.released_at IS NOT NULL THEN RETURN NEW; END IF;
    PERFORM control.lock_dns_claim_name(NEW.canonical_domain,true);
    IF EXISTS(SELECT 1 FROM control.domains d WHERE d.id<>NEW.id AND d.released_at IS NULL
        AND (d.canonical_domain=NEW.canonical_domain
            OR right(d.canonical_domain,length(NEW.canonical_domain)+1)='.'||NEW.canonical_domain
            OR right(NEW.canonical_domain,length(d.canonical_domain)+1)='.'||d.canonical_domain))
        OR EXISTS(SELECT 1 FROM control.operator_nameserver_hostnames n
        WHERE n.hostname=NEW.canonical_domain
            OR right(n.hostname,length(NEW.canonical_domain)+1)='.'||NEW.canonical_domain
            OR right(NEW.canonical_domain,length(n.hostname)+1)='.'||n.hostname)
    THEN
        RAISE EXCEPTION 'custom domain overlaps a saved domain or nameserver' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER guard_custom_domain_name BEFORE INSERT OR UPDATE OF canonical_domain,released_at ON control.domains
FOR EACH ROW EXECUTE FUNCTION control.guard_custom_domain_name();

-- +goose StatementBegin
CREATE FUNCTION control.guard_endpoint_nameserver_name() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    PERFORM control.lock_dns_claim_name(NEW.hostname,false);
    IF EXISTS(SELECT 1 FROM control.operator_nameserver_hostnames WHERE hostname=NEW.hostname) THEN
        RAISE EXCEPTION 'service endpoint conflicts with an operator nameserver' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER guard_endpoint_nameserver_name BEFORE INSERT OR UPDATE OF hostname ON control.service_endpoints
FOR EACH ROW EXECUTE FUNCTION control.guard_endpoint_nameserver_name();
