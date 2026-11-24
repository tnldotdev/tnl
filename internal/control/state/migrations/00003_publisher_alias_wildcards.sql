-- +goose Up
-- existing alias bindings remain exact, including retired bindings.
ALTER TABLE control.service_endpoints ADD COLUMN wildcard_dns boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT service_endpoint_wildcard_dns CHECK (NOT wildcard_dns OR
        (service_run_id IS NOT NULL AND NOT dns_automation AND dns_state IN ('unmanaged','removed')));

-- only one trust boundary and ingress pool can own a literal wildcard name.
CREATE TABLE control.publisher_alias_wildcards (
    parent text PRIMARY KEY,
    team_id text NOT NULL REFERENCES control.teams(id),
    domain_id text NOT NULL REFERENCES control.domains(id),
    domain_revision bigint NOT NULL CHECK (domain_revision>0),
    ingress_pool_id text NOT NULL REFERENCES control.ingress_pools(id),
    zone_id text NOT NULL DEFAULT '',
    ipv4_address inet CHECK (family(ipv4_address)=4),
    ipv6_address inet CHECK (family(ipv6_address)=6),
    shadowed_labels text[] NOT NULL DEFAULT '{}',
    verified_until timestamptz,
    available_at timestamptz NOT NULL,
    work_owner text,
    work_epoch bigint NOT NULL DEFAULT 0,
    work_expires_at timestamptz,
    consecutive_errors bigint NOT NULL DEFAULT 0 CHECK (consecutive_errors>=0),
    CHECK (verified_until IS NULL OR zone_id<>'' AND num_nonnulls(ipv4_address,ipv6_address)>0),
    CHECK ((work_owner IS NULL)=(work_expires_at IS NULL))
);
CREATE INDEX publisher_alias_wildcards_work ON control.publisher_alias_wildcards(available_at,parent);
CREATE INDEX publisher_alias_wildcards_domain ON control.publisher_alias_wildcards(domain_id);
CREATE INDEX services_run_alias_parent ON control.services(run_alias_parent) WHERE run_alias_parent<>'';

-- source authority is the previously approved dedicated wildcard certificate
-- scope, not a publisher's requested suffix or an arbitrary DNS response.
CREATE VIEW control.publisher_alias_wildcard_facts AS
WITH candidates AS NOT MATERIALIZED (
SELECT service.id AS service_id, service.run_alias_parent AS parent, service.team_id, domain.id AS domain_id,
    domain.authority_revision AS domain_revision, endpoint.ingress_pool_id,
    domain.canonical_domain, domain.dns_authority_reference
FROM control.services service
JOIN control.domains domain ON domain.id=service.domain_id AND domain.state='ready' AND domain.released_at IS NULL
    AND domain.kind='custom' AND domain.team_id=service.team_id
JOIN control.teams team ON team.id=service.team_id AND team.deleted_at IS NULL
JOIN control.service_endpoints endpoint ON endpoint.service_id=service.id AND endpoint.hostname=service.certificate_hostname
    AND endpoint.domain_id=domain.id AND endpoint.service_run_id IS NULL AND endpoint.retired_at IS NULL
    AND endpoint.public AND endpoint.dns_automation AND endpoint.ingress_pool_id=service.ingress_pool_id
    AND endpoint.namespace=endpoint.hostname
JOIN control.deployments deployment ON deployment.id=endpoint.deployment_id AND deployment.deleted_at IS NULL
    AND deployment.team_id=service.team_id
JOIN control.service_namespace_claims claim ON claim.namespace=service.run_alias_parent AND claim.domain_id=domain.id
    AND claim.deployment_id=deployment.id AND claim.retired_at IS NULL
WHERE service.public AND service.enabled AND service.deleted_at IS NULL AND service.protocol='http'
    AND service.run_alias_parent<>'' AND service.run_alias_parent=service.certificate_scope
    AND right(service.run_alias_parent,length(domain.canonical_domain)+1)='.'||domain.canonical_domain
    AND EXISTS (
        SELECT 1 FROM control.dns_authorities authority WHERE authority.authority_reference=domain.dns_authority_reference
          AND authority.state='ready' AND authority.provider_zone_id IS NOT NULL
          AND authority.domain_id=domain.id AND authority.team_id=team.id
          AND authority.canonical_domain=domain.canonical_domain)
)
SELECT candidate.* FROM candidates candidate
WHERE NOT EXISTS (SELECT 1 FROM candidates other WHERE other.parent=candidate.parent
    AND (other.team_id,other.domain_id,other.domain_revision,other.ingress_pool_id)
        <>(candidate.team_id,candidate.domain_id,candidate.domain_revision,candidate.ingress_pool_id));

-- +goose StatementBegin
CREATE FUNCTION control.publisher_alias_dns_until(endpoint control.service_endpoints, observed_at timestamptz)
RETURNS timestamptz LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN NOT endpoint.wildcard_dns THEN CASE
            WHEN endpoint.dns_state='published' OR endpoint.dns_state='unmanaged' AND NOT endpoint.dns_automation
            THEN 'infinity'::timestamptz END
        ELSE (
            SELECT proof.verified_until FROM control.publisher_alias_wildcards proof
            JOIN control.services service ON service.id=endpoint.service_id AND service.team_id=proof.team_id
                AND service.certificate_scope=proof.parent AND service.run_alias_parent=proof.parent
            JOIN control.service_runs run ON run.id=endpoint.service_run_id
                AND ('*.'||proof.parent)=ANY(run.certificate_identifiers)
            JOIN control.domains domain ON domain.id=proof.domain_id AND domain.authority_revision=proof.domain_revision
            JOIN control.ingress_pools pool ON pool.id=proof.ingress_pool_id
                AND pool.ipv4_address IS NOT DISTINCT FROM proof.ipv4_address
                AND pool.ipv6_address IS NOT DISTINCT FROM proof.ipv6_address
            WHERE proof.parent=endpoint.publisher_alias_parent AND proof.domain_id=endpoint.domain_id
                AND proof.ingress_pool_id=endpoint.ingress_pool_id AND pool.state IN ('enabled','draining')
                AND proof.verified_until>observed_at AND split_part(endpoint.hostname,'.',1)<>ALL(proof.shadowed_labels)
                AND EXISTS (SELECT 1 FROM control.publisher_alias_wildcard_facts facts
                    WHERE facts.service_id=endpoint.service_id
                      AND (facts.parent,facts.team_id,facts.domain_id,facts.domain_revision,facts.ingress_pool_id)=
                        (proof.parent,proof.team_id,proof.domain_id,proof.domain_revision,proof.ingress_pool_id))
                AND EXISTS (
                    SELECT 1 FROM control.dns_authorities authority WHERE authority.authority_reference=domain.dns_authority_reference
                        AND authority.provider_zone_id=proof.zone_id)
        )
    END;
$$;
-- +goose StatementEnd
