-- name: GetIdentityTeamDomainRelease :one
SELECT domain.id, domain.kind, domain.team_id, domain.canonical_domain,
    domain.dns_authority_reference, domain.state, domain.authority_revision,
    domain.created_at, domain.verified_at, domain.updated_at, domain.released_at,
    COALESCE(authority.nameservers, '{}'::text[]) AS nameservers,
    sqlc.arg(observed_at)::timestamptz AS observed_at,
    array_remove(ARRAY[
        CASE WHEN EXISTS (
            SELECT 1 FROM control.deployments deployment
            WHERE deployment.domain_id=domain.id AND deployment.deleted_at IS NULL
        ) THEN 'deployments' END,
        CASE WHEN EXISTS (
            SELECT 1 FROM control.services service
            WHERE service.domain_id=domain.id AND service.deleted_at IS NULL
        ) THEN 'services' END,
        CASE WHEN EXISTS (
            SELECT 1 FROM control.service_endpoints endpoint
            WHERE endpoint.domain_id=domain.id AND endpoint.dns_state NOT IN ('unmanaged','removed')
        ) THEN 'endpoint_dns' END,
        CASE WHEN EXISTS (
            SELECT 1 FROM control.acme_orders issuance
            JOIN control.acme_authorizations auth ON auth.order_id=issuance.id
            WHERE issuance.certificate_domain_id=domain.id
              AND (auth.state IN ('presenting','presented','validating','valid','cleaning')
                OR auth.presented_at IS NOT NULL AND auth.cleanup_completed_at IS NULL)
        ) THEN 'challenge_cleanup' END,
        CASE WHEN EXISTS (
            SELECT 1 FROM control.acme_orders issuance
            WHERE issuance.certificate_domain_id=domain.id
              AND issuance.state NOT IN ('waiting_for_install','installed','failed','canceled')
        ) THEN 'issuance' END,
        CASE WHEN EXISTS (
            SELECT 1 FROM control.acme_orders issuance
            WHERE issuance.certificate_domain_id=domain.id
              AND issuance.finalization_possible AND issuance.not_after IS NULL
        ) THEN 'uncertain_issuance' END,
        CASE WHEN EXISTS (
            SELECT 1 FROM control.acme_orders issuance
            WHERE issuance.certificate_domain_id=domain.id AND issuance.not_after>sqlc.arg(observed_at)
        ) OR EXISTS (
            SELECT 1 FROM control.service_supplied_certificates supplied
            WHERE supplied.certificate_domain_id=domain.id AND supplied.not_after>sqlc.arg(observed_at)
        ) THEN 'certificate' END,
        CASE WHEN authority.state IS DISTINCT FROM 'released' THEN 'dns_authority' END
    ]::text[], NULL)::text[] AS release_blockers,
    GREATEST((SELECT max(issuance.not_after)::timestamptz FROM control.acme_orders issuance
        WHERE issuance.certificate_domain_id=domain.id),
        (SELECT max(supplied.not_after)::timestamptz FROM control.service_supplied_certificates supplied
        WHERE supplied.certificate_domain_id=domain.id))::timestamptz AS certificate_expires_at
FROM control.domains domain
LEFT JOIN control.dns_authorities authority ON authority.authority_reference=domain.dns_authority_reference
WHERE domain.id=sqlc.arg(domain_id)
  AND (domain.kind='managed' AND domain.released_at IS NULL OR domain.team_id=sqlc.arg(team_id))
  AND EXISTS (
      SELECT 1 FROM control.teams team
      JOIN control.team_memberships member ON member.team_id=team.id
      WHERE team.id=sqlc.arg(team_id) AND team.deleted_at IS NULL
        AND member.identity_id=sqlc.arg(identity_id)
        AND control.active_membership(member.id,CURRENT_TIMESTAMP)
  );
