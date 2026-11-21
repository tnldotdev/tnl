-- +goose Up
-- return the grant selected by the existing permission decision. a replacement
-- grant can authorize a new admission but cannot renew one made by the old grant.
DROP FUNCTION control.visitor_identity_permission(text,text,text,text,text,timestamptz);

-- +goose StatementBegin
CREATE FUNCTION control.visitor_identity_permission(scope_kind text, scope_id text, person_id text,
    session_id text, preview_scope text, at_time timestamptz)
RETURNS TABLE(reason text, expires_at timestamptz, grant_id text) LANGUAGE sql STABLE AS $$
    WITH resources AS (
        SELECT s.id,s.team_id,ownership.membership_id,ownership.namespace_scope
        FROM control.services s
        LEFT JOIN LATERAL (
            SELECT root.membership_id,root.namespace_scope
            FROM control.publisher_namespace_allocations allocation
            JOIN control.publisher_grants root ON root.id=allocation.publisher_grant_id
                AND root.publisher_identity_id=allocation.publisher_identity_id AND root.kind='namespace'
            JOIN control.publisher_identities publisher ON publisher.id=root.publisher_identity_id AND publisher.team_id=s.team_id
            JOIN control.service_endpoints endpoint ON endpoint.service_id=s.id AND endpoint.hostname=s.certificate_hostname
                AND endpoint.domain_id=s.domain_id AND endpoint.retired_at IS NULL AND endpoint.deployment_id IS NULL
                AND endpoint.local_source_key='' AND endpoint.domain_id=root.domain_id AND endpoint.namespace=root.namespace
            WHERE allocation.service_id=s.id AND allocation.deployment_id IS NULL
            UNION ALL
            SELECT NULL::text,'shared'::text
            FROM control.publisher_namespace_allocations allocation
            JOIN control.publisher_grants root ON root.id=allocation.publisher_grant_id
                AND root.publisher_identity_id=allocation.publisher_identity_id AND root.kind='deployment_credential'
            JOIN control.deployment_management_grants approval ON approval.grant_id=root.id AND approval.team_id=s.team_id
            JOIN control.deployments deployment ON deployment.id=allocation.deployment_id AND deployment.team_id=approval.team_id
                AND deployment.project_key=approval.project_key AND deployment.deleted_at IS NULL
            JOIN control.service_namespace_claims claim ON claim.deployment_id=deployment.id AND claim.namespace=deployment.namespace
                AND claim.domain_id=deployment.domain_id AND claim.retired_at IS NULL
            JOIN control.service_endpoints endpoint ON endpoint.service_id=s.id AND endpoint.hostname=s.certificate_hostname
                AND endpoint.deployment_id=deployment.id AND endpoint.namespace=claim.namespace
                AND endpoint.domain_id=claim.domain_id AND endpoint.domain_id=s.domain_id AND endpoint.retired_at IS NULL
            WHERE allocation.service_id=s.id
        ) ownership ON true
        WHERE scope_kind='service' AND s.id=scope_id AND s.enabled AND s.deleted_at IS NULL
    )
    SELECT permission.reason,LEAST(permission.expires_at,control.company_subject_deadline(r.team_id,i.id,session_id,at_time)),permission.grant_id
    FROM resources r
    JOIN control.teams t ON t.id=r.team_id AND t.deleted_at IS NULL
    JOIN control.identities i ON i.id=person_id AND i.disabled_at IS NULL
    LEFT JOIN control.team_memberships m ON m.team_id=r.team_id AND m.identity_id=i.id AND control.active_membership(m.id,at_time)
    CROSS JOIN LATERAL (
        SELECT 'owner'::text AS reason,NULL::timestamptz AS expires_at,0 AS priority,NULL::text AS grant_id,NULL::timestamptz AS created_at
        WHERE (r.namespace_scope='member' AND m.id=r.membership_id)
            OR (r.namespace_scope='shared' AND m.role IN ('owner','admin'))
        UNION ALL
        SELECT CASE g.kind WHEN 'team' THEN 'team_grant' ELSE 'identity_grant' END,g.expires_at,2,g.id,g.created_at
        FROM control.visitor_grants g WHERE g.service_id=r.id AND g.team_id=r.team_id
            AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>at_time)
            AND (NOT g.auto_owner OR m.role IN ('owner','admin'))
            AND ((g.kind='team' AND m.id IS NOT NULL) OR (g.kind='identity' AND g.identity_id=i.id))
    ) permission
    WHERE control.company_subject_session_authorized(r.team_id,i.id,session_id,at_time)
    ORDER BY permission.priority,permission.expires_at DESC NULLS FIRST,permission.created_at,permission.grant_id LIMIT 1;
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION control.visitor_identity_permission(text,text,text,text,text,timestamptz);
-- +goose StatementBegin
CREATE FUNCTION control.visitor_identity_permission(scope_kind text, scope_id text, person_id text,
    session_id text, preview_scope text, at_time timestamptz)
RETURNS TABLE(reason text, expires_at timestamptz) LANGUAGE sql STABLE AS $$
    WITH resources AS (
        SELECT s.id,s.team_id,ownership.membership_id,ownership.namespace_scope
        FROM control.services s
        LEFT JOIN LATERAL (
            SELECT root.membership_id,root.namespace_scope
            FROM control.publisher_namespace_allocations allocation
            JOIN control.publisher_grants root ON root.id=allocation.publisher_grant_id
                AND root.publisher_identity_id=allocation.publisher_identity_id AND root.kind='namespace'
            JOIN control.publisher_identities publisher ON publisher.id=root.publisher_identity_id AND publisher.team_id=s.team_id
            JOIN control.service_endpoints endpoint ON endpoint.service_id=s.id AND endpoint.hostname=s.certificate_hostname
                AND endpoint.domain_id=s.domain_id AND endpoint.retired_at IS NULL AND endpoint.deployment_id IS NULL
                AND endpoint.local_source_key='' AND endpoint.domain_id=root.domain_id AND endpoint.namespace=root.namespace
            WHERE allocation.service_id=s.id AND allocation.deployment_id IS NULL
            UNION ALL
            SELECT NULL::text,'shared'::text
            FROM control.publisher_namespace_allocations allocation
            JOIN control.publisher_grants root ON root.id=allocation.publisher_grant_id
                AND root.publisher_identity_id=allocation.publisher_identity_id AND root.kind='deployment_credential'
            JOIN control.deployment_management_grants approval ON approval.grant_id=root.id AND approval.team_id=s.team_id
            JOIN control.deployments deployment ON deployment.id=allocation.deployment_id AND deployment.team_id=approval.team_id
                AND deployment.project_key=approval.project_key AND deployment.deleted_at IS NULL
            JOIN control.service_namespace_claims claim ON claim.deployment_id=deployment.id AND claim.namespace=deployment.namespace
                AND claim.domain_id=deployment.domain_id AND claim.retired_at IS NULL
            JOIN control.service_endpoints endpoint ON endpoint.service_id=s.id AND endpoint.hostname=s.certificate_hostname
                AND endpoint.deployment_id=deployment.id AND endpoint.namespace=claim.namespace
                AND endpoint.domain_id=claim.domain_id AND endpoint.domain_id=s.domain_id AND endpoint.retired_at IS NULL
            WHERE allocation.service_id=s.id
        ) ownership ON true
        WHERE scope_kind='service' AND s.id=scope_id AND s.enabled AND s.deleted_at IS NULL
    )
    SELECT permission.reason,LEAST(permission.expires_at,control.company_subject_deadline(r.team_id,i.id,session_id,at_time))
    FROM resources r
    JOIN control.teams t ON t.id=r.team_id AND t.deleted_at IS NULL
    JOIN control.identities i ON i.id=person_id AND i.disabled_at IS NULL
    LEFT JOIN control.team_memberships m ON m.team_id=r.team_id AND m.identity_id=i.id AND control.active_membership(m.id,at_time)
    CROSS JOIN LATERAL (
        SELECT 'owner'::text AS reason,NULL::timestamptz AS expires_at,0 AS priority
        WHERE (r.namespace_scope='member' AND m.id=r.membership_id)
            OR (r.namespace_scope='shared' AND m.role IN ('owner','admin'))
        UNION ALL
        SELECT CASE g.kind WHEN 'team' THEN 'team_grant' ELSE 'identity_grant' END,g.expires_at,2
        FROM control.visitor_grants g WHERE g.service_id=r.id AND g.team_id=r.team_id
            AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>at_time)
            AND (NOT g.auto_owner OR m.role IN ('owner','admin'))
            AND ((g.kind='team' AND m.id IS NOT NULL) OR (g.kind='identity' AND g.identity_id=i.id))
    ) permission
    WHERE control.company_subject_session_authorized(r.team_id,i.id,session_id,at_time)
    ORDER BY permission.priority,permission.expires_at DESC NULLS FIRST LIMIT 1;
$$;
-- +goose StatementEnd
