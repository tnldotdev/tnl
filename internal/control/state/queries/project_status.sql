-- name: GetAppliedProject :one
SELECT * FROM control.applied_projects WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key);

-- name: ListProjectPublications :many
-- one row per open publication, or one row for an idle/unrealized resource.
-- worktree bytes are encoded so separators cannot alias another cursor key.
WITH resources AS (
    SELECT applied.service,COALESCE(deployment.name,'local')::text AS deployment,''::text AS worktree_key,applied.service_id
    FROM control.applied_project_services applied
    LEFT JOIN control.deployments deployment ON deployment.id=applied.deployment_id
    WHERE applied.team_id=sqlc.arg(team_id) AND applied.project_key=sqlc.arg(project_key)
       AND (applied.deployment_id IS NOT NULL OR applied.service_id IS NOT NULL OR NOT EXISTS (
          SELECT 1 FROM control.local_project_services local
          WHERE local.team_id=applied.team_id AND local.project_key=applied.project_key AND local.service=applied.service))
    UNION ALL
    SELECT local.service,'local'::text AS deployment,local.worktree_key,local.service_id
    FROM control.local_project_services local
    WHERE local.team_id=sqlc.arg(team_id) AND local.project_key=sqlc.arg(project_key)
), publications AS (
    SELECT resource.service,resource.deployment,resource.worktree_key,resource.service_id,
        COALESCE(service.certificate_hostname,'')::text AS hostname,
        COALESCE(service.service_port,0)::integer AS port,
        COALESCE(service.enabled AND service.deleted_at IS NULL,false)::boolean AS enabled,
        COALESCE(endpoint.public,false)::boolean AS public,
        COALESCE(endpoint.dns_state,'unmanaged')::text AS dns_state,
        COALESCE(run.id,'')::text AS run_id,
        COALESCE(run.run_number,0)::bigint AS run_number,
        COALESCE(run.state,'')::text AS publication_state,
        run.publisher_expires_at,
        run.certificate_expires_at,
        COALESCE(run.healthy,false)::boolean AS healthy,
        run.ready_at
    FROM resources resource
    LEFT JOIN control.services service ON service.id=resource.service_id
    LEFT JOIN control.service_endpoints endpoint ON endpoint.service_id=service.id AND endpoint.hostname=service.certificate_hostname AND endpoint.retired_at IS NULL
    LEFT JOIN control.service_runs run ON run.service_id=resource.service_id AND run.closed_at IS NULL
), keyed AS (
    SELECT *,(deployment||'/'||service||'/'||encode(convert_to(worktree_key,'UTF8'),'hex')||'/'||run_id)::text AS cursor_key FROM publications
)
SELECT * FROM keyed WHERE cursor_key COLLATE "C">sqlc.arg(after_key)::text COLLATE "C"
ORDER BY cursor_key COLLATE "C" LIMIT 101;
