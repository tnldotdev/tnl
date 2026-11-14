-- name: GetAppliedProject :one
SELECT * FROM control.applied_projects WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key);

-- name: ListProjectPublications :many
-- one row per open publication, or one row for an idle/unrealized resource.
-- worktree bytes are encoded so separators cannot alias another cursor key.
WITH resources AS (
    SELECT applied.service,COALESCE(deployment.name,'local')::text AS deployment,''::text AS worktree_key,applied.service_id,applied.public_url_id
    FROM control.applied_project_services applied
    LEFT JOIN control.deployments deployment ON deployment.id=applied.deployment_id
    WHERE applied.team_id=sqlc.arg(team_id) AND applied.project_key=sqlc.arg(project_key)
       AND (applied.deployment_id IS NOT NULL OR applied.service_id IS NOT NULL OR applied.public_url_id IS NOT NULL OR NOT EXISTS (
          SELECT 1 FROM control.local_project_services local
          WHERE local.team_id=applied.team_id AND local.project_key=applied.project_key AND local.service=applied.service))
    UNION ALL
    SELECT local.service,'local'::text AS deployment,local.worktree_key,local.service_id,local.public_url_id
    FROM control.local_project_services local
    WHERE local.team_id=sqlc.arg(team_id) AND local.project_key=sqlc.arg(project_key)
), publications AS (
    SELECT resource.service,resource.deployment,resource.worktree_key,resource.service_id,resource.public_url_id,
        COALESCE(service.certificate_hostname,url.canonical_hostname,'')::text AS hostname,
        COALESCE(service.service_port,CASE WHEN url.id IS NOT NULL THEN 443 ELSE 0 END)::integer AS port,
        COALESCE(service.enabled AND service.deleted_at IS NULL,url.lifecycle_state='enabled',false)::boolean AS enabled,
        COALESCE(url.dns_state,'')::text AS dns_state,
        COALESCE(public_run.id,private_run.id,'')::text AS run_id,
        COALESCE(public_run.publish_run_number,private_run.run_number,0)::bigint AS run_number,
        COALESCE(public_run.state,private_run.state,'')::text AS publication_state,
        COALESCE(public_run.publisher_expires_at,private_run.publisher_expires_at) AS publisher_expires_at,
        COALESCE(public_run.certificate_not_after,private_run.certificate_expires_at) AS certificate_expires_at,
        COALESCE(private_run.healthy,true)::boolean AS healthy,
        COALESCE(public_run.ready_at,private_run.ready_at) AS ready_at
    FROM resources resource
    LEFT JOIN control.services service ON service.id=resource.service_id
    LEFT JOIN control.public_urls url ON url.id=resource.public_url_id
    LEFT JOIN control.publish_runs public_run ON public_run.public_url_id=resource.public_url_id AND public_run.closed_at IS NULL
    LEFT JOIN control.service_runs private_run ON private_run.service_id=resource.service_id AND private_run.closed_at IS NULL
), keyed AS (
    SELECT *,(deployment||'/'||service||'/'||encode(convert_to(worktree_key,'UTF8'),'hex')||'/'||run_id)::text AS cursor_key FROM publications
)
SELECT * FROM keyed WHERE cursor_key COLLATE "C">sqlc.arg(after_key)::text COLLATE "C"
ORDER BY cursor_key COLLATE "C" LIMIT 101;
