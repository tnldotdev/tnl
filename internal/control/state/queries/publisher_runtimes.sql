-- name: GetPublisherRuntime :one
SELECT * FROM control.publisher_runtimes WHERE publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: StartPublisherRuntime :one
INSERT INTO control.publisher_runtimes(publisher_identity_id,team_id,key_id,scope_id,process_run_id,epoch,address,address_family,started_at,observed_at,last_seen_at,lease_expires_at,deployment_report,deployment_group_id,deployment_first_observed_at)
VALUES(sqlc.arg(publisher_identity_id),sqlc.arg(team_id),sqlc.arg(key_id),sqlc.arg(scope_id),sqlc.arg(process_run_id),sqlc.arg(epoch),sqlc.narg(address),sqlc.arg(address_family),sqlc.arg(now),sqlc.arg(now),sqlc.arg(now),sqlc.arg(lease_expires_at),convert_from(sqlc.narg(deployment_report)::bytea,'UTF8')::jsonb,sqlc.narg(deployment_group_id),sqlc.narg(deployment_first_observed_at))
ON CONFLICT(publisher_identity_id) DO UPDATE SET key_id=EXCLUDED.key_id,scope_id=EXCLUDED.scope_id,process_run_id=EXCLUDED.process_run_id,epoch=EXCLUDED.epoch,address=EXCLUDED.address,address_family=EXCLUDED.address_family,started_at=EXCLUDED.started_at,observed_at=EXCLUDED.observed_at,last_seen_at=EXCLUDED.last_seen_at,lease_expires_at=EXCLUDED.lease_expires_at,stopped_at=NULL,deployment_report=EXCLUDED.deployment_report,deployment_group_id=EXCLUDED.deployment_group_id,deployment_first_observed_at=COALESCE(control.publisher_runtimes.deployment_first_observed_at,EXCLUDED.deployment_first_observed_at)
RETURNING *;

-- name: RenewPublisherRuntime :one
UPDATE control.publisher_runtimes SET address=sqlc.narg(address),address_family=sqlc.arg(address_family),observed_at=sqlc.arg(now),last_seen_at=sqlc.arg(now),lease_expires_at=sqlc.arg(lease_expires_at)
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id) AND process_run_id=sqlc.arg(process_run_id) AND epoch=sqlc.arg(epoch) AND stopped_at IS NULL
RETURNING *;

-- name: StopPublisherRuntime :one
UPDATE control.publisher_runtimes SET stopped_at=COALESCE(stopped_at,sqlc.arg(now)),lease_expires_at=LEAST(lease_expires_at,sqlc.arg(now)),last_seen_at=CASE WHEN stopped_at IS NULL THEN sqlc.arg(now) ELSE last_seen_at END
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id) AND process_run_id=sqlc.arg(process_run_id) AND epoch=sqlc.arg(epoch)
RETURNING *;

-- name: PublisherRuntimeActive :one
SELECT EXISTS(SELECT 1 FROM control.publisher_runtimes r
JOIN control.publisher_identities p ON p.id=r.publisher_identity_id
JOIN control.publisher_identity_keys k ON k.id=r.key_id AND k.publisher_identity_id=p.id
JOIN control.teams t ON t.id=r.team_id AND t.id=p.team_id
WHERE r.publisher_identity_id=sqlc.arg(publisher_identity_id) AND r.process_run_id=sqlc.arg(process_run_id) AND r.epoch=sqlc.arg(epoch)
AND r.stopped_at IS NULL AND r.lease_expires_at>sqlc.arg(now)
AND control.active_publisher(p.id,sqlc.arg(now)) AND k.retired_at IS NULL AND t.deleted_at IS NULL
AND (EXISTS(SELECT 1 FROM control.publisher_group_members m JOIN control.project_publisher_groups g ON g.id=m.group_id WHERE m.publisher_identity_id=p.id AND m.key_id=k.id AND g.team_id=p.team_id AND g.id=r.scope_id AND g.deleted_at IS NULL)
 OR EXISTS(SELECT 1 FROM control.publisher_grants g
 LEFT JOIN control.public_urls u ON u.id=g.public_url_id
 LEFT JOIN control.services s ON s.id=g.service_id
 LEFT JOIN control.domains d ON d.id=COALESCE(g.domain_id,u.domain_id,s.domain_id)
 WHERE g.id=r.scope_id AND g.publisher_identity_id=p.id AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>sqlc.arg(now))
 AND ((g.kind='service' AND s.team_id=p.team_id AND s.enabled AND s.deleted_at IS NULL
       AND (s.domain_id IS NULL OR d.state='ready' AND d.released_at IS NULL AND (d.kind='managed' OR d.team_id=p.team_id)))
   OR (d.state='ready' AND d.released_at IS NULL AND (d.kind='managed' OR d.team_id=p.team_id)
       AND (g.kind='namespace' OR g.kind='saved_public_url' AND u.team_id=p.team_id AND u.lifecycle_state='enabled' AND NOT u.ephemeral
            AND u.purpose IN ('app','alias','demo','oauth','webhooks')))))))::boolean;
