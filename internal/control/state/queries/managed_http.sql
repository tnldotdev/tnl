-- name: ManagedHTTPBrowserEndpoint :one
SELECT s.team_id,s.certificate_hostname,s.service_port,
    ARRAY(SELECT run.id FROM control.private_service_runs run
        WHERE run.private_service_id=s.id AND run.state='ready' AND run.healthy
        AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now)
        AND run.certificate_expires_at>sqlc.arg(now) ORDER BY run.run_number LIMIT 256)::text[] AS run_ids
FROM control.private_services s
WHERE s.id=sqlc.arg(private_service_id) AND s.protocol='http' AND s.enabled AND s.deleted_at IS NULL;

-- name: InsertManagedHTTPBrowserLogin :exec
INSERT INTO control.managed_http_browser_logins(state_digest,binding_digest,private_service_id,run_ids,return_path,nonce,verifier_ciphertext,storage_key_id,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: ConsumeManagedHTTPBrowserLogin :one
UPDATE control.managed_http_browser_logins SET consumed_at=sqlc.arg(now)
WHERE state_digest=sqlc.arg(state_digest) AND binding_digest=sqlc.arg(binding_digest)
AND consumed_at IS NULL AND expires_at>sqlc.arg(now)
RETURNING *;

-- name: InsertManagedHTTPBrowserSession :exec
INSERT INTO control.managed_http_browser_sessions(handoff_digest,private_service_id,run_ids,control_session_id,return_path,handoff_expires_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: RedeemManagedHTTPBrowserSession :one
UPDATE control.managed_http_browser_sessions SET cookie_digest=sqlc.arg(cookie_digest)
WHERE handoff_digest=sqlc.arg(handoff_digest) AND private_service_id=sqlc.arg(private_service_id)
AND sqlc.arg(private_run_id)::text=ANY(run_ids) AND cookie_digest IS NULL AND revoked_at IS NULL
AND handoff_expires_at>sqlc.arg(now) AND expires_at>sqlc.arg(now)
RETURNING return_path,expires_at;

-- name: ManagedHTTPBrowserPermission :one
SELECT session.identity_id,session.id AS control_session_id,person.display_name,
    LEAST(browser.expires_at,session.refresh_expires_at)::timestamptz AS expires_at
FROM control.managed_http_browser_sessions browser
JOIN control.control_sessions session ON session.id=browser.control_session_id AND session.revoked_at IS NULL
JOIN control.identities person ON person.id=session.identity_id AND person.disabled_at IS NULL
WHERE browser.private_service_id=sqlc.arg(private_service_id) AND browser.cookie_digest=sqlc.arg(cookie_digest)
AND sqlc.arg(private_run_id)::text=ANY(browser.run_ids) AND browser.revoked_at IS NULL
AND browser.expires_at>sqlc.arg(now) AND session.refresh_expires_at>sqlc.arg(now);

-- name: RevokeManagedHTTPBrowserSession :exec
UPDATE control.managed_http_browser_sessions SET revoked_at=sqlc.arg(now)
WHERE private_service_id=sqlc.arg(private_service_id) AND cookie_digest=sqlc.arg(cookie_digest)
AND sqlc.arg(private_run_id)::text=ANY(run_ids);

-- name: InsertManagedHTTPGrant :exec
INSERT INTO control.managed_http_grants(id,private_service_id,kind,secret_digest,created_by_identity_id,control_session_id,expires_at)
VALUES($1,$2,$3,$4,$5,sqlc.narg(control_session_id),$6);

-- name: RevokeManagedHTTPGrant :execrows
UPDATE control.managed_http_grants SET revoked_at=COALESCE(revoked_at,sqlc.arg(now))
WHERE id=sqlc.arg(id) AND private_service_id=sqlc.arg(private_service_id);

-- name: ListManagedHTTPGrants :many
SELECT id,kind,expires_at,revoked_at FROM control.managed_http_grants
WHERE private_service_id=sqlc.arg(private_service_id) ORDER BY id;

-- name: ManagedHTTPGrantPermission :one
SELECT id,created_by_identity_id,control_session_id,expires_at FROM control.managed_http_grants
WHERE private_service_id=sqlc.arg(private_service_id) AND kind=sqlc.arg(kind)
AND secret_digest=sqlc.arg(secret_digest) AND revoked_at IS NULL AND expires_at>sqlc.arg(now);

-- name: ManagedHTTPDirectBinding :one
SELECT (v.promoted_at IS NOT NULL)::boolean AS admitted,LEAST(sqlc.arg(now)::timestamptz+interval '2 minutes',
    run.publisher_expires_at,run.certificate_expires_at,g.expires_at,ingress.lease_expires_at,
    (SELECT max(relay.lease_expires_at) FROM control.private_service_connection_slots slot
     JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
     AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
     WHERE slot.private_run_id=run.id AND slot.state='ready' AND slot.session_open
     AND relay.lease_expires_at>sqlc.arg(now) AND NOT relay.draining))::timestamptz AS valid_until
FROM control.direct_service_visitors v
JOIN control.private_services service ON service.id=v.private_service_id AND service.public AND service.enabled
    AND service.deleted_at IS NULL AND service.protocol='http' AND service.service_port=v.destination_port
JOIN control.private_service_runs run ON run.id=v.private_run_id AND run.private_service_id=service.id
    AND run.run_number=v.run_number AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
    AND run.publisher_expires_at>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
JOIN control.ingress_leases ingress ON ingress.ingress_id=v.ingress_id AND ingress.ingress_run_id=v.ingress_run_id
    AND ingress.ingress_lease_revision=v.ingress_lease_revision AND ingress.lease_expires_at>sqlc.arg(now)
JOIN control.publisher_grants g ON g.id=run.publisher_grant_id AND g.kind='private_service'
    AND g.private_service_id=service.id AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>sqlc.arg(now))
JOIN control.publisher_identities publisher ON publisher.id=g.publisher_identity_id AND publisher.id=run.publisher_identity_id AND publisher.revoked_at IS NULL
WHERE v.visitor_connection_id=sqlc.arg(visitor_connection_id) AND v.private_service_id=sqlc.arg(private_service_id)
AND v.private_run_id=sqlc.arg(private_run_id) AND v.run_number=sqlc.arg(run_number)
AND v.source_ip=sqlc.arg(source_ip) AND v.destination_port=sqlc.arg(destination_port)
AND v.closed_at IS NULL AND v.valid_until>sqlc.arg(now)
AND EXISTS(SELECT 1 FROM control.private_service_connection_slots slot JOIN control.relay_leases relay
    ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
    AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
    WHERE slot.private_run_id=run.id AND slot.state='ready' AND slot.session_open
    AND relay.lease_expires_at>sqlc.arg(now) AND NOT relay.draining);

-- name: BindManagedHTTPDirectCredential :exec
UPDATE control.direct_service_visitors SET http_credential_kind=sqlc.arg(kind),http_credential_digest=sqlc.arg(digest),
    identity_id=NULL,device_id=NULL,workload_session_id=NULL,certificate_digest=NULL,valid_until=sqlc.arg(valid_until)
WHERE visitor_connection_id=sqlc.arg(visitor_connection_id);

-- name: ManagedHTTPDirectCredential :one
SELECT http_credential_kind,http_credential_digest,destination_port,identity_id,device_id,workload_session_id FROM control.direct_service_visitors
WHERE visitor_connection_id=$1;

-- name: ManagedHTTPAppliedConfiguration :one
SELECT project.team_id,project.project_key,project.configuration_ciphertext,project.storage_key_id,service.service FROM control.applied_project_services service
JOIN control.applied_projects project ON project.team_id=service.team_id AND project.project_key=service.project_key
WHERE service.private_service_id=$1;

-- name: CleanupManagedHTTPLogins :exec
DELETE FROM control.managed_http_browser_logins stored WHERE stored.state_digest IN
    (SELECT expired.state_digest FROM control.managed_http_browser_logins expired WHERE expired.expires_at<=sqlc.arg(now) LIMIT 100);

-- name: CleanupManagedHTTPSessions :exec
DELETE FROM control.managed_http_browser_sessions stored WHERE stored.handoff_digest IN
    (SELECT expired.handoff_digest FROM control.managed_http_browser_sessions expired WHERE expired.expires_at<=sqlc.arg(now) OR expired.revoked_at IS NOT NULL LIMIT 100);
