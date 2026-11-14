-- name: InsertService :one
INSERT INTO control.services(id, team_id, name, name_scope, created_by_identity_id, idempotency_key, request_digest, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(name_scope), sqlc.arg(created_by_identity_id),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest), sqlc.arg(now), sqlc.arg(now)) RETURNING *;

-- name: LockService :one
SELECT * FROM control.services WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetService :one
SELECT * FROM control.services WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: GetServiceConfiguration :one
-- local normalization uses the logical service key, not its generated saved name.
SELECT COALESCE(local.service,service.name)::text AS service,
    service.configuration_ciphertext,service.storage_key_id,
    (local.service_id IS NOT NULL)::boolean AS local_owned,
    EXISTS(SELECT 1 FROM control.applied_project_services binding
        WHERE binding.service_id=service.id) AS deployment_owned,
    (allocation.service_id IS NOT NULL)::boolean AS allocation_owned,
    COALESCE(allocation.required_temporary_approval,'')::text AS required_temporary_approval
FROM control.services service
LEFT JOIN control.local_project_services local ON local.service_id=service.id
LEFT JOIN control.publisher_namespace_allocations allocation ON allocation.service_id=service.id
WHERE service.id=sqlc.arg(service_id);

-- name: SetServiceConfiguration :execrows
UPDATE control.services
SET configuration_ciphertext=sqlc.narg(ciphertext),storage_key_id=sqlc.narg(storage_key_id)
WHERE id=sqlc.arg(service_id);

-- name: DeleteService :one
-- caller closes all current runs and publishes a tombstone under this service
-- lock in the same transaction.
UPDATE control.services SET enabled = false, deleted_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND team_id = sqlc.arg(team_id) AND deleted_at IS NULL RETURNING *;

-- name: ListServicesForTeam :many
SELECT * FROM control.services
WHERE team_id = sqlc.arg(team_id) AND deleted_at IS NULL AND id > sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: SelectServiceForPublisher :one
-- current permission covers the selected service using the original grant.
SELECT s.* FROM control.services s
WHERE s.id = sqlc.arg(service_id)
AND EXISTS(SELECT 1 FROM control.publisher_service_permission(
    sqlc.arg(publisher_identity_id)::text,sqlc.arg(publisher_grant_id)::text,s.id,sqlc.arg(now)));

-- name: ListTeamNamespaceLabels :many
-- invitations and quarantined memberships still own their reserved namespaces.
SELECT COALESCE(member.managed_label,'')::text AS managed_label,reservation.member_slug
FROM control.member_slug_reservations reservation
LEFT JOIN control.team_memberships member ON member.slug_reservation_id=reservation.id
WHERE reservation.team_id=sqlc.arg(team_id) AND reservation.state<>'released';

-- name: InsertServiceGrant :one
INSERT INTO control.visitor_grants(id, service_id, team_id, kind, identity_id, invitation_id,
    created_by_identity_id, idempotency_key, request_digest, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(service_id), sqlc.arg(team_id), sqlc.arg(kind),
    sqlc.narg(identity_id), sqlc.narg(invitation_id), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(now), sqlc.narg(expires_at)) RETURNING *;

-- name: RevokeServiceGrant :execrows
UPDATE control.visitor_grants SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND service_id = sqlc.arg(service_id) AND revoked_at IS NULL;

-- name: ListServiceGrants :many
SELECT * FROM control.visitor_grants WHERE service_id = sqlc.arg(service_id)
AND id COLLATE "C" > sqlc.arg(after_id)
ORDER BY id COLLATE "C" LIMIT 101;

-- name: InsertServiceInvitation :one
INSERT INTO control.service_invitations(id, service_id, team_id, normalized_email,
    token_digest, created_by_identity_id, idempotency_key, request_digest, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(service_id), sqlc.arg(team_id), sqlc.arg(normalized_email),
    sqlc.arg(token_digest), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(now), sqlc.arg(expires_at)) RETURNING *;

-- name: AcceptServiceInvitation :one
-- verified_actor_email comes only from the consumed configured-issuer assertion;
-- control sessions retain their stored verified email check.
UPDATE control.service_invitations invitation
SET accepted_identity_id = sqlc.arg(identity_id), accepted_at = sqlc.arg(now)
FROM control.services service, control.identities person
WHERE invitation.id=sqlc.arg(id) AND invitation.service_id=sqlc.arg(service_id)
    AND invitation.token_digest = sqlc.arg(token_digest) AND invitation.revoked_at IS NULL
    AND invitation.accepted_at IS NULL AND invitation.expires_at > sqlc.arg(now)
    AND service.id = invitation.service_id AND service.team_id = invitation.team_id
    AND service.enabled AND service.deleted_at IS NULL
    AND person.id = sqlc.arg(identity_id) AND person.disabled_at IS NULL
    AND (sqlc.narg(verified_actor_email)::text=invitation.normalized_email
        OR (sqlc.narg(verified_actor_email)::text IS NULL AND person.email_verified AND person.normalized_email = invitation.normalized_email))
RETURNING invitation.*;

-- name: RevokeServiceInvitation :execrows
UPDATE control.service_invitations SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND service_id = sqlc.arg(service_id) AND revoked_at IS NULL;

-- name: RevokeServiceInvitationGrant :execrows
-- caller revokes invitation and accepted grant in the same transaction.
UPDATE control.visitor_grants SET revoked_at = sqlc.arg(now)
WHERE invitation_id = sqlc.arg(invitation_id) AND service_id = sqlc.arg(service_id)
    AND revoked_at IS NULL;

-- name: ListServiceInvitations :many
SELECT * FROM control.service_invitations
WHERE service_id = sqlc.arg(service_id) AND id COLLATE "C" > sqlc.arg(after_id)
ORDER BY id COLLATE "C" LIMIT 101;

-- name: FindServiceInvitationRequest :one
-- the caller rechecks current management before recovering metadata, never secrets.
SELECT * FROM control.service_invitations
WHERE created_by_identity_id = sqlc.arg(created_by_identity_id)
AND idempotency_key = sqlc.arg(idempotency_key) FOR UPDATE;

-- name: ListAvailableServices :many
-- visitor inventory includes authorized saved services while the publisher is
-- offline. two live slots are required for the first ready transition; after
-- that, one surviving slot keeps a ready run available during replacement.
-- do not include target addresses or credentials.
SELECT s.id, s.team_id, s.name, s.created_at, s.protocol,s.tls_metadata,s.publisher_pool,s.trust_revision,
    s.certificate_hostname,s.service_port,s.public,r.id AS service_run_id, r.run_number
FROM control.services s
JOIN control.teams t ON t.id = s.team_id AND t.deleted_at IS NULL
JOIN control.identities i ON i.id = sqlc.arg(identity_id) AND i.disabled_at IS NULL
LEFT JOIN control.service_runs r ON r.service_id=s.id AND r.id=(SELECT candidate.id
    FROM control.service_runs candidate WHERE candidate.service_id=s.id
    AND candidate.state='ready' AND candidate.healthy AND candidate.closed_at IS NULL AND candidate.publisher_expires_at>sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.publisher_service_permission(candidate.publisher_identity_id,candidate.publisher_grant_id,s.id,sqlc.arg(now)))
    AND EXISTS (SELECT 1 FROM control.publisher_identity_keys signing JOIN control.publisher_grants pg ON pg.id=candidate.publisher_grant_id
        WHERE signing.id=candidate.publisher_key_id AND signing.publisher_identity_id=candidate.publisher_identity_id
        AND (pg.kind='service' OR signing.retired_at IS NULL))
    AND EXISTS (SELECT 1 FROM control.service_connection_slots slot
        JOIN control.relay_leases lease ON lease.relay_id = slot.relay_id
          AND lease.relay_run_id = slot.relay_run_id AND lease.relay_lease_revision = slot.relay_lease_revision
          AND lease.relay_service_id = slot.relay_service_id
          AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining
         WHERE slot.service_run_id = candidate.id AND slot.state = 'ready' AND slot.session_open)
    ORDER BY candidate.run_number DESC LIMIT 1)
WHERE s.deleted_at IS NULL AND s.enabled AND s.id > sqlc.arg(after_id)
    AND control.company_subject_session_authorized(s.team_id,i.id,sqlc.arg(control_session_id)::text,sqlc.arg(now))
    AND EXISTS(SELECT 1 FROM control.visitor_identity_permission(
        'service',s.id,i.id,sqlc.arg(control_session_id)::text,'',sqlc.arg(now)))
ORDER BY s.id LIMIT 101;

-- name: PrepareServiceRun :one
-- caller locks the service, checks the live publisher grant and enrolled key,
-- allocates one run number and captures its managed certificate plan.
-- a retry with the same idempotency key returns the same prepared row.
-- endpoint retirement does not revoke the saved connector identity. capture
-- retained provenance only for this exact service, hostname and domain.
INSERT INTO control.service_runs(preferred_regions, traffic_limits, id, service_id, team_id, run_number,
    publisher_identity_id, publisher_grant_id, publisher_key_id, idempotency_key,
    request_digest, preparation_expires_at, assignment_seed_ciphertext,
    assignment_seed_storage_key_id, certificate_cache_key,certificate_scope,certificate_identifiers,certificate_domain_id,certificate_hostname,certificate_namespace,require_post_quantum,state, created_at, publisher_expires_at)
VALUES (sqlc.arg(preferred_regions), convert_from(sqlc.arg(traffic_limits)::bytea,'UTF8')::jsonb, sqlc.arg(id), sqlc.arg(service_id), sqlc.arg(team_id), sqlc.arg(run_number),
    sqlc.arg(publisher_identity_id), sqlc.arg(publisher_grant_id), sqlc.arg(publisher_key_id),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest),
    sqlc.arg(preparation_expires_at), sqlc.arg(assignment_seed_ciphertext),
    sqlc.arg(assignment_seed_storage_key_id),sqlc.arg(certificate_cache_key),sqlc.arg(certificate_scope),sqlc.arg(certificate_identifiers),sqlc.narg(certificate_domain_id),sqlc.arg(certificate_hostname),
    (SELECT endpoint.namespace FROM control.service_endpoints endpoint
        WHERE endpoint.service_id=sqlc.arg(service_id) AND endpoint.hostname=sqlc.arg(certificate_hostname)
        AND endpoint.domain_id=sqlc.narg(certificate_domain_id)),
    sqlc.arg(require_post_quantum), 'prepared', sqlc.arg(now), sqlc.arg(publisher_expires_at)) RETURNING *;

-- name: LockServiceRun :one
SELECT * FROM control.service_runs
WHERE id = sqlc.arg(id) AND service_id = sqlc.arg(service_id) FOR UPDATE;

-- name: ClosedServiceRuns :many
-- only an exact stored terminal tuple proves a finite traffic budget can retire.
SELECT run.service_id,run.id,run.run_number
FROM control.service_runs run
WHERE run.id=ANY(sqlc.arg(run_ids)::text[])
    AND run.state='closed' AND run.closed_at IS NOT NULL ORDER BY run.id;

-- name: GetServiceRunPublisherIdentity :one
-- starting a run requires its exact authenticated publisher, grant and key.
SELECT publisher_key.public_key FROM control.service_runs run
JOIN control.publisher_identity_keys publisher_key
    ON publisher_key.id = run.publisher_key_id
    AND publisher_key.publisher_identity_id = run.publisher_identity_id
JOIN control.publisher_identities publisher ON publisher.id = run.publisher_identity_id
    AND publisher.revoked_at IS NULL AND publisher.team_id = run.team_id
    AND control.active_publisher(publisher.id,sqlc.arg(now))
JOIN control.publisher_grants grant_record ON grant_record.id = run.publisher_grant_id
    AND grant_record.publisher_identity_id = publisher.id
    AND grant_record.revoked_at IS NULL
    AND (grant_record.expires_at IS NULL OR grant_record.expires_at > sqlc.arg(now))
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.service_id = sqlc.arg(service_id)
    AND run.publisher_identity_id = sqlc.arg(publisher_identity_id)
    AND run.publisher_grant_id = sqlc.arg(publisher_grant_id)
    AND run.publisher_key_id = sqlc.arg(publisher_key_id)
    AND run.closed_at IS NULL
    AND (grant_record.kind='service' OR publisher_key.retired_at IS NULL)
    AND EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,run.service_id,sqlc.arg(now)));

-- name: AdvanceServiceRunNumber :one
UPDATE control.services SET next_run_number = next_run_number + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND enabled AND deleted_at IS NULL RETURNING (next_run_number - 1)::bigint AS run_number;

-- name: ReadyServiceRun :one
UPDATE control.service_runs run SET state = 'ready', ready_at = COALESCE(run.ready_at, sqlc.arg(now))
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.service_id = sqlc.arg(service_id)
    AND run.state = 'starting' AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND run.healthy
    AND run.certificate_expires_at>sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.service_connection_slots slot
        JOIN control.relay_leases lease ON lease.relay_id = slot.relay_id
          AND lease.relay_run_id = slot.relay_run_id AND lease.relay_lease_revision = slot.relay_lease_revision
          AND lease.relay_service_id = slot.relay_service_id
          AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining
        WHERE slot.service_run_id = run.id AND slot.state = 'ready' AND slot.session_open
        GROUP BY slot.service_run_id
        HAVING count(*) >= CASE WHEN run.ready_at IS NULL THEN 2 ELSE 1 END)
RETURNING run.*;

-- name: DemoteServiceRun :execrows
UPDATE control.service_runs SET state = 'starting'
WHERE id = sqlc.arg(id) AND service_id = sqlc.arg(service_id)
    AND run_number = sqlc.arg(run_number) AND state = 'ready' AND closed_at IS NULL;

-- name: RenewServiceRun :one
UPDATE control.service_runs run SET publisher_expires_at = LEAST(sqlc.arg(publisher_expires_at),service.expires_at,publisher_grant.expires_at)
FROM control.services service, control.publisher_grants publisher_grant, control.publisher_identities publisher
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.service_id = sqlc.arg(service_id)
    AND run.run_token_digest = sqlc.arg(run_token_digest)
    AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND sqlc.arg(publisher_expires_at)::timestamptz > sqlc.arg(now)
    AND service.id = run.service_id AND service.enabled AND service.deleted_at IS NULL
    AND (service.expires_at IS NULL OR service.expires_at>sqlc.arg(now))
    AND publisher_grant.id = run.publisher_grant_id AND publisher_grant.publisher_identity_id=run.publisher_identity_id
    AND publisher_grant.revoked_at IS NULL
    AND (publisher_grant.expires_at IS NULL OR publisher_grant.expires_at > sqlc.arg(now))
    AND publisher.id = run.publisher_identity_id AND publisher.team_id = service.team_id
    AND publisher.revoked_at IS NULL
    AND control.active_publisher(publisher.id,sqlc.arg(now))
    AND EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,run.service_id,sqlc.arg(now)))
    AND EXISTS(SELECT 1 FROM control.publisher_identity_keys signing WHERE signing.id=run.publisher_key_id
        AND signing.publisher_identity_id=run.publisher_identity_id AND (publisher_grant.kind='service' OR signing.retired_at IS NULL))
RETURNING run.*;

-- name: CloseServiceRun :execrows
UPDATE control.service_runs SET state = 'closed', closed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND service_id = sqlc.arg(service_id)
    AND run_number = sqlc.arg(run_number) AND closed_at IS NULL;

-- name: InsertServiceConnectionSlot :one
INSERT INTO control.service_connection_slots(publisher_connection_id, service_run_id,
    service_id, run_number, connection_slot, connection_assignment_revision,
    relay_service_id, relay_address, tls_server_name, credential_digest, credential_expires_at, state,assigned_at)
VALUES (sqlc.arg(publisher_connection_id), sqlc.arg(service_run_id), sqlc.arg(service_id),
    sqlc.arg(run_number), sqlc.arg(connection_slot), sqlc.arg(connection_assignment_revision),
    sqlc.arg(relay_service_id), sqlc.arg(relay_address), sqlc.arg(tls_server_name),
    sqlc.arg(credential_digest), sqlc.arg(credential_expires_at), 'assigned',sqlc.arg(assigned_at)) RETURNING *;

-- name: ListServiceConnectionSlots :many
SELECT * FROM control.service_connection_slots WHERE service_run_id = sqlc.arg(service_run_id)
ORDER BY connection_slot;

-- name: ListServiceConnectionSlotsNeedingReplacement :many
-- replace expired never-ready claims even with a live relay lease.
-- ready slots retain ownership and streams while their matching lease is live.
SELECT slot.* FROM control.service_connection_slots slot
WHERE slot.service_run_id = sqlc.arg(service_run_id)
    AND (slot.state = 'closed' OR slot.state IN ('assigned', 'connected') AND slot.credential_expires_at <= sqlc.arg(now)
        OR slot.state IN ('connected', 'ready') AND NOT EXISTS (
            SELECT 1 FROM control.relay_leases lease
            WHERE lease.relay_id = slot.relay_id AND lease.relay_run_id = slot.relay_run_id
              AND lease.relay_lease_revision = slot.relay_lease_revision
              AND lease.relay_service_id = slot.relay_service_id
              AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining))
ORDER BY slot.connection_slot;

-- name: ExpireServiceConnectionSlot :execrows
UPDATE control.service_connection_slots slot SET state = 'closed', relay_id = NULL,
    relay_run_id = NULL, relay_lease_revision = NULL
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.service_run_id = sqlc.arg(service_run_id)
    AND slot.state IN ('connected', 'ready')
    AND (slot.state = 'connected' AND slot.credential_expires_at <= sqlc.arg(now)
        OR NOT EXISTS (SELECT 1 FROM control.relay_leases lease
            WHERE lease.relay_id = slot.relay_id AND lease.relay_run_id = slot.relay_run_id
              AND lease.relay_lease_revision = slot.relay_lease_revision
              AND lease.relay_service_id = slot.relay_service_id
              AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining));

-- name: DeleteServiceConnectionSlot :execrows
DELETE FROM control.service_connection_slots WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND service_run_id = sqlc.arg(service_run_id)
    AND (state = 'closed' OR state = 'assigned' AND credential_expires_at <= sqlc.arg(now));

-- name: ClaimServiceConnectionSlot :one
UPDATE control.service_connection_slots slot
SET relay_id = sqlc.arg(relay_id), relay_run_id = sqlc.arg(relay_run_id),
    relay_lease_revision = sqlc.arg(relay_lease_revision), state = 'connected'
FROM control.service_runs r, control.relay_leases l
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.credential_digest = sqlc.arg(credential_digest)
    AND slot.connection_assignment_revision = sqlc.arg(connection_assignment_revision)
    -- recover only the exact committed claim while it is still connected.
    -- the relay fences local handshakes through disconnect; no other process
    -- can adopt the slot and readiness cannot be reset by a claim replay.
    AND (slot.state = 'assigned' OR slot.state = 'connected'
        AND slot.relay_id = sqlc.arg(relay_id) AND slot.relay_run_id = sqlc.arg(relay_run_id)
        AND slot.relay_lease_revision = sqlc.arg(relay_lease_revision))
    AND slot.credential_expires_at > sqlc.arg(now)
    AND r.id = slot.service_run_id AND r.closed_at IS NULL AND r.publisher_expires_at > sqlc.arg(now)
    AND l.relay_id = sqlc.arg(relay_id) AND l.relay_run_id = sqlc.arg(relay_run_id)
    AND l.relay_lease_revision = sqlc.arg(relay_lease_revision)
    AND l.relay_service_id = slot.relay_service_id AND l.lease_expires_at > sqlc.arg(now) AND NOT l.draining
RETURNING slot.*;

-- name: ReadyServiceConnectionSlot :one
UPDATE control.service_connection_slots slot SET state = 'ready'
FROM control.service_runs run, control.relay_leases lease
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.connection_assignment_revision = sqlc.arg(connection_assignment_revision)
    AND slot.state = 'connected' AND slot.service_run_id = run.id
    AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND lease.relay_id = slot.relay_id AND lease.relay_run_id = slot.relay_run_id
    AND lease.relay_lease_revision = slot.relay_lease_revision
    AND lease.relay_service_id = slot.relay_service_id
    AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining
RETURNING slot.*;

-- name: DisconnectServiceConnectionSlot :one
UPDATE control.service_connection_slots slot
SET state = 'closed', relay_id = NULL, relay_run_id = NULL, relay_lease_revision = NULL
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.service_run_id = sqlc.arg(service_run_id) AND slot.run_number = sqlc.arg(run_number)
    AND slot.connection_assignment_revision = sqlc.arg(connection_assignment_revision)
    AND slot.relay_id = sqlc.arg(relay_id) AND slot.relay_run_id = sqlc.arg(relay_run_id)
    AND slot.relay_lease_revision = sqlc.arg(relay_lease_revision)
    AND slot.state IN ('connected', 'ready')
RETURNING slot.*;

-- name: GetServiceSource :one
SELECT l.project_key,l.source_fingerprint,l.service,l.worktree_key
FROM control.local_project_services l WHERE l.service_id=sqlc.arg(service_id)
UNION ALL
SELECT a.project_key,p.source_fingerprint,a.service,s.placement_worktree_key AS worktree_key
FROM control.applied_project_services a
JOIN control.applied_projects p ON p.team_id=a.team_id AND p.project_key=a.project_key
JOIN control.services s ON s.id=a.service_id
WHERE a.service_id=sqlc.arg(service_id)
LIMIT 1;

-- name: LockPendingServiceInvitation :one
SELECT * FROM control.service_invitations
WHERE id=sqlc.arg(id) AND service_id=sqlc.arg(service_id)
AND revoked_at IS NULL AND accepted_at IS NULL AND expires_at>sqlc.arg(now)
FOR UPDATE;
