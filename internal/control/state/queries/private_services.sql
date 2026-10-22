-- name: InsertPrivateService :one
INSERT INTO control.private_services(id, team_id, name, name_scope, created_by_identity_id, idempotency_key, request_digest, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(name_scope), sqlc.arg(created_by_identity_id),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest), sqlc.arg(now), sqlc.arg(now)) RETURNING *;

-- name: LockPrivateService :one
SELECT * FROM control.private_services WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetPrivateService :one
SELECT * FROM control.private_services WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: DeletePrivateService :one
-- caller closes all current runs and publishes a tombstone under this service
-- lock in the same transaction.
UPDATE control.private_services SET enabled = false, deleted_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND team_id = sqlc.arg(team_id) AND deleted_at IS NULL RETURNING *;

-- name: ListPrivateServicesForTeam :many
SELECT * FROM control.private_services
WHERE team_id = sqlc.arg(team_id) AND deleted_at IS NULL AND id > sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: SelectPrivateServiceForPublisher :one
-- only an exact grant for an active team and service permits publication.
SELECT s.* FROM control.private_services s
JOIN control.teams t ON t.id = s.team_id AND t.deleted_at IS NULL
JOIN control.publisher_identities p ON p.team_id = s.team_id AND p.revoked_at IS NULL
    AND control.active_publisher(p.id,sqlc.arg(now))
JOIN control.publisher_grants g ON g.publisher_identity_id = p.id
    AND g.kind = 'private_service' AND g.private_service_id = s.id
    AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > sqlc.arg(now))
WHERE s.id = sqlc.arg(private_service_id) AND p.id = sqlc.arg(publisher_identity_id)
    AND g.id = sqlc.arg(publisher_grant_id) AND s.enabled AND s.deleted_at IS NULL AND p.kind <> 'guest';

-- name: InsertPrivateServiceGrant :one
INSERT INTO control.private_service_grants(id, private_service_id, team_id, kind, identity_id, invitation_id,
    created_by_identity_id, idempotency_key, request_digest, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(private_service_id), sqlc.arg(team_id), sqlc.arg(kind),
    sqlc.narg(identity_id), sqlc.narg(invitation_id), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(now), sqlc.narg(expires_at)) RETURNING *;

-- name: RevokePrivateServiceGrant :execrows
UPDATE control.private_service_grants SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id) AND revoked_at IS NULL;

-- name: ListPrivateServiceGrants :many
SELECT * FROM control.private_service_grants WHERE private_service_id = sqlc.arg(private_service_id)
AND id COLLATE "C" > sqlc.arg(after_id)
ORDER BY id COLLATE "C" LIMIT 101;

-- name: InsertPrivateServiceInvitation :one
INSERT INTO control.private_service_invitations(id, private_service_id, team_id, normalized_email,
    token_digest, created_by_identity_id, idempotency_key, request_digest, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(private_service_id), sqlc.arg(team_id), sqlc.arg(normalized_email),
    sqlc.arg(token_digest), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(now), sqlc.arg(expires_at)) RETURNING *;

-- name: AcceptPrivateServiceInvitation :one
-- verified_actor_email comes only from the consumed configured-issuer assertion;
-- control sessions retain their stored verified email check.
UPDATE control.private_service_invitations invitation
SET accepted_identity_id = sqlc.arg(identity_id), accepted_at = sqlc.arg(now)
FROM control.private_services service, control.identities person
WHERE invitation.id=sqlc.arg(id) AND invitation.private_service_id=sqlc.arg(private_service_id)
    AND invitation.token_digest = sqlc.arg(token_digest) AND invitation.revoked_at IS NULL
    AND invitation.accepted_at IS NULL AND invitation.expires_at > sqlc.arg(now)
    AND service.id = invitation.private_service_id AND service.team_id = invitation.team_id
    AND service.enabled AND service.deleted_at IS NULL
    AND person.id = sqlc.arg(identity_id) AND person.disabled_at IS NULL
    AND (sqlc.narg(verified_actor_email)::text=invitation.normalized_email
        OR (sqlc.narg(verified_actor_email)::text IS NULL AND person.email_verified AND person.normalized_email = invitation.normalized_email))
RETURNING invitation.*;

-- name: RevokePrivateServiceInvitation :execrows
UPDATE control.private_service_invitations SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id) AND revoked_at IS NULL;

-- name: RevokePrivateServiceInvitationGrant :execrows
-- caller revokes invitation and accepted grant in the same transaction.
UPDATE control.private_service_grants SET revoked_at = sqlc.arg(now)
WHERE invitation_id = sqlc.arg(invitation_id) AND private_service_id = sqlc.arg(private_service_id)
    AND revoked_at IS NULL;

-- name: ListPrivateServiceInvitations :many
SELECT * FROM control.private_service_invitations
WHERE private_service_id = sqlc.arg(private_service_id) AND id COLLATE "C" > sqlc.arg(after_id)
ORDER BY id COLLATE "C" LIMIT 101;

-- name: FindPrivateServiceInvitationRequest :one
-- the caller rechecks current management before recovering metadata, never secrets.
SELECT * FROM control.private_service_invitations
WHERE created_by_identity_id = sqlc.arg(created_by_identity_id)
AND idempotency_key = sqlc.arg(idempotency_key) FOR UPDATE;

-- name: ListAvailablePrivateServices :many
-- visitor inventory includes authorized saved services while the publisher is
-- offline. two live slots are required for the first ready transition; after
-- that, one surviving slot keeps a ready run available during replacement.
-- do not include target addresses or credentials.
SELECT s.id, s.team_id, s.name, s.created_at, s.protocol,s.tls_metadata,s.publisher_pool,s.trust_revision,
    s.certificate_hostname,s.service_port,s.public,r.id AS private_run_id, r.run_number
FROM control.private_services s
JOIN control.teams t ON t.id = s.team_id AND t.deleted_at IS NULL
JOIN control.identities i ON i.id = sqlc.arg(identity_id) AND i.disabled_at IS NULL
LEFT JOIN control.private_service_runs r ON r.private_service_id=s.id AND r.id=(SELECT candidate.id
    FROM control.private_service_runs candidate WHERE candidate.private_service_id=s.id
    AND candidate.state='ready' AND candidate.healthy AND candidate.closed_at IS NULL AND candidate.publisher_expires_at>sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.publisher_grants pg
        JOIN control.publisher_identities p ON p.id = pg.publisher_identity_id
         WHERE pg.id = candidate.publisher_grant_id AND pg.private_service_id = s.id
          AND pg.kind = 'private_service' AND pg.revoked_at IS NULL
          AND (pg.expires_at IS NULL OR pg.expires_at > sqlc.arg(now))
           AND p.team_id = s.team_id AND control.active_publisher(p.id,sqlc.arg(now)))
    AND EXISTS (SELECT 1 FROM control.private_service_connection_slots slot
        JOIN control.relay_leases lease ON lease.relay_id = slot.relay_id
          AND lease.relay_run_id = slot.relay_run_id AND lease.relay_lease_revision = slot.relay_lease_revision
          AND lease.relay_service_id = slot.relay_service_id
          AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining
         WHERE slot.private_run_id = candidate.id AND slot.state = 'ready' AND slot.session_open)
    ORDER BY candidate.run_number DESC LIMIT 1)
WHERE s.deleted_at IS NULL AND s.enabled AND s.id > sqlc.arg(after_id)
    AND control.company_subject_session_authorized(s.team_id,i.id,sqlc.arg(control_session_id)::text,sqlc.arg(now))
    AND (
        EXISTS (SELECT 1 FROM control.private_service_grants g
            LEFT JOIN control.team_memberships m ON m.team_id = s.team_id
                AND m.identity_id = i.id AND control.active_membership(m.id,sqlc.arg(now))
            WHERE g.private_service_id = s.id AND g.revoked_at IS NULL
                 AND (g.expires_at IS NULL OR g.expires_at > sqlc.arg(now))
                 AND (NOT g.auto_owner OR m.role IN ('owner','admin'))
                AND ((g.kind = 'identity' AND g.identity_id = i.id)
                  OR (g.kind = 'team' AND m.id IS NOT NULL)))
    )
ORDER BY s.id LIMIT 101;

-- name: PreparePrivateServiceRun :one
-- caller locks the service, checks the live publisher grant and enrolled key,
-- allocates one run number and captures its managed certificate plan.
-- a retry with the same idempotency key returns the same prepared row.
INSERT INTO control.private_service_runs(id, private_service_id, team_id, run_number,
    publisher_identity_id, publisher_grant_id, publisher_key_id, idempotency_key,
    request_digest, preparation_expires_at, assignment_seed_ciphertext,
    assignment_seed_storage_key_id, certificate_cache_key,certificate_scope,certificate_identifiers,certificate_domain_id,certificate_hostname,service_port,state, created_at, publisher_expires_at)
VALUES (sqlc.arg(id), sqlc.arg(private_service_id), sqlc.arg(team_id), sqlc.arg(run_number),
    sqlc.arg(publisher_identity_id), sqlc.arg(publisher_grant_id), sqlc.arg(publisher_key_id),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest),
    sqlc.arg(preparation_expires_at), sqlc.arg(assignment_seed_ciphertext),
    sqlc.arg(assignment_seed_storage_key_id),sqlc.arg(certificate_cache_key),sqlc.arg(certificate_scope),sqlc.arg(certificate_identifiers),sqlc.narg(certificate_domain_id),sqlc.arg(certificate_hostname),sqlc.narg(service_port), 'prepared', sqlc.arg(now), sqlc.arg(publisher_expires_at)) RETURNING *;

-- name: LockPrivateServiceRun :one
SELECT * FROM control.private_service_runs
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id) FOR UPDATE;

-- name: GetPrivateRunPublisherIdentity :one
-- starting a run requires its exact authenticated publisher, grant and key.
SELECT publisher_key.public_key FROM control.private_service_runs run
JOIN control.publisher_identity_keys publisher_key
    ON publisher_key.id = run.publisher_key_id
    AND publisher_key.publisher_identity_id = run.publisher_identity_id
JOIN control.publisher_identities publisher ON publisher.id = run.publisher_identity_id
    AND publisher.revoked_at IS NULL AND publisher.team_id = run.team_id
    AND control.active_publisher(publisher.id,sqlc.arg(now))
JOIN control.publisher_grants grant_record ON grant_record.id = run.publisher_grant_id
    AND grant_record.publisher_identity_id = publisher.id
    AND grant_record.kind = 'private_service' AND grant_record.private_service_id = run.private_service_id
    AND grant_record.revoked_at IS NULL
    AND (grant_record.expires_at IS NULL OR grant_record.expires_at > sqlc.arg(now))
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.private_service_id = sqlc.arg(private_service_id)
    AND run.publisher_identity_id = sqlc.arg(publisher_identity_id)
    AND run.publisher_grant_id = sqlc.arg(publisher_grant_id)
    AND run.publisher_key_id = sqlc.arg(publisher_key_id)
    AND run.closed_at IS NULL;

-- name: AdvancePrivateServiceRunNumber :one
UPDATE control.private_services SET next_run_number = next_run_number + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND enabled AND deleted_at IS NULL RETURNING (next_run_number - 1)::bigint AS run_number;

-- name: ReadyPrivateServiceRun :one
UPDATE control.private_service_runs run SET state = 'ready', ready_at = COALESCE(run.ready_at, sqlc.arg(now))
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.private_service_id = sqlc.arg(private_service_id)
    AND run.state = 'starting' AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND run.healthy
    AND run.certificate_expires_at>sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.private_service_connection_slots slot
        JOIN control.relay_leases lease ON lease.relay_id = slot.relay_id
          AND lease.relay_run_id = slot.relay_run_id AND lease.relay_lease_revision = slot.relay_lease_revision
          AND lease.relay_service_id = slot.relay_service_id
          AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining
        WHERE slot.private_run_id = run.id AND slot.state = 'ready' AND slot.session_open
        GROUP BY slot.private_run_id
        HAVING count(*) >= CASE WHEN run.ready_at IS NULL THEN 2 ELSE 1 END)
RETURNING run.*;

-- name: DemotePrivateServiceRun :execrows
UPDATE control.private_service_runs SET state = 'starting'
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id)
    AND run_number = sqlc.arg(run_number) AND state = 'ready' AND closed_at IS NULL;

-- name: RenewPrivateServiceRun :one
UPDATE control.private_service_runs run SET publisher_expires_at = sqlc.arg(publisher_expires_at)
FROM control.private_services service, control.publisher_grants publisher_grant, control.publisher_identities publisher
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.private_service_id = sqlc.arg(private_service_id)
    AND run.run_token_digest = sqlc.arg(run_token_digest)
    AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND sqlc.arg(publisher_expires_at)::timestamptz > sqlc.arg(now)
    AND service.id = run.private_service_id AND service.enabled AND service.deleted_at IS NULL
    AND publisher_grant.id = run.publisher_grant_id AND publisher_grant.private_service_id = service.id
    AND publisher_grant.kind = 'private_service' AND publisher_grant.revoked_at IS NULL
    AND (publisher_grant.expires_at IS NULL OR publisher_grant.expires_at > sqlc.arg(now))
    AND publisher.id = run.publisher_identity_id AND publisher.team_id = service.team_id
    AND publisher.revoked_at IS NULL
    AND control.active_publisher(publisher.id,sqlc.arg(now))
RETURNING run.*;

-- name: ClosePrivateServiceRun :execrows
UPDATE control.private_service_runs SET state = 'closed', closed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id)
    AND run_number = sqlc.arg(run_number) AND closed_at IS NULL;

-- name: ExpirePrivateServiceRunPreparation :execrows
UPDATE control.private_service_runs SET state = 'closed', closed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'prepared' AND closed_at IS NULL AND preparation_expires_at <= sqlc.arg(now);

-- name: InsertPrivateServiceConnectionSlot :one
INSERT INTO control.private_service_connection_slots(publisher_connection_id, private_run_id,
    private_service_id, run_number, connection_slot, connection_assignment_revision,
    relay_service_id, relay_address, tls_server_name, credential_digest, credential_expires_at, state,assigned_at)
VALUES (sqlc.arg(publisher_connection_id), sqlc.arg(private_run_id), sqlc.arg(private_service_id),
    sqlc.arg(run_number), sqlc.arg(connection_slot), sqlc.arg(connection_assignment_revision),
    sqlc.arg(relay_service_id), sqlc.arg(relay_address), sqlc.arg(tls_server_name),
    sqlc.arg(credential_digest), sqlc.arg(credential_expires_at), 'assigned',sqlc.arg(assigned_at)) RETURNING *;

-- name: ListPrivateServiceConnectionSlots :many
SELECT * FROM control.private_service_connection_slots WHERE private_run_id = sqlc.arg(private_run_id)
ORDER BY connection_slot;

-- name: ListPrivateServiceConnectionSlotsNeedingReplacement :many
-- replace expired never-ready claims even with a live relay lease.
-- ready slots retain ownership and streams while their matching lease is live.
SELECT slot.* FROM control.private_service_connection_slots slot
WHERE slot.private_run_id = sqlc.arg(private_run_id)
    AND (slot.state = 'closed' OR slot.state IN ('assigned', 'connected') AND slot.credential_expires_at <= sqlc.arg(now)
        OR slot.state IN ('connected', 'ready') AND NOT EXISTS (
            SELECT 1 FROM control.relay_leases lease
            WHERE lease.relay_id = slot.relay_id AND lease.relay_run_id = slot.relay_run_id
              AND lease.relay_lease_revision = slot.relay_lease_revision
              AND lease.relay_service_id = slot.relay_service_id
              AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining))
ORDER BY slot.connection_slot;

-- name: ExpirePrivateServiceConnectionSlot :execrows
UPDATE control.private_service_connection_slots slot SET state = 'closed', relay_id = NULL,
    relay_run_id = NULL, relay_lease_revision = NULL
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.private_run_id = sqlc.arg(private_run_id)
    AND slot.state IN ('connected', 'ready')
    AND (slot.state = 'connected' AND slot.credential_expires_at <= sqlc.arg(now)
        OR NOT EXISTS (SELECT 1 FROM control.relay_leases lease
            WHERE lease.relay_id = slot.relay_id AND lease.relay_run_id = slot.relay_run_id
              AND lease.relay_lease_revision = slot.relay_lease_revision
              AND lease.relay_service_id = slot.relay_service_id
              AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining));

-- name: DeletePrivateServiceConnectionSlot :execrows
DELETE FROM control.private_service_connection_slots WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND private_run_id = sqlc.arg(private_run_id)
    AND (state = 'closed' OR state = 'assigned' AND credential_expires_at <= sqlc.arg(now));

-- name: ClaimPrivateServiceConnectionSlot :one
UPDATE control.private_service_connection_slots slot
SET relay_id = sqlc.arg(relay_id), relay_run_id = sqlc.arg(relay_run_id),
    relay_lease_revision = sqlc.arg(relay_lease_revision), state = 'connected'
FROM control.private_service_runs r, control.relay_leases l
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
    AND r.id = slot.private_run_id AND r.closed_at IS NULL AND r.publisher_expires_at > sqlc.arg(now)
    AND l.relay_id = sqlc.arg(relay_id) AND l.relay_run_id = sqlc.arg(relay_run_id)
    AND l.relay_lease_revision = sqlc.arg(relay_lease_revision)
    AND l.relay_service_id = slot.relay_service_id AND l.lease_expires_at > sqlc.arg(now) AND NOT l.draining
RETURNING slot.*;

-- name: ReadyPrivateServiceConnectionSlot :one
UPDATE control.private_service_connection_slots slot SET state = 'ready'
FROM control.private_service_runs run, control.relay_leases lease
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.connection_assignment_revision = sqlc.arg(connection_assignment_revision)
    AND slot.state = 'connected' AND slot.private_run_id = run.id
    AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND lease.relay_id = slot.relay_id AND lease.relay_run_id = slot.relay_run_id
    AND lease.relay_lease_revision = slot.relay_lease_revision
    AND lease.relay_service_id = slot.relay_service_id
    AND lease.lease_expires_at > sqlc.arg(now) AND NOT lease.draining
RETURNING slot.*;

-- name: DisconnectPrivateServiceConnectionSlot :one
UPDATE control.private_service_connection_slots slot
SET state = 'closed', relay_id = NULL, relay_run_id = NULL, relay_lease_revision = NULL
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.private_run_id = sqlc.arg(private_run_id) AND slot.run_number = sqlc.arg(run_number)
    AND slot.connection_assignment_revision = sqlc.arg(connection_assignment_revision)
    AND slot.relay_id = sqlc.arg(relay_id) AND slot.relay_run_id = sqlc.arg(relay_run_id)
    AND slot.relay_lease_revision = sqlc.arg(relay_lease_revision)
    AND slot.state IN ('connected', 'ready')
RETURNING slot.*;

-- name: InsertPrivateServiceRoutingEvent :one
-- lock PrivateServiceRoutingClock before inserting, and advance the clock in
-- the same transaction so a snapshot cannot miss an earlier uncommitted event.
INSERT INTO control.private_service_routing_events(private_service_id, kind, private_run_id,
    run_number, projection, expires_at, created_at)
VALUES (sqlc.arg(private_service_id), sqlc.arg(kind), sqlc.narg(private_run_id),
    sqlc.narg(run_number), sqlc.arg(projection), sqlc.arg(expires_at), sqlc.arg(now)) RETURNING *;

-- name: LockPrivateServiceRoutingClock :one
SELECT current_revision FROM control.private_service_routing_clock WHERE id = 1 FOR UPDATE;

-- name: AdvancePrivateServiceRoutingClock :one
UPDATE control.private_service_routing_clock SET current_revision = sqlc.arg(revision), updated_at = sqlc.arg(now)
WHERE id = 1 AND current_revision < sqlc.arg(revision) RETURNING current_revision;

-- name: ReadPrivateServiceRoutingClock :one
SELECT current_revision FROM control.private_service_routing_clock WHERE id = 1;

-- name: ListPrivateServiceRoutingSnapshot :many
SELECT e.* FROM control.private_service_routing_events e
JOIN (SELECT history.private_service_id, max(history.revision) AS latest_revision
    FROM control.private_service_routing_events history WHERE history.revision <= sqlc.arg(through_revision)
    GROUP BY history.private_service_id, history.private_run_id) latest ON latest.latest_revision = e.revision
WHERE e.kind = 'upsert' AND e.expires_at > sqlc.arg(now)
    AND NOT EXISTS (SELECT 1 FROM control.private_service_routing_events deleted
        WHERE deleted.private_service_id=e.private_service_id AND deleted.private_run_id IS NULL
        AND deleted.kind='tombstone' AND deleted.revision > e.revision
        AND deleted.revision <= sqlc.arg(through_revision))
ORDER BY e.private_service_id, e.run_number;

-- name: ListPrivateServiceRoutingEvents :many
SELECT * FROM control.private_service_routing_events
WHERE revision > sqlc.arg(after_revision) AND revision <= sqlc.arg(through_revision)
ORDER BY revision LIMIT sqlc.arg(page_limit);

-- name: RevokePrivateConnectorSession :execrows
UPDATE control.private_connector_sessions SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL;

-- name: CleanupPrivateConnectorSessions :exec
DELETE FROM control.private_connector_sessions session WHERE session.id IN
    (SELECT expired.id FROM control.private_connector_sessions expired
        WHERE expired.workload_session_id IS NULL AND expired.expires_at <= sqlc.arg(now)
        AND NOT EXISTS (SELECT 1 FROM control.private_visitor_streams stream
            WHERE stream.connector_session_id = expired.id)
        ORDER BY expired.expires_at, expired.id LIMIT 100 FOR UPDATE SKIP LOCKED);

-- name: RecheckPrivateServiceVisitor :one
-- revalidate the admitted stream, live device, grant and exact run. identity
-- and source are bound by ingress, and an outage never extends the deadline.
WITH permitted AS (
    SELECT LEAST(sqlc.arg(now)::timestamptz + interval '2 minutes', run.publisher_expires_at, run.certificate_expires_at,
      control.company_subject_deadline(service.team_id,person.id,COALESCE(session.control_session_id,''),sqlc.arg(now)),
      ingress.lease_expires_at, publisher_grant.expires_at,
      (SELECT MAX(relay.lease_expires_at) FROM control.private_service_connection_slots slot
          JOIN control.relay_leases relay ON relay.relay_id = slot.relay_id
            AND relay.relay_run_id = slot.relay_run_id
            AND relay.relay_lease_revision = slot.relay_lease_revision
            AND relay.relay_service_id = slot.relay_service_id
            AND relay.lease_expires_at > sqlc.arg(now) AND NOT relay.draining
          WHERE slot.private_run_id = run.id AND slot.state = 'ready' AND slot.session_open),
      CASE WHEN EXISTS (SELECT 1 FROM control.private_service_grants permanent
          LEFT JOIN control.team_memberships member ON member.team_id = service.team_id
            AND member.identity_id = person.id AND control.active_membership(member.id,sqlc.arg(now))
          WHERE permanent.private_service_id = service.id AND permanent.revoked_at IS NULL
            AND permanent.expires_at IS NULL
            AND (NOT permanent.auto_owner OR member.role IN ('owner','admin'))
            AND ((permanent.kind = 'identity' AND permanent.identity_id = person.id)
              OR (permanent.kind = 'team' AND member.id IS NOT NULL)))
      THEN 'infinity'::timestamptz ELSE
        (SELECT MAX(limited.expires_at) FROM control.private_service_grants limited
          LEFT JOIN control.team_memberships member ON member.team_id = service.team_id
            AND member.identity_id = person.id AND control.active_membership(member.id,sqlc.arg(now))
          WHERE limited.private_service_id = service.id AND limited.revoked_at IS NULL
             AND limited.expires_at > sqlc.arg(now)
             AND (NOT limited.auto_owner OR member.role IN ('owner','admin'))
            AND ((limited.kind = 'identity' AND limited.identity_id = person.id)
              OR (limited.kind = 'team' AND member.id IS NOT NULL))) END) AS valid_until
    FROM control.private_visitor_streams stream
    JOIN control.private_connector_sessions session ON session.id = stream.connector_session_id
    JOIN control.visitor_devices device ON device.id=session.device_id
      AND device.identity_id=session.identity_id AND device.revoked_at IS NULL
    JOIN control.private_service_runs run ON run.id = stream.private_run_id
    JOIN control.private_services service ON service.id = stream.private_service_id
    JOIN control.teams team ON team.id = service.team_id AND team.deleted_at IS NULL
    JOIN control.identities person ON person.id = stream.identity_id AND person.disabled_at IS NULL
    JOIN control.ingress_leases ingress ON ingress.ingress_id = session.ingress_id
      AND ingress.ingress_run_id = session.ingress_run_id
      AND ingress.ingress_lease_revision = session.ingress_lease_revision
    JOIN control.publisher_grants publisher_grant ON publisher_grant.id = run.publisher_grant_id
    JOIN control.publisher_identities publisher ON publisher.id = run.publisher_identity_id
    WHERE stream.private_service_id = sqlc.arg(private_service_id)
      AND stream.private_run_id = sqlc.arg(private_run_id)
      AND stream.run_number = sqlc.arg(run_number)
      AND stream.connector_session_id = sqlc.arg(connector_session_id)
      AND stream.identity_id = sqlc.arg(identity_id)
      AND stream.visitor_connection_id = sqlc.arg(visitor_connection_id)
      AND stream.source_ip = sqlc.arg(observed_source_ip)::inet
      AND stream.closed_at IS NULL AND stream.device_id=device.id AND stream.valid_until>sqlc.arg(now)
      AND session.identity_id = person.id
      AND control.company_subject_session_authorized(service.team_id,person.id,COALESCE(session.control_session_id,''),sqlc.arg(now))
      AND session.bound_at IS NOT NULL AND session.revoked_at IS NULL
      AND session.source_ip = stream.source_ip
      AND session.ingress_id = sqlc.arg(ingress_id)
      AND session.ingress_run_id = sqlc.arg(ingress_run_id)
      AND session.ingress_lease_revision = sqlc.arg(ingress_lease_revision)
      AND ingress.lease_expires_at > sqlc.arg(now)
      AND service.enabled AND service.deleted_at IS NULL
      AND run.private_service_id = service.id AND run.run_number = stream.run_number
      AND run.state = 'ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
      AND run.certificate_expires_at > sqlc.arg(now)
      AND publisher_grant.publisher_identity_id = publisher.id
      AND publisher_grant.private_service_id = service.id
      AND publisher_grant.kind = 'private_service' AND publisher_grant.revoked_at IS NULL
      AND (publisher_grant.expires_at IS NULL OR publisher_grant.expires_at > sqlc.arg(now))
      AND publisher.team_id = service.team_id AND publisher.revoked_at IS NULL
      AND control.active_publisher(publisher.id,sqlc.arg(now))
      AND EXISTS (SELECT 1 FROM control.private_service_connection_slots slot
          JOIN control.relay_leases relay ON relay.relay_id = slot.relay_id
            AND relay.relay_run_id = slot.relay_run_id
            AND relay.relay_lease_revision = slot.relay_lease_revision
            AND relay.relay_service_id = slot.relay_service_id
            AND relay.lease_expires_at > sqlc.arg(now) AND NOT relay.draining
          WHERE slot.private_run_id = run.id AND slot.state = 'ready' AND slot.session_open)
      AND (EXISTS (SELECT 1 FROM control.private_service_grants grant_record
          LEFT JOIN control.team_memberships member ON member.team_id = service.team_id
            AND member.identity_id = person.id AND control.active_membership(member.id,sqlc.arg(now))
          WHERE grant_record.private_service_id = service.id
            AND grant_record.revoked_at IS NULL
             AND (grant_record.expires_at IS NULL OR grant_record.expires_at > sqlc.arg(now))
             AND (NOT grant_record.auto_owner OR member.role IN ('owner','admin'))
            AND ((grant_record.kind = 'identity' AND grant_record.identity_id = person.id)
              OR (grant_record.kind = 'team' AND member.id IS NOT NULL))))
)
SELECT EXISTS (SELECT 1 FROM permitted)::boolean AS allowed,
    COALESCE((SELECT valid_until FROM permitted LIMIT 1), sqlc.arg(now)::timestamptz)::timestamptz AS valid_until;

-- name: GetPrivateServiceSource :one
SELECT l.project_key,l.source_fingerprint,l.service,l.worktree_key
FROM control.local_project_services l WHERE l.private_service_id=sqlc.arg(private_service_id)
UNION ALL
SELECT a.project_key,p.source_fingerprint,a.service,s.placement_worktree_key AS worktree_key
FROM control.applied_project_services a
JOIN control.applied_projects p ON p.team_id=a.team_id AND p.project_key=a.project_key
JOIN control.private_services s ON s.id=a.private_service_id
WHERE a.private_service_id=sqlc.arg(private_service_id)
LIMIT 1;

-- name: LockPendingPrivateServiceInvitation :one
SELECT * FROM control.private_service_invitations
WHERE id=sqlc.arg(id) AND private_service_id=sqlc.arg(private_service_id)
AND revoked_at IS NULL AND accepted_at IS NULL AND expires_at>sqlc.arg(now)
FOR UPDATE;
