-- name: InsertPrivateService :one
INSERT INTO control.private_services(id, team_id, name, created_by_identity_id, idempotency_key, request_digest, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(created_by_identity_id),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest), sqlc.arg(now), sqlc.arg(now)) RETURNING *;

-- name: LockPrivateService :one
SELECT * FROM control.private_services WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: DeletePrivateService :one
-- caller closes its active run and publishes a tombstone under this service
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
ORDER BY id LIMIT 101;

-- name: InsertPrivateServiceInvitation :one
INSERT INTO control.private_service_invitations(id, private_service_id, team_id, normalized_email,
    token_digest, created_by_identity_id, idempotency_key, request_digest, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(private_service_id), sqlc.arg(team_id), sqlc.arg(normalized_email),
    sqlc.arg(token_digest), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(now), sqlc.arg(expires_at)) RETURNING *;

-- name: AcceptPrivateServiceInvitation :one
-- caller verifies the authenticated identity's email against normalized_email.
UPDATE control.private_service_invitations invitation
SET accepted_identity_id = sqlc.arg(identity_id), accepted_at = sqlc.arg(now)
FROM control.private_services service, control.identities person
WHERE invitation.token_digest = sqlc.arg(token_digest) AND invitation.revoked_at IS NULL
    AND invitation.accepted_at IS NULL AND invitation.expires_at > sqlc.arg(now)
    AND service.id = invitation.private_service_id AND service.enabled AND service.deleted_at IS NULL
    AND person.id = sqlc.arg(identity_id) AND person.disabled_at IS NULL
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
WHERE private_service_id = sqlc.arg(private_service_id) ORDER BY id LIMIT 101;

-- name: ListAvailablePrivateServices :many
-- visitor inventory includes authorized saved services while the publisher is
-- offline. only project an open, ready run with two ready slots and a live
-- publisher grant. do not include target addresses, tickets or keys.
SELECT s.id, s.team_id, s.name, r.id AS private_run_id, r.run_number
FROM control.private_services s
JOIN control.teams t ON t.id = s.team_id AND t.deleted_at IS NULL
JOIN control.identities i ON i.id = sqlc.arg(identity_id) AND i.disabled_at IS NULL
LEFT JOIN control.private_service_runs r ON r.private_service_id = s.id
    AND r.state = 'ready' AND r.closed_at IS NULL AND r.publisher_expires_at > sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.publisher_grants pg
        JOIN control.publisher_identities p ON p.id = pg.publisher_identity_id
        WHERE pg.id = r.publisher_grant_id AND pg.private_service_id = s.id
          AND pg.kind = 'private_service' AND pg.revoked_at IS NULL
          AND (pg.expires_at IS NULL OR pg.expires_at > sqlc.arg(now))
          AND p.team_id = s.team_id AND p.revoked_at IS NULL)
    AND EXISTS (SELECT 1 FROM control.private_service_connection_slots slot
        WHERE slot.private_run_id = r.id AND slot.state = 'ready'
        GROUP BY slot.private_run_id HAVING count(*) = 2)
WHERE s.deleted_at IS NULL AND s.enabled AND s.id > sqlc.arg(after_id)
    AND (
        EXISTS (SELECT 1 FROM control.team_memberships m
            WHERE m.team_id = s.team_id AND m.identity_id = i.id AND m.removed_at IS NULL
              AND m.role IN ('owner', 'admin'))
        OR EXISTS (SELECT 1 FROM control.private_service_grants g
            LEFT JOIN control.team_memberships m ON m.team_id = s.team_id
                AND m.identity_id = i.id AND m.removed_at IS NULL
            WHERE g.private_service_id = s.id AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > sqlc.arg(now))
                AND ((g.kind = 'identity' AND g.identity_id = i.id)
                  OR (g.kind = 'team' AND m.id IS NOT NULL)))
    )
ORDER BY s.id LIMIT 101;

-- name: PreparePrivateServiceRun :one
-- caller locks the service, checks the live publisher grant and enrolled key,
-- allocates one run number, then returns this run ID and nonce to the publisher.
-- a retry with the same idempotency key returns the same prepared row.
INSERT INTO control.private_service_runs(id, private_service_id, team_id, run_number,
    publisher_identity_id, publisher_grant_id, publisher_key_id, idempotency_key,
    request_digest, binding_nonce, binding_expires_at, state, created_at, publisher_expires_at)
VALUES (sqlc.arg(id), sqlc.arg(private_service_id), sqlc.arg(team_id), sqlc.arg(run_number),
    sqlc.arg(publisher_identity_id), sqlc.arg(publisher_grant_id), sqlc.arg(publisher_key_id),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest), sqlc.arg(binding_nonce),
    sqlc.arg(binding_expires_at), 'prepared', sqlc.arg(now), sqlc.arg(publisher_expires_at)) RETURNING *;

-- name: LockPrivateServiceRun :one
SELECT * FROM control.private_service_runs
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id) FOR UPDATE;

-- name: GetPrivateRunBindingIdentityKey :one
-- use this enrolled public key after locking the prepared run and compare the
-- publisherAuth token's identity, grant and key ID with the same locked row.
SELECT publisher_key.public_key FROM control.private_service_runs run
JOIN control.publisher_identity_keys publisher_key
    ON publisher_key.id = run.publisher_key_id
    AND publisher_key.publisher_identity_id = run.publisher_identity_id
    AND publisher_key.retired_at IS NULL
JOIN control.publisher_identities publisher ON publisher.id = run.publisher_identity_id
    AND publisher.revoked_at IS NULL AND publisher.team_id = run.team_id
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

-- name: BindPrivateServiceRunKey :one
-- control verifies the Ed25519 signature with the enrolled publisher identity
-- key over the exact team/service/run/number/nonce/public key/idempotency tuple
-- before this write. a bearer token alone cannot supply or replace the pin.
UPDATE control.private_service_runs run
SET stream_public_key = sqlc.arg(stream_public_key),
    stream_key_binding_signature = sqlc.arg(binding_signature),
    run_token_digest = sqlc.arg(run_token_digest), bound_at = sqlc.arg(now),
    publisher_expires_at = sqlc.arg(publisher_expires_at), state = 'starting'
FROM control.private_services service, control.teams team,
    control.publisher_grants grant_record, control.publisher_identities publisher,
    control.publisher_identity_keys publisher_key
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.private_service_id = sqlc.arg(private_service_id)
    AND run.state = 'prepared' AND run.closed_at IS NULL AND run.binding_expires_at > sqlc.arg(now)
    AND run.binding_nonce = sqlc.arg(binding_nonce)
    AND run.publisher_key_id = sqlc.arg(publisher_key_id)
    AND sqlc.arg(publisher_expires_at)::timestamptz > sqlc.arg(now)
    AND service.id = run.private_service_id AND service.enabled AND service.deleted_at IS NULL
    AND team.id = service.team_id AND team.deleted_at IS NULL
    AND grant_record.id = run.publisher_grant_id AND grant_record.publisher_identity_id = run.publisher_identity_id
    AND grant_record.kind = 'private_service' AND grant_record.private_service_id = service.id
    AND grant_record.revoked_at IS NULL
    AND (grant_record.expires_at IS NULL OR grant_record.expires_at > sqlc.arg(now))
    AND publisher.id = run.publisher_identity_id AND publisher.team_id = service.team_id
    AND publisher.revoked_at IS NULL
    AND publisher_key.id = run.publisher_key_id AND publisher_key.publisher_identity_id = publisher.id
    AND publisher_key.retired_at IS NULL
RETURNING run.*;

-- name: RetryPrivateServiceRunKeyBinding :one
-- the caller re-verifies the SAME signed binding using the enrolled identity
-- and atomically rotates only the run token. the public key is immutable.
UPDATE control.private_service_runs run SET run_token_digest = sqlc.arg(run_token_digest)
FROM control.publisher_grants grant_record, control.publisher_identities publisher,
    control.publisher_identity_keys publisher_key, control.private_services service
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.private_service_id = sqlc.arg(private_service_id)
    AND run.state IN ('starting', 'ready') AND run.closed_at IS NULL
    AND run.stream_public_key = sqlc.arg(stream_public_key)
    AND run.stream_key_binding_signature = sqlc.arg(binding_signature)
    AND run.publisher_key_id = sqlc.arg(publisher_key_id)
    AND run.publisher_expires_at > sqlc.arg(now)
    AND service.id = run.private_service_id AND service.enabled AND service.deleted_at IS NULL
    AND grant_record.id = run.publisher_grant_id AND grant_record.kind = 'private_service'
    AND grant_record.private_service_id = service.id AND grant_record.revoked_at IS NULL
    AND (grant_record.expires_at IS NULL OR grant_record.expires_at > sqlc.arg(now))
    AND publisher.id = run.publisher_identity_id AND publisher.revoked_at IS NULL
    AND publisher.team_id = service.team_id
    AND publisher_key.id = run.publisher_key_id AND publisher_key.publisher_identity_id = publisher.id
    AND publisher_key.retired_at IS NULL
RETURNING run.*;

-- name: AdvancePrivateServiceRunNumber :one
UPDATE control.private_services SET next_run_number = next_run_number + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND enabled AND deleted_at IS NULL RETURNING next_run_number - 1 AS run_number;

-- name: ReadyPrivateServiceRun :one
UPDATE control.private_service_runs run SET state = 'ready', ready_at = sqlc.arg(now)
WHERE run.id = sqlc.arg(id) AND run.run_number = sqlc.arg(run_number)
    AND run.private_service_id = sqlc.arg(private_service_id)
    AND run.state = 'starting' AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.private_service_connection_slots slot
        WHERE slot.private_run_id = run.id AND slot.state = 'ready'
        GROUP BY slot.private_run_id HAVING count(*) = 2)
RETURNING run.*;

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
RETURNING run.*;

-- name: ClosePrivateServiceRun :execrows
UPDATE control.private_service_runs SET state = 'closed', closed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND private_service_id = sqlc.arg(private_service_id)
    AND run_number = sqlc.arg(run_number) AND closed_at IS NULL;

-- name: ExpirePrivateServiceRunPreparation :execrows
UPDATE control.private_service_runs SET state = 'closed', closed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'prepared' AND closed_at IS NULL AND binding_expires_at <= sqlc.arg(now);

-- name: InsertPrivateServiceConnectionSlot :one
INSERT INTO control.private_service_connection_slots(publisher_connection_id, private_run_id,
    private_service_id, run_number, connection_slot, connection_assignment_revision,
    relay_service_id, relay_address, tls_server_name, credential_digest, credential_expires_at, state)
VALUES (sqlc.arg(publisher_connection_id), sqlc.arg(private_run_id), sqlc.arg(private_service_id),
    sqlc.arg(run_number), sqlc.arg(connection_slot), sqlc.arg(connection_assignment_revision),
    sqlc.arg(relay_service_id), sqlc.arg(relay_address), sqlc.arg(tls_server_name),
    sqlc.arg(credential_digest), sqlc.arg(credential_expires_at), 'assigned') RETURNING *;

-- name: ClaimPrivateServiceConnectionSlot :one
UPDATE control.private_service_connection_slots slot
SET relay_id = sqlc.arg(relay_id), relay_run_id = sqlc.arg(relay_run_id),
    relay_lease_revision = sqlc.arg(relay_lease_revision), state = 'connected'
FROM control.private_service_runs r, control.relay_leases l
WHERE slot.publisher_connection_id = sqlc.arg(publisher_connection_id)
    AND slot.credential_digest = sqlc.arg(credential_digest)
    AND slot.connection_assignment_revision = sqlc.arg(connection_assignment_revision)
    AND slot.state = 'assigned' AND slot.credential_expires_at > sqlc.arg(now)
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
    GROUP BY history.private_service_id) latest ON latest.latest_revision = e.revision
WHERE e.kind = 'upsert' AND e.expires_at > sqlc.arg(now) ORDER BY e.private_service_id;

-- name: ListPrivateServiceRoutingEvents :many
SELECT * FROM control.private_service_routing_events
WHERE revision > sqlc.arg(after_revision) AND revision <= sqlc.arg(through_revision)
ORDER BY revision LIMIT sqlc.arg(page_limit);

-- name: InsertPrivateConnectorSession :one
-- a signed-in identity obtains a one-use infrastructure credential before
-- starting the mux session. source IP is unknown until ingress claims it.
INSERT INTO control.private_connector_sessions(id, credential_digest, private_service_id, identity_id, created_at, expires_at)
SELECT sqlc.arg(id), sqlc.arg(credential_digest), service.id, person.id,
    sqlc.arg(now), sqlc.arg(expires_at)
FROM control.private_services service
JOIN control.teams team ON team.id = service.team_id AND team.deleted_at IS NULL
JOIN control.identities person ON person.id = sqlc.arg(identity_id) AND person.disabled_at IS NULL
WHERE service.id = sqlc.arg(private_service_id) AND service.enabled AND service.deleted_at IS NULL
    AND sqlc.arg(expires_at)::timestamptz > sqlc.arg(now)
    AND sqlc.arg(expires_at)::timestamptz <= sqlc.arg(now)::timestamptz + interval '15 minutes'
    AND (EXISTS (SELECT 1 FROM control.team_memberships member
        WHERE member.team_id = service.team_id AND member.identity_id = person.id
            AND member.removed_at IS NULL AND member.role IN ('owner', 'admin'))
      OR EXISTS (SELECT 1 FROM control.private_service_grants visitor_grant
        LEFT JOIN control.team_memberships member ON member.team_id = service.team_id
            AND member.identity_id = person.id AND member.removed_at IS NULL
        WHERE visitor_grant.private_service_id = service.id AND visitor_grant.revoked_at IS NULL
          AND (visitor_grant.expires_at IS NULL OR visitor_grant.expires_at > sqlc.arg(now))
          AND ((visitor_grant.kind = 'identity' AND visitor_grant.identity_id = person.id)
            OR (visitor_grant.kind = 'team' AND member.id IS NOT NULL))))
RETURNING *;

-- name: ClaimPrivateConnectorSession :one
-- observed_source_ip is supplied ONLY by authenticated ingress from its
-- trusted socket/PROXY metadata; never from a connector frame or browser.
UPDATE control.private_connector_sessions session
SET bound_at = sqlc.arg(now), source_ip = sqlc.arg(observed_source_ip)::inet,
    ingress_id = sqlc.arg(ingress_id), ingress_run_id = sqlc.arg(ingress_run_id),
    ingress_lease_revision = sqlc.arg(ingress_lease_revision)
FROM control.ingress_leases ingress, control.identities person
WHERE session.id = sqlc.arg(id) AND session.credential_digest = sqlc.arg(credential_digest)
    AND session.private_service_id = sqlc.arg(private_service_id)
    AND session.bound_at IS NULL AND session.revoked_at IS NULL AND session.expires_at > sqlc.arg(now)
    AND person.id = session.identity_id AND person.disabled_at IS NULL
    AND ingress.ingress_id = sqlc.arg(ingress_id) AND ingress.ingress_run_id = sqlc.arg(ingress_run_id)
    AND ingress.ingress_lease_revision = sqlc.arg(ingress_lease_revision)
    AND ingress.lease_expires_at > sqlc.arg(now) AND NOT ingress.draining
RETURNING session.*;

-- name: RevokePrivateConnectorSession :execrows
UPDATE control.private_connector_sessions SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL;

-- name: CleanupPrivateConnectorSessions :exec
DELETE FROM control.private_connector_sessions session WHERE session.id IN
    (SELECT expired.id FROM control.private_connector_sessions expired
        WHERE expired.expires_at <= sqlc.arg(now) LIMIT 100)
    AND NOT EXISTS (SELECT 1 FROM control.private_service_tickets ticket
        WHERE ticket.connector_session_id = session.id);

-- name: InsertPrivateServiceTicket :one
-- caller locks the service/run. this rechecks current permission and copies
-- the ingress-observed source from the claimed, identity-bound mux session.
-- never put a ticket in a routing projection or accept a client source IP.
INSERT INTO control.private_service_tickets(digest, private_service_id, private_run_id, run_number,
    connector_session_id, identity_id, source_ip, stream_public_key, created_at, expires_at)
SELECT sqlc.arg(digest), s.id, r.id, r.run_number, session.id, i.id,
    session.source_ip, r.stream_public_key, sqlc.arg(now), sqlc.arg(expires_at)
FROM control.private_services s
JOIN control.private_service_runs r ON r.private_service_id = s.id
JOIN control.teams t ON t.id = s.team_id AND t.deleted_at IS NULL
JOIN control.identities i ON i.id = sqlc.arg(identity_id) AND i.disabled_at IS NULL
JOIN control.private_connector_sessions session ON session.id = sqlc.arg(connector_session_id)
    AND session.identity_id = i.id AND session.private_service_id = s.id AND session.bound_at IS NOT NULL
    AND session.source_ip IS NOT NULL AND session.revoked_at IS NULL
    AND session.expires_at > sqlc.arg(now)
JOIN control.ingress_leases ingress ON ingress.ingress_id = session.ingress_id
    AND ingress.ingress_run_id = session.ingress_run_id
    AND ingress.ingress_lease_revision = session.ingress_lease_revision
    AND ingress.lease_expires_at > sqlc.arg(now) AND NOT ingress.draining
WHERE s.id = sqlc.arg(private_service_id) AND r.id = sqlc.arg(private_run_id)
    AND s.enabled AND s.deleted_at IS NULL AND r.state = 'ready'
    AND r.closed_at IS NULL AND r.publisher_expires_at > sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM control.publisher_grants pg
        JOIN control.publisher_identities p ON p.id = pg.publisher_identity_id
        WHERE pg.id = r.publisher_grant_id AND pg.private_service_id = s.id
          AND pg.kind = 'private_service' AND pg.revoked_at IS NULL
          AND (pg.expires_at IS NULL OR pg.expires_at > sqlc.arg(now))
          AND p.team_id = s.team_id AND p.revoked_at IS NULL)
    AND sqlc.arg(expires_at)::timestamptz > sqlc.arg(now)
    AND sqlc.arg(expires_at)::timestamptz <= sqlc.arg(now)::timestamptz + interval '1 minute'
    AND EXISTS (SELECT 1 FROM control.private_service_connection_slots slot
        WHERE slot.private_run_id = r.id AND slot.state = 'ready'
        GROUP BY slot.private_run_id HAVING count(*) = 2)
    AND (EXISTS (SELECT 1 FROM control.team_memberships m WHERE m.team_id = s.team_id
        AND m.identity_id = i.id AND m.removed_at IS NULL AND m.role IN ('owner', 'admin'))
      OR EXISTS (SELECT 1 FROM control.private_service_grants g
        LEFT JOIN control.team_memberships m ON m.team_id = s.team_id AND m.identity_id = i.id AND m.removed_at IS NULL
        WHERE g.private_service_id = s.id AND g.revoked_at IS NULL
          AND (g.expires_at IS NULL OR g.expires_at > sqlc.arg(now))
          AND ((g.kind = 'identity' AND g.identity_id = i.id) OR (g.kind = 'team' AND m.id IS NOT NULL))))
RETURNING *;

-- name: ConsumePrivateServiceTicket :one
-- consume before forwarding bytes, against the current grant and ingress lease.
-- the publisher proves the run key over end-to-end TLS after this claim.
-- ingress passes the authenticated mux session ID and its trusted socket source;
-- no client-supplied source or SNI is used for this exact-ID lookup.
UPDATE control.private_service_tickets ticket
SET consumed_at = sqlc.arg(now), visitor_connection_id = sqlc.arg(visitor_connection_id)
FROM control.private_service_runs r, control.private_services s,
    control.ingress_leases ingress, control.private_connector_sessions session
WHERE ticket.digest = sqlc.arg(digest) AND ticket.private_service_id = sqlc.arg(private_service_id)
    AND ticket.private_run_id = sqlc.arg(private_run_id) AND ticket.run_number = sqlc.arg(run_number)
    AND ticket.connector_session_id = sqlc.arg(connector_session_id)
    AND ticket.source_ip = sqlc.arg(observed_source_ip)::inet
    AND ticket.consumed_at IS NULL
    AND ticket.expires_at > sqlc.arg(now) AND r.id = ticket.private_run_id
    AND session.id = ticket.connector_session_id AND session.identity_id = ticket.identity_id
    AND session.private_service_id = ticket.private_service_id
    AND session.source_ip = ticket.source_ip AND session.bound_at IS NOT NULL
    AND session.expires_at > sqlc.arg(now) AND session.revoked_at IS NULL
    AND session.ingress_id = sqlc.arg(ingress_id) AND session.ingress_run_id = sqlc.arg(ingress_run_id)
    AND session.ingress_lease_revision = sqlc.arg(ingress_lease_revision)
    AND ingress.ingress_id = sqlc.arg(ingress_id) AND ingress.ingress_run_id = sqlc.arg(ingress_run_id)
    AND ingress.ingress_lease_revision = sqlc.arg(ingress_lease_revision)
    AND ingress.lease_expires_at > sqlc.arg(now) AND NOT ingress.draining
    AND r.run_number = ticket.run_number AND r.stream_public_key = ticket.stream_public_key
    AND r.closed_at IS NULL AND r.state = 'ready' AND r.publisher_expires_at > sqlc.arg(now)
    AND s.id = ticket.private_service_id AND s.enabled AND s.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM control.teams team WHERE team.id = s.team_id AND team.deleted_at IS NULL)
    AND EXISTS (SELECT 1 FROM control.publisher_grants pg
        JOIN control.publisher_identities p ON p.id = pg.publisher_identity_id
        WHERE pg.id = r.publisher_grant_id AND pg.private_service_id = s.id
          AND pg.kind = 'private_service' AND pg.revoked_at IS NULL
          AND (pg.expires_at IS NULL OR pg.expires_at > sqlc.arg(now))
          AND p.team_id = s.team_id AND p.revoked_at IS NULL)
    AND EXISTS (SELECT 1 FROM control.identities i WHERE i.id = ticket.identity_id AND i.disabled_at IS NULL
        AND (EXISTS (SELECT 1 FROM control.team_memberships m WHERE m.team_id = s.team_id
            AND m.identity_id = i.id AND m.removed_at IS NULL AND m.role IN ('owner', 'admin'))
          OR EXISTS (SELECT 1 FROM control.private_service_grants g
            LEFT JOIN control.team_memberships m ON m.team_id = s.team_id
              AND m.identity_id = i.id AND m.removed_at IS NULL
            WHERE g.private_service_id = s.id AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > sqlc.arg(now))
              AND ((g.kind = 'identity' AND g.identity_id = i.id) OR (g.kind = 'team' AND m.id IS NOT NULL)))))
RETURNING ticket.*;

-- name: CleanupPrivateServiceTickets :exec
DELETE FROM control.private_service_tickets WHERE digest IN
    (SELECT expired.digest FROM control.private_service_tickets expired
        WHERE expired.expires_at <= sqlc.arg(now) LIMIT 100);
