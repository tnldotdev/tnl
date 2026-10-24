-- each phase has its own budget so a busy leaf cannot starve its parents.
-- select only unreferenced candidates before LIMIT; never cascade subject state.

-- name: CleanupWorkloadCertificateFacts :execrows
DELETE FROM control.visitor_certificate_facts WHERE certificate_digest IN (
    SELECT fact.certificate_digest FROM control.visitor_certificate_facts fact
    WHERE fact.workload_session_id IS NOT NULL AND fact.expires_at < sqlc.arg(before_time)
    ORDER BY fact.expires_at, fact.certificate_digest LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupWorkloadConnectors :execrows
DELETE FROM control.connector_sessions WHERE id IN (
    SELECT session.id FROM control.connector_sessions session
    WHERE session.workload_session_id IS NOT NULL
      AND session.expires_at < sqlc.arg(before_time)
      AND (session.revoked_at IS NULL OR session.revoked_at < sqlc.arg(before_time))
    ORDER BY session.expires_at, session.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupWorkloadCertificates :execrows
DELETE FROM control.workload_client_certificates WHERE certificate_digest IN (
    SELECT cert.certificate_digest FROM control.workload_client_certificates cert
    WHERE cert.expires_at < sqlc.arg(before_time)
    ORDER BY cert.expires_at, cert.certificate_digest LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupWorkloadIngressRequests :execrows
DELETE FROM control.workload_ingress_requests WHERE (workload_session_id, idempotency_key) IN (
    SELECT request.workload_session_id, request.idempotency_key FROM control.workload_ingress_requests request
    JOIN control.workload_sessions session ON session.id = request.workload_session_id
    WHERE session.expires_at < sqlc.arg(before_time) AND session.lease_expires_at < sqlc.arg(before_time)
      AND (session.revoked_at IS NULL OR session.revoked_at < sqlc.arg(before_time))
    ORDER BY session.expires_at, request.workload_session_id, request.idempotency_key LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF request SKIP LOCKED
);

-- name: CleanupWorkloadAssertions :execrows
DELETE FROM control.workload_assertions WHERE jti_digest IN (
    SELECT assertion.jti_digest FROM control.workload_assertions assertion WHERE assertion.expires_at < sqlc.arg(before_time)
    ORDER BY assertion.expires_at, assertion.jti_digest LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupWorkloadAudit :execrows
DELETE FROM control.workload_audit WHERE ctid IN (
    SELECT audit.ctid FROM control.workload_audit audit WHERE audit.occurred_at < sqlc.arg(before_time)
    ORDER BY audit.occurred_at, audit.ctid LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupWorkloadServiceRights :execrows
-- keep the exact service snapshot until all other session references are gone.
DELETE FROM control.workload_session_services WHERE (workload_session_id, service_id) IN (
    SELECT rights.workload_session_id, rights.service_id FROM control.workload_session_services rights
    JOIN control.workload_sessions session ON session.id = rights.workload_session_id
    WHERE session.expires_at < sqlc.arg(before_time) AND session.lease_expires_at < sqlc.arg(before_time)
      AND (session.revoked_at IS NULL OR session.revoked_at < sqlc.arg(before_time))
      AND to_timestamp((session.claims->>'exp')::double precision) < sqlc.arg(before_time)
      AND NOT EXISTS (SELECT 1 FROM control.workload_assertions child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_audit child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_ingress_requests child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_client_certificates child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.connector_sessions child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.visitor_certificate_facts child WHERE child.workload_session_id = session.id)
    ORDER BY session.expires_at, rights.workload_session_id, rights.service_id LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF rights SKIP LOCKED
);

-- name: CleanupWorkloadSessions :execrows
DELETE FROM control.workload_sessions WHERE id IN (
    SELECT session.id FROM control.workload_sessions session
    WHERE session.expires_at < sqlc.arg(before_time) AND session.lease_expires_at < sqlc.arg(before_time)
      AND (session.revoked_at IS NULL OR session.revoked_at < sqlc.arg(before_time))
      AND to_timestamp((session.claims->>'exp')::double precision) < sqlc.arg(before_time)
      AND NOT EXISTS (SELECT 1 FROM control.workload_session_services child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_assertions child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_audit child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_ingress_requests child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.workload_client_certificates child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.connector_sessions child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.visitor_certificate_facts child WHERE child.workload_session_id = session.id)
    ORDER BY session.expires_at, session.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);
