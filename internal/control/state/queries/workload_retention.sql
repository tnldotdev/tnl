-- each phase has its own budget so a busy leaf cannot starve its parents.
-- select only unreferenced candidates before LIMIT; never cascade subject state.

-- name: CleanupWorkloadDirectVisitors :execrows
DELETE FROM control.direct_service_visitors WHERE visitor_connection_id IN (
    SELECT visitor.visitor_connection_id FROM control.direct_service_visitors visitor
    WHERE visitor.workload_session_id IS NOT NULL
      AND (visitor.valid_until < sqlc.arg(before_time) OR visitor.closed_at < sqlc.arg(before_time))
    ORDER BY visitor.valid_until, visitor.visitor_connection_id LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupWorkloadCertificates :execrows
DELETE FROM control.workload_client_certificates WHERE certificate_digest IN (
    SELECT cert.certificate_digest FROM control.workload_client_certificates cert
    WHERE cert.expires_at < sqlc.arg(before_time)
      AND NOT EXISTS (SELECT 1 FROM control.direct_service_visitors visitor WHERE visitor.certificate_digest = cert.certificate_digest)
    ORDER BY cert.expires_at, cert.certificate_digest LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
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
      AND NOT EXISTS (SELECT 1 FROM control.workload_client_certificates child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.direct_service_visitors child WHERE child.workload_session_id = session.id)
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
      AND NOT EXISTS (SELECT 1 FROM control.workload_client_certificates child WHERE child.workload_session_id = session.id)
      AND NOT EXISTS (SELECT 1 FROM control.direct_service_visitors child WHERE child.workload_session_id = session.id)
    ORDER BY session.expires_at, session.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);
