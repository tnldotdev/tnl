-- name: DeleteObsoleteRouteSessions :execrows
DELETE FROM route_sessions
WHERE id IN (
    SELECT session.id
    FROM route_sessions AS session
    JOIN routes AS route ON route.id = session.route_id
    WHERE session.status = 'expired'
		AND (session.route_version < route.route_version OR route.status = 'deleted')
    ORDER BY session.expires_at, session.id
    LIMIT sqlc.arg(batch_size)
);

-- name: DeleteObsoleteRouteAllowedIPPrefixes :execrows
DELETE FROM route_allowed_ip_prefixes
WHERE (route_id, route_version, position) IN (
    SELECT prefix.route_id, prefix.route_version, prefix.position
    FROM route_allowed_ip_prefixes AS prefix
    JOIN routes AS route ON route.id = prefix.route_id
	WHERE prefix.route_version < route.route_version OR route.status = 'deleted'
    ORDER BY prefix.route_id, prefix.route_version, prefix.position
    LIMIT sqlc.arg(batch_size)
);

-- name: DeleteExpiredRouteAuthorizationUses :execrows
DELETE FROM route_authorization_uses
WHERE (authorization_issuer, authorization_id) IN (
    SELECT use.authorization_issuer, use.authorization_id
    FROM route_authorization_uses AS use
    WHERE use.authorization_expires_at <= sqlc.arg(now)
    ORDER BY use.authorization_expires_at, use.created_at, use.authorization_issuer, use.authorization_id
    LIMIT sqlc.arg(batch_size)
);

-- name: DeleteObsoleteCertificateIssuances :execrows
DELETE FROM certificate_issuances
WHERE id IN (
    SELECT issuance.id
    FROM certificate_issuances AS issuance
    JOIN routes AS route ON route.id = issuance.route_id
    WHERE (
        issuance.status = 'failed'
            AND issuance.updated_at <= sqlc.arg(attempt_cutoff)
        OR issuance.status IN ('waiting_for_install', 'installed')
            AND issuance.not_after IS NOT NULL
            AND issuance.not_after <= CAST(sqlc.arg(now) AS INTEGER)
        OR issuance.certificate_pem IS NULL
            AND issuance.status NOT IN ('installed', 'failed')
            AND issuance.order_expires_at IS NOT NULL
            AND issuance.order_expires_at <= CAST(sqlc.arg(now) AS INTEGER)
		OR issuance.route_version < route.route_version
            AND issuance.certificate_pem IS NULL
            AND issuance.updated_at <= sqlc.arg(retention_cutoff)
    )
        AND NOT (
            issuance.order_started_at IS NOT NULL
            AND issuance.order_started_at >= sqlc.arg(attempt_cutoff)
        )
    ORDER BY issuance.updated_at, issuance.id
    LIMIT sqlc.arg(batch_size)
);

-- name: DeleteObsoleteDeletedRouteUsageSnapshots :execrows
DELETE FROM route_usage_snapshots
WHERE id IN (
    SELECT snapshot.id
    FROM route_usage_snapshots AS snapshot
    JOIN routes AS route ON route.id = snapshot.route_id
    WHERE route.status = 'deleted'
        AND route.deleted_at <= CAST(sqlc.arg(cutoff) AS INTEGER)
        AND NOT EXISTS (
            SELECT 1
            FROM route_usage_outbox_items AS outbox
			WHERE outbox.source_kind = 'usage_bucket_report'
                AND outbox.source_id = snapshot.id
        )
    ORDER BY snapshot.bucket_start, snapshot.id
    LIMIT sqlc.arg(batch_size)
);

-- name: DeleteObsoleteRouteRegistrations :execrows
DELETE FROM route_registrations
WHERE id IN (
    SELECT registration.id
    FROM route_registrations AS registration
    JOIN routes AS route ON route.id = registration.route_id
    WHERE route.status = 'deleted'
        AND route.deleted_at <= CAST(sqlc.arg(cutoff) AS INTEGER)
        AND registration.acknowledged_revision = registration.revision
        AND NOT EXISTS (
            SELECT 1
            FROM route_usage_outbox_items AS outbox
            WHERE outbox.source_kind = 'registration'
                AND outbox.source_id = registration.id
        )
        AND NOT EXISTS (
            SELECT 1 FROM route_lifecycle_events AS event
            WHERE event.route_id = route.id
        )
        AND NOT EXISTS (
            SELECT 1 FROM route_usage_snapshots AS snapshot
            WHERE snapshot.route_id = route.id
        )
    ORDER BY registration.created_at, registration.id
    LIMIT sqlc.arg(batch_size)
);

-- name: DeleteObsoleteDeletedRoutes :execrows
DELETE FROM routes
WHERE id IN (
    SELECT route.id
    FROM routes AS route
    WHERE route.status = 'deleted'
        AND route.deleted_at <= CAST(sqlc.arg(cutoff) AS INTEGER)
        AND NOT EXISTS (
            SELECT 1 FROM route_authorization_uses AS authorization
            WHERE authorization.route_id = route.id
        )
        AND NOT EXISTS (
            SELECT 1 FROM route_registrations AS registration
            WHERE registration.route_id = route.id
        )
        AND NOT EXISTS (
            SELECT 1 FROM route_lifecycle_events AS event
            WHERE event.route_id = route.id
        )
        AND NOT EXISTS (
            SELECT 1 FROM route_usage_snapshots AS snapshot
            WHERE snapshot.route_id = route.id
        )
    ORDER BY route.deleted_at, route.id
    LIMIT sqlc.arg(batch_size)
);
