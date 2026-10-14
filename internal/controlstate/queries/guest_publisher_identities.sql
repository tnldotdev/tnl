-- name: InsertGuestPublisherIdentity :exec
INSERT INTO control.guest_publisher_identities (publisher_identity_id, guest_id, created_at)
VALUES (sqlc.arg(publisher_identity_id), sqlc.arg(guest_id), sqlc.arg(created_at));

-- name: GuestForPublisherIdentity :one
SELECT guest.id, guest.team_id, guest.membership_id, guest.domain_id, guest.namespace_label, domain.canonical_domain,
    guest.expires_at, guest.used_ready_ns, guest.used_bytes
FROM control.guest_publisher_identities AS publisher
JOIN control.guest_trials AS guest ON guest.id = publisher.guest_id
JOIN control.domains AS domain ON domain.id = guest.domain_id AND domain.kind = 'managed' AND domain.state = 'ready'
WHERE publisher.publisher_identity_id = sqlc.arg(publisher_identity_id);
