-- +goose Up
ALTER TABLE hostname_claims ADD COLUMN kind TEXT NOT NULL DEFAULT 'persistent_managed'
    CHECK (kind IN ('reserved', 'persistent_managed', 'persistent_custom_domain', 'ephemeral'));
ALTER TABLE hostname_claims ADD COLUMN state TEXT NOT NULL DEFAULT 'active'
    CHECK (state IN ('reserved', 'held', 'pending_dns', 'active', 'dns_unready', 'released_owned', 'released', 'burned', 'quarantined'));
ALTER TABLE hostname_claims ADD COLUMN source TEXT NOT NULL DEFAULT 'custom'
    CHECK (source IN ('configured', 'generated', 'custom'));
ALTER TABLE hostname_claims ADD COLUMN activated_at INTEGER;
ALTER TABLE hostname_claims ADD COLUMN released_at INTEGER;
ALTER TABLE hostname_claims ADD COLUMN route_binding TEXT;
ALTER TABLE hostname_claims ADD COLUMN reason TEXT;

UPDATE hostname_claims
SET state = CASE WHEN tombstoned_at IS NULL THEN 'active' ELSE 'released_owned' END,
    activated_at = CASE WHEN tombstoned_at IS NULL THEN created_at ELSE NULL END,
    released_at = tombstoned_at;

ALTER TABLE hostname_claim_requests ADD COLUMN requested_kind TEXT NOT NULL DEFAULT 'persistent_managed'
    CHECK (requested_kind IN ('persistent_managed', 'ephemeral'));

DROP INDEX hostname_claims_principal_active;
CREATE INDEX hostname_claims_principal_active
    ON hostname_claims (principal_id, created_at, id)
    WHERE kind IN ('persistent_managed', 'persistent_custom_domain')
        AND state IN ('active', 'released_owned');
CREATE INDEX hostname_claims_ephemeral_cleanup
    ON hostname_claims (state, created_at)
    WHERE kind = 'ephemeral';
CREATE INDEX hostname_claims_friendly_capacity
    ON hostname_claims (kind)
    WHERE kind IN ('persistent_managed', 'ephemeral');

CREATE TABLE domain_claim_challenges (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    request_key TEXT NOT NULL,
    domain TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    verification_target TEXT NOT NULL UNIQUE,
    is_apex INTEGER NOT NULL CHECK (is_apex IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('pending_dns', 'verified', 'invalidated')),
    claim_id TEXT REFERENCES hostname_claims(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    verified_at INTEGER,
    invalidated_at INTEGER,
    UNIQUE (principal_id, request_key)
) STRICT;

CREATE INDEX domain_claim_challenges_principal
    ON domain_claim_challenges (principal_id, created_at, id);
CREATE INDEX domain_claim_challenges_pending_domain
    ON domain_claim_challenges (domain)
    WHERE state = 'pending_dns';
