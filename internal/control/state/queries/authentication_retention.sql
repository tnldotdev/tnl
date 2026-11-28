-- replay records remain until their assertions cannot be accepted. workers use
-- short independent transactions and skip claims another transaction still owns.
-- name: CleanupPublisherAssertions :execrows
WITH expired AS (
    SELECT a.publisher_identity_id,a.assertion_id FROM control.publisher_assertions a
    WHERE a.expires_at<=sqlc.arg(now) ORDER BY a.expires_at,a.publisher_identity_id,a.assertion_id
    LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
)
DELETE FROM control.publisher_assertions AS assertion USING expired
WHERE assertion.publisher_identity_id=expired.publisher_identity_id AND assertion.assertion_id=expired.assertion_id;

-- name: CleanupPublisherAccess :execrows
WITH expired AS (
    SELECT token.access_token_digest FROM control.publisher_access_tokens token
    WHERE token.expires_at<=sqlc.arg(now) ORDER BY token.expires_at,token.access_token_digest
    LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
)
DELETE FROM control.publisher_access_tokens WHERE access_token_digest IN (SELECT access_token_digest FROM expired);

-- name: CleanupCompanyLoginIntents :execrows
WITH expired AS (
    SELECT intent.id FROM control.company_login_intents intent
    WHERE intent.expires_at<=sqlc.arg(now) ORDER BY intent.expires_at,intent.id
    LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
)
DELETE FROM control.company_login_intents WHERE id IN (SELECT id FROM expired);

-- name: CleanupOIDCAssertions :execrows
WITH expired AS (
    SELECT assertion.assertion_digest FROM control.oidc_assertion_exchanges assertion
    WHERE assertion.expires_at<=sqlc.arg(now) ORDER BY assertion.expires_at,assertion.assertion_digest
    LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
)
DELETE FROM control.oidc_assertion_exchanges WHERE assertion_digest IN (SELECT assertion_digest FROM expired);
