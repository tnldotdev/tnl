-- name: InsertServiceCertificateOrder :one
INSERT INTO control.acme_orders(id,account_id,service_run_id,service_id,service_run_number,
    idempotency_key,request_digest,certificate_cache_key,certificate_scope,certificate_domain_id,certificate_identifiers,
    challenge_method,csr_der,csr_digest,state,available_at,created_at,updated_at)
SELECT sqlc.arg(id),sqlc.arg(account_id),run.id,run.service_id,run.run_number,
    sqlc.arg(idempotency_key),sqlc.arg(request_digest),run.certificate_cache_key,run.certificate_scope,run.certificate_domain_id,run.certificate_identifiers,
    'dns-01',sqlc.arg(csr_der),sqlc.arg(csr_digest),'pending',sqlc.arg(now),sqlc.arg(now),sqlc.arg(now)
FROM control.service_runs run
JOIN control.services service ON service.id=run.service_id
WHERE run.id=sqlc.arg(service_run_id) AND run.closed_at IS NULL AND cardinality(run.certificate_identifiers)>0
RETURNING *;

-- name: ListPublisherCertificateCheckpoints :many
SELECT certificate_plan FROM control.publisher_certificate_checkpoints
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id)
ORDER BY plan_digest LIMIT 1025;

-- name: GetServiceCertificateRequest :one
SELECT * FROM control.service_certificate_requests
WHERE service_run_id=sqlc.arg(service_run_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: InsertServiceCertificateRequest :exec
INSERT INTO control.service_certificate_requests(service_run_id,idempotency_key,request_digest,issuance_id)
VALUES(sqlc.arg(service_run_id),sqlc.arg(idempotency_key),sqlc.arg(request_digest),sqlc.arg(issuance_id));

-- name: GetServiceCertificateOrderByCSR :one
SELECT issuance.* FROM control.acme_orders issuance
JOIN control.service_runs source ON source.id=issuance.service_run_id
WHERE source.publisher_identity_id=sqlc.arg(publisher_identity_id)
    AND issuance.account_id=sqlc.arg(account_id) AND issuance.csr_digest=sqlc.arg(csr_digest)
    AND issuance.certificate_cache_key=sqlc.arg(certificate_cache_key) AND issuance.certificate_scope=sqlc.arg(certificate_scope)
    AND issuance.certificate_identifiers=sqlc.arg(certificate_identifiers) AND issuance.certificate_domain_id=sqlc.arg(domain_id)
ORDER BY issuance.created_revision DESC LIMIT 1;

-- name: GetPrivateDNSChallengeContext :one
SELECT service.id AS service_id,service.team_id,orders.certificate_domain_id AS domain_id,
    domain.dns_authority_reference,orders.certificate_scope AS canonical_hostname,
    domain.canonical_domain,auth.id AS authorization_id,auth.identifier,
    auth.challenge_digest,auth.presentation_reference,auth.state
FROM control.acme_authorizations auth
JOIN control.acme_orders orders ON orders.id=auth.order_id
JOIN control.services service ON service.id=orders.service_id
JOIN control.domains domain ON domain.id=orders.certificate_domain_id
WHERE service.id=sqlc.arg(service_id) AND auth.id=sqlc.arg(authorization_id)
    AND auth.challenge_type='dns-01';
