-- name: InsertPrivateCertificateOrder :one
INSERT INTO control.acme_orders(id,account_id,private_run_id,private_service_id,private_run_number,
    idempotency_key,request_digest,certificate_cache_key,certificate_scope,certificate_domain_id,certificate_identifiers,
    challenge_method,csr_der,csr_digest,state,available_at,created_at,updated_at)
SELECT sqlc.arg(id),sqlc.arg(account_id),run.id,run.private_service_id,run.run_number,
    sqlc.arg(idempotency_key),sqlc.arg(request_digest),run.certificate_cache_key,run.certificate_scope,run.certificate_domain_id,run.certificate_identifiers,
    'dns-01',sqlc.arg(csr_der),sqlc.arg(csr_digest),'pending',sqlc.arg(now),sqlc.arg(now),sqlc.arg(now)
FROM control.private_service_runs run
JOIN control.private_services service ON service.id=run.private_service_id
WHERE run.id=sqlc.arg(private_run_id) AND run.closed_at IS NULL AND cardinality(run.certificate_identifiers)>0
RETURNING *;

-- name: GetPrivateCertificateRequest :one
SELECT * FROM control.private_certificate_requests
WHERE private_run_id=sqlc.arg(private_run_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: InsertPrivateCertificateRequest :exec
INSERT INTO control.private_certificate_requests(private_run_id,idempotency_key,request_digest,issuance_id)
VALUES(sqlc.arg(private_run_id),sqlc.arg(idempotency_key),sqlc.arg(request_digest),sqlc.arg(issuance_id));

-- name: GetPrivateCertificateOrderByCSR :one
SELECT issuance.* FROM control.acme_orders issuance
JOIN control.private_service_runs source ON source.id=issuance.private_run_id
WHERE source.publisher_identity_id=sqlc.arg(publisher_identity_id)
    AND issuance.account_id=sqlc.arg(account_id) AND issuance.csr_digest=sqlc.arg(csr_digest)
    AND issuance.certificate_cache_key=sqlc.arg(certificate_cache_key) AND issuance.certificate_scope=sqlc.arg(certificate_scope)
    AND issuance.certificate_identifiers=sqlc.arg(certificate_identifiers) AND issuance.certificate_domain_id=sqlc.arg(domain_id)
ORDER BY issuance.created_revision DESC LIMIT 1;

-- name: GetPrivateDNSChallengeContext :one
SELECT service.id AS private_service_id,service.team_id,orders.certificate_domain_id AS domain_id,
    domain.dns_authority_reference,orders.certificate_scope AS canonical_hostname,
    domain.canonical_domain,auth.id AS authorization_id,auth.identifier,
    auth.challenge_digest,auth.presentation_reference,auth.state
FROM control.acme_authorizations auth
JOIN control.acme_orders orders ON orders.id=auth.order_id
JOIN control.private_services service ON service.id=orders.private_service_id
JOIN control.domains domain ON domain.id=orders.certificate_domain_id
WHERE service.id=sqlc.arg(private_service_id) AND auth.id=sqlc.arg(authorization_id)
    AND auth.challenge_type='dns-01';
