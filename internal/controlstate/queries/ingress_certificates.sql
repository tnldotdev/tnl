-- name: LockIngressTransportIssuer :one
SELECT * FROM control.ingress_transport_issuers ORDER BY revision DESC LIMIT 1 FOR UPDATE;

-- name: NextIngressTransportIssuerRevision :one
SELECT nextval(pg_get_serial_sequence('control.ingress_transport_issuers','revision'))::bigint;

-- name: InsertIngressTransportIssuer :one
INSERT INTO control.ingress_transport_issuers(revision,certificate_pem,private_key_ciphertext,storage_key_id,created_at,not_after)
OVERRIDING SYSTEM VALUE VALUES(sqlc.arg(revision),sqlc.arg(certificate_pem),sqlc.arg(private_key_ciphertext),sqlc.arg(storage_key_id),sqlc.arg(now),sqlc.arg(not_after)) RETURNING *;

-- name: ListIngressTransportIssuerCertificates :many
SELECT certificate_pem FROM control.ingress_transport_issuers WHERE not_after>sqlc.arg(now) ORDER BY revision DESC LIMIT 2;

-- name: LockIngressTransportCertificate :one
SELECT * FROM control.ingress_transport_certificates WHERE ingress_id=sqlc.arg(ingress_id) AND ingress_run_id=sqlc.arg(ingress_run_id)
    AND ingress_lease_revision=sqlc.arg(ingress_lease_revision) AND tls_server_name=sqlc.arg(tls_server_name) FOR UPDATE;

-- name: StoreIngressTransportCertificate :one
INSERT INTO control.ingress_transport_certificates(ingress_id,ingress_run_id,ingress_lease_revision,tls_server_name,issuer_revision,
    certificate_pem,private_key_ciphertext,storage_key_id,public_key_sha256,not_before,not_after)
VALUES(sqlc.arg(ingress_id),sqlc.arg(ingress_run_id),sqlc.arg(ingress_lease_revision),sqlc.arg(tls_server_name),sqlc.arg(issuer_revision),
    sqlc.arg(certificate_pem),sqlc.arg(private_key_ciphertext),sqlc.arg(storage_key_id),sqlc.arg(public_key_sha256),sqlc.arg(not_before),sqlc.arg(not_after))
ON CONFLICT(ingress_id,ingress_run_id,ingress_lease_revision,tls_server_name) DO UPDATE SET issuer_revision=EXCLUDED.issuer_revision,
    certificate_pem=EXCLUDED.certificate_pem,private_key_ciphertext=EXCLUDED.private_key_ciphertext,storage_key_id=EXCLUDED.storage_key_id,
    public_key_sha256=EXCLUDED.public_key_sha256,not_before=EXCLUDED.not_before,not_after=EXCLUDED.not_after RETURNING *;
