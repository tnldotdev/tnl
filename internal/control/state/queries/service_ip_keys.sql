-- name: ReadServiceIPKey :one
SELECT key_ciphertext, storage_key_id FROM control.service_ip_keys
WHERE service_id=sqlc.arg(service_id) AND purpose=sqlc.arg(purpose);

-- name: CreateServiceIPKey :exec
INSERT INTO control.service_ip_keys(service_id,purpose,key_ciphertext,storage_key_id)
VALUES(sqlc.arg(service_id),sqlc.arg(purpose),sqlc.arg(key_ciphertext),sqlc.arg(storage_key_id))
ON CONFLICT(service_id,purpose) DO NOTHING;
