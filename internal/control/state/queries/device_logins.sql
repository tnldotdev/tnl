-- name: LockDeviceLoginCapacity :exec
SELECT pg_advisory_xact_lock(837174137711267954);

-- name: InsertDeviceLogin :execrows
INSERT INTO control.device_logins (credential_digest, user_code, expires_at, payload, storage_key_id)
SELECT sqlc.arg(credential_digest), sqlc.arg(user_code), sqlc.arg(expires_at), sqlc.arg(payload), sqlc.arg(storage_key_id)
WHERE (SELECT count(*) FROM control.device_logins) < 4096;

-- name: LockDeviceLoginByCredential :one
SELECT * FROM control.device_logins WHERE credential_digest = sqlc.arg(credential_digest) FOR UPDATE;

-- name: LockDeviceLoginByCode :one
SELECT * FROM control.device_logins WHERE user_code = sqlc.arg(user_code) FOR UPDATE;

-- name: LockDeviceLoginByState :one
SELECT * FROM control.device_logins WHERE state_digest = sqlc.arg(state_digest) FOR UPDATE;

-- name: UpdateDeviceLogin :exec
UPDATE control.device_logins SET payload = sqlc.arg(payload), storage_key_id = sqlc.arg(storage_key_id), state_digest = sqlc.narg(state_digest)
WHERE credential_digest = sqlc.arg(credential_digest);

-- name: DeleteExpiredDeviceLogins :exec
DELETE FROM control.device_logins WHERE expires_at <= sqlc.arg(now);
