-- name: GetPendingPublisherEnrollment :one
SELECT * FROM pending_publisher_enrollments WHERE server_origin = sqlc.arg(server_origin) AND enrollment_id = sqlc.arg(enrollment_id);

-- name: PruneExpiredPendingPublisherEnrollments :exec
DELETE FROM pending_publisher_enrollments WHERE expires_at <= sqlc.arg(now);

-- name: GetPendingPublisherEnrollmentForSelection :one
SELECT * FROM pending_publisher_enrollments WHERE server_origin = sqlc.arg(server_origin)
  AND selection_kind = sqlc.arg(selection_kind) AND selection_key = sqlc.arg(selection_key);

-- name: SavePendingPublisherEnrollment :exec
INSERT INTO pending_publisher_enrollments
    (server_origin, enrollment_id, selection_kind, selection_key, public_key, signing_key_ciphertext,
     enrollment_secret_ciphertext, result_json, expires_at, updated_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(enrollment_id), sqlc.arg(selection_kind), sqlc.arg(selection_key),
    sqlc.arg(public_key), sqlc.arg(signing_key_ciphertext), sqlc.narg(enrollment_secret_ciphertext),
    sqlc.narg(result_json), sqlc.arg(expires_at), sqlc.arg(updated_at))
ON CONFLICT (server_origin, enrollment_id) DO UPDATE SET
    result_json = coalesce(excluded.result_json, pending_publisher_enrollments.result_json),
    updated_at = excluded.updated_at
WHERE pending_publisher_enrollments.public_key = excluded.public_key
  AND pending_publisher_enrollments.selection_kind = excluded.selection_kind
  AND pending_publisher_enrollments.selection_key = excluded.selection_key;

-- name: DeletePendingPublisherEnrollment :exec
DELETE FROM pending_publisher_enrollments WHERE server_origin = sqlc.arg(server_origin) AND enrollment_id = sqlc.arg(enrollment_id);

-- name: RecordPublisherEnrollmentResult :execrows
UPDATE pending_publisher_enrollments SET result_json = sqlc.arg(result_json), updated_at = sqlc.arg(updated_at)
WHERE server_origin = sqlc.arg(server_origin) AND enrollment_id = sqlc.arg(enrollment_id)
  AND (result_json IS NULL OR result_json = sqlc.arg(result_json));

-- name: GetPublisherIdentity :one
SELECT * FROM publisher_identities WHERE server_origin = sqlc.arg(server_origin) AND identity_id = sqlc.arg(identity_id);

-- name: SavePublisherIdentity :exec
INSERT INTO publisher_identities (server_origin, identity_id, public_document_json, signing_key_ciphertext, updated_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(identity_id), sqlc.arg(public_document_json),
    sqlc.arg(signing_key_ciphertext), sqlc.arg(updated_at))
ON CONFLICT (server_origin, identity_id) DO NOTHING;

-- name: SelectPublisherIdentity :exec
INSERT INTO publisher_selections (server_origin, selection_kind, selection_key, identity_id, updated_at, expires_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(selection_kind), sqlc.arg(selection_key),
    sqlc.arg(identity_id), sqlc.arg(updated_at), sqlc.narg(expires_at))
ON CONFLICT (server_origin, selection_kind, selection_key) DO UPDATE SET
    identity_id = excluded.identity_id, updated_at = excluded.updated_at,
    expires_at = excluded.expires_at;

-- name: PruneExpiredPublisherEnrollmentSelections :exec
DELETE FROM publisher_selections WHERE selection_kind = 'enrollment' AND expires_at <= sqlc.arg(now);

-- name: GetSelectedPublisherIdentity :one
SELECT identity.* FROM publisher_selections selection
JOIN publisher_identities identity ON identity.server_origin = selection.server_origin AND identity.identity_id = selection.identity_id
WHERE selection.server_origin = sqlc.arg(server_origin)
  AND selection.selection_kind = sqlc.arg(selection_kind) AND selection.selection_key = sqlc.arg(selection_key)
  AND (selection.selection_kind <> 'enrollment' OR selection.expires_at > sqlc.arg(now));

-- name: DeletePublisherIdentity :exec
DELETE FROM publisher_identities WHERE server_origin = sqlc.arg(server_origin) AND identity_id = sqlc.arg(identity_id);

-- name: DeletePublisherSelection :exec
DELETE FROM publisher_selections WHERE server_origin = sqlc.arg(server_origin)
  AND selection_kind = sqlc.arg(selection_kind) AND selection_key = sqlc.arg(selection_key);

-- name: GetPublisherJobRegistry :one
SELECT jobs_ciphertext FROM publisher_job_registry WHERE id = 1;

-- name: DeletePublisherJobRegistry :exec
DELETE FROM publisher_job_registry WHERE id = 1;

-- name: SavePublisherJobRegistry :exec
INSERT INTO publisher_job_registry (id, jobs_ciphertext, updated_at) VALUES (1, sqlc.arg(jobs_ciphertext), sqlc.arg(updated_at))
ON CONFLICT (id) DO UPDATE SET jobs_ciphertext = excluded.jobs_ciphertext, updated_at = excluded.updated_at;

-- name: GetPublisherJobFileManifest :one
SELECT manifest_ciphertext FROM publisher_job_file_manifest WHERE id = 1;

-- name: DeletePublisherJobFileManifest :exec
DELETE FROM publisher_job_file_manifest WHERE id = 1;

-- name: SavePublisherJobFileManifest :exec
INSERT INTO publisher_job_file_manifest (id, manifest_ciphertext, updated_at) VALUES (1, sqlc.arg(manifest_ciphertext), sqlc.arg(updated_at))
ON CONFLICT (id) DO UPDATE SET manifest_ciphertext = excluded.manifest_ciphertext, updated_at = excluded.updated_at;
