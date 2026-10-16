-- caller locks the public URL and current run before creating an attempt.
-- source_ip and session digest come from the trusted publisher connection,
-- never from a browser or the eight-character code.
-- name: InsertSSHAttempt :one
INSERT INTO control.ssh_attempts
    (id, code_digest, publisher_proof_digest, public_url_id, publish_run_id,
     publish_run_number, visitor_connection_id, source_ip, ssh_user, ssh_session_digest,
     state, created_at, expires_at)
SELECT sqlc.arg(id), sqlc.arg(code_digest), sqlc.arg(publisher_proof_digest),
       run.public_url_id, run.id, run.publish_run_number,
       sqlc.arg(visitor_connection_id), sqlc.arg(source_ip)::inet, sqlc.arg(ssh_user),
       sqlc.arg(ssh_session_digest), 'pending', sqlc.arg(created_at), sqlc.arg(expires_at)
FROM control.publish_runs AS run
JOIN control.public_urls AS url ON url.id = run.public_url_id
WHERE run.id = sqlc.arg(publish_run_id) AND run.publish_run_number = sqlc.arg(publish_run_number)
  AND run.closed_at IS NULL AND run.state = 'ready' AND run.publisher_expires_at > sqlc.arg(created_at)
  AND url.service_protocol = 'ssh' AND url.lifecycle_state = 'enabled' AND url.public_port IS NOT NULL
  AND (SELECT count(*) FROM control.ssh_attempts AS active
       WHERE active.publish_run_id = run.id AND active.state IN ('pending', 'approved')
         AND active.expires_at > sqlc.arg(created_at)) < 128
RETURNING *;

-- only an authenticated control-host identity can inspect or decide. code
-- lookup reveals no proof and grants no access to the SSH connection.
-- name: LookupSSHAttemptForBrowser :one
SELECT attempt.id, attempt.public_url_id, attempt.publish_run_id, attempt.publish_run_number,
       attempt.source_ip, attempt.ssh_user, attempt.state, attempt.expires_at
FROM control.ssh_attempts AS attempt
JOIN control.publish_runs AS run ON run.id = attempt.publish_run_id
JOIN control.public_urls AS url ON url.id = attempt.public_url_id
WHERE attempt.code_digest = sqlc.arg(code_digest) AND attempt.state = 'pending'
  AND attempt.expires_at > sqlc.arg(now) AND run.publish_run_number = attempt.publish_run_number
  AND run.closed_at IS NULL AND run.state = 'ready' AND run.publisher_expires_at > sqlc.arg(now)
  AND url.lifecycle_state = 'enabled' AND url.service_protocol = 'ssh';

-- control must check current SSH grant, requested OS account, and browser
-- identity under the team/URL lock before invoking this guarded transition.
-- name: ApproveSSHAttempt :one
UPDATE control.ssh_attempts AS attempt
SET state = 'approved', identity_id = sqlc.arg(identity_id), approved_at = sqlc.arg(now)
FROM control.publish_runs AS run, control.public_urls AS url
WHERE attempt.id = sqlc.arg(attempt_id) AND attempt.code_digest = sqlc.arg(code_digest)
  AND attempt.state = 'pending' AND attempt.expires_at > sqlc.arg(now)
  AND run.id = attempt.publish_run_id AND run.publish_run_number = attempt.publish_run_number
  AND run.closed_at IS NULL AND run.state = 'ready' AND run.publisher_expires_at > sqlc.arg(now)
  AND url.id = attempt.public_url_id AND url.service_protocol = 'ssh' AND url.lifecycle_state = 'enabled'
RETURNING attempt.*;

-- name: DenySSHAttempt :one
UPDATE control.ssh_attempts AS attempt
SET state = 'denied', identity_id = sqlc.arg(identity_id), denied_at = sqlc.arg(now)
FROM control.publish_runs AS run
WHERE attempt.id = sqlc.arg(attempt_id) AND attempt.code_digest = sqlc.arg(code_digest)
  AND attempt.state = 'pending' AND attempt.expires_at > sqlc.arg(now)
  AND run.id = attempt.publish_run_id AND run.publish_run_number = attempt.publish_run_number
  AND run.closed_at IS NULL
RETURNING attempt.*;

-- name: PollSSHAttempt :one
SELECT attempt.state, attempt.expires_at FROM control.ssh_attempts AS attempt
JOIN control.publish_runs AS run ON run.id = attempt.publish_run_id
WHERE attempt.id = sqlc.arg(attempt_id) AND attempt.publisher_proof_digest = sqlc.arg(publisher_proof_digest)
  AND attempt.publish_run_id = sqlc.arg(publish_run_id)
  AND attempt.publish_run_number = sqlc.arg(publish_run_number)
  AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
  AND attempt.expires_at > sqlc.arg(now);

-- claim verifies the original SSH session and source as well as the private
-- proof; a browser code alone can never start a stream.
-- name: ClaimSSHAttempt :one
UPDATE control.ssh_attempts AS attempt SET state = 'claimed', claimed_at = sqlc.arg(now)
FROM control.publish_runs AS run, control.public_urls AS url
WHERE attempt.id = sqlc.arg(attempt_id) AND attempt.publisher_proof_digest = sqlc.arg(publisher_proof_digest)
  AND attempt.ssh_session_digest = sqlc.arg(ssh_session_digest)
  AND attempt.visitor_connection_id = sqlc.arg(visitor_connection_id)
  AND attempt.source_ip = sqlc.arg(source_ip)::inet AND attempt.ssh_user = sqlc.arg(ssh_user)
  AND attempt.publish_run_id = sqlc.arg(publish_run_id)
  AND attempt.publish_run_number = sqlc.arg(publish_run_number)
  AND attempt.state = 'approved' AND attempt.expires_at > sqlc.arg(now)
  AND run.id = attempt.publish_run_id AND run.closed_at IS NULL AND run.state = 'ready'
  AND run.publisher_expires_at > sqlc.arg(now)
  AND url.id = attempt.public_url_id AND url.service_protocol = 'ssh' AND url.lifecycle_state = 'enabled'
RETURNING attempt.*;

-- name: CancelSSHAttempt :execrows
UPDATE control.ssh_attempts SET state = 'canceled', canceled_at = sqlc.arg(now)
WHERE id = sqlc.arg(attempt_id) AND publisher_proof_digest = sqlc.arg(publisher_proof_digest)
  AND publish_run_id = sqlc.arg(publish_run_id) AND publish_run_number = sqlc.arg(publish_run_number)
  AND state IN ('pending', 'approved');

-- name: CleanupSSHAttempts :exec
DELETE FROM control.ssh_attempts AS stored WHERE stored.id IN
    (SELECT expired.id FROM control.ssh_attempts AS expired WHERE expired.expires_at <= sqlc.arg(now) LIMIT 100);
