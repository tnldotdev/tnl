-- name: FlushChangePublications :exec
-- finish shared projection waits before the caller's final authorization check.
SET CONSTRAINTS ALL IMMEDIATE;
