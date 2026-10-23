-- name: FindStreamCapacityAllocation :one
SELECT * FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND run_id=sqlc.arg(run_id)
    AND ingress_id=sqlc.arg(ingress_id) AND ingress_run_id=sqlc.arg(ingress_run_id) AND ingress_lease_revision=sqlc.arg(ingress_lease_revision)
    AND request_id=sqlc.arg(request_id) FOR UPDATE;

-- name: SumStreamCapacityAllocations :one
SELECT COALESCE(sum(capacity),0)::bigint FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND run_id=sqlc.arg(run_id) AND valid_until>sqlc.arg(now);

-- name: CountStreamCapacityAllocations :one
SELECT count(*) FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND valid_until>sqlc.arg(now);

-- name: CreateStreamCapacityAllocation :one
INSERT INTO control.stream_capacity_allocations(id,resource_kind,resource_id,run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,request_id,capacity,issued_at,renewed_at,valid_until)
VALUES(sqlc.arg(id),sqlc.arg(resource_kind),sqlc.arg(resource_id),sqlc.arg(run_id),sqlc.arg(run_number),sqlc.arg(ingress_id),sqlc.arg(ingress_run_id),sqlc.arg(ingress_lease_revision),sqlc.arg(request_id),sqlc.arg(capacity),sqlc.arg(now),sqlc.arg(now),sqlc.arg(valid_until)) RETURNING *;

-- name: RenewStreamCapacityAllocation :one
UPDATE control.stream_capacity_allocations SET renewed_at=sqlc.arg(now),valid_until=sqlc.arg(valid_until)
WHERE id=sqlc.arg(id) AND retired_at IS NULL AND valid_until>sqlc.arg(now) AND renewed_at<=sqlc.arg(now) RETURNING *;

-- name: RetireStreamCapacityAllocation :execrows
UPDATE control.stream_capacity_allocations SET retired_at=COALESCE(retired_at,sqlc.arg(now))
WHERE id=sqlc.arg(id) AND ingress_id=sqlc.arg(ingress_id) AND ingress_run_id=sqlc.arg(ingress_run_id) AND ingress_lease_revision=sqlc.arg(ingress_lease_revision);

-- name: ReadStreamCapacityAllocations :many
SELECT * FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND valid_until>sqlc.arg(now)
ORDER BY id LIMIT 2049;

-- name: ObservePublisherStreamAllocations :exec
UPDATE control.stream_capacity_allocations SET publisher_observed_at=sqlc.arg(now)
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id)
    AND run_id=sqlc.arg(run_id) AND run_number=sqlc.arg(run_number)
    AND id=ANY(sqlc.arg(ids)::text[]) AND retired_at IS NULL AND valid_until>sqlc.arg(now);
