-- name: GetIngressPool :one
SELECT * FROM control.ingress_pools WHERE id = sqlc.arg(id);
