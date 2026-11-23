-- name: LockServiceRunEndpoint :one
SELECT id, endpoint_revision, certificate_hostname, domain_id, ingress_pool_id, protocol,
       service_port, public, run_alias_parent
FROM control.services WHERE id=$1 AND enabled AND deleted_at IS NULL FOR SHARE;
