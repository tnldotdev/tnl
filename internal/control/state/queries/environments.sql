-- name: LockEnvironment :one
SELECT * FROM control.environments WHERE team_id=$1 AND project_key=$2 AND id=$3 FOR UPDATE;

-- name: GetEnvironment :one
SELECT * FROM control.environments WHERE team_id=$1 AND project_key=$2 AND id=$3;

-- name: ListEnvironments :many
SELECT * FROM control.environments WHERE team_id=$1 AND project_key=$2 ORDER BY id;

-- name: GetEnvironmentForGroup :one
SELECT environment.* FROM control.project_publisher_groups publisher_group
JOIN control.environments environment ON environment.id=publisher_group.environment_id
    AND environment.group_id=publisher_group.id
    AND environment.team_id=publisher_group.team_id AND environment.project_key=publisher_group.project_key
WHERE publisher_group.id=$1;

-- name: ReadServiceDefinition :one
SELECT * FROM control.service_definitions WHERE team_id=$1 AND project_key=$2 AND revision=$3;

-- name: GetEnvironmentPublisherGroup :one
SELECT * FROM control.project_publisher_groups WHERE id=$1;

-- name: PublisherGroupEnvironmentOwnership :one
SELECT publisher_group.environment_id AS forward_environment_id,environment.id AS reverse_environment_id
FROM control.project_publisher_groups publisher_group
LEFT JOIN control.environments environment ON environment.group_id=publisher_group.id
WHERE publisher_group.id=$1;

-- name: ServicePublisherGroup :one
SELECT group_id FROM control.applied_project_services WHERE service_id=$1;
