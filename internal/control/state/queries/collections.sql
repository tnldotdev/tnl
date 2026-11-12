-- name: CreateCollection :one
INSERT INTO control.collections(id,team_id,project_key,name,default_definition_revision,initial_default_definition_revision,mutation_revision,created_by_identity_id,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,$5,1,$6,$7,$7) RETURNING *;

-- name: GetCollection :one
SELECT * FROM control.collections WHERE team_id=$1 AND project_key=$2 AND id=$3;

-- name: LockCollection :one
SELECT * FROM control.collections WHERE team_id=$1 AND project_key=$2 AND id=$3 FOR UPDATE;

-- name: GetCollectionByName :one
SELECT * FROM control.collections WHERE team_id=$1 AND project_key=$2 AND name=$3;

-- name: ListCollections :many
SELECT * FROM control.collections WHERE team_id=$1 AND project_key=$2 ORDER BY id;

-- name: UpdateCollectionDefault :one
UPDATE control.collections SET default_definition_revision=$4,mutation_revision=mutation_revision+1,updated_at=$5
WHERE team_id=$1 AND project_key=$2 AND id=$3 AND mutation_revision=$6 RETURNING *;
