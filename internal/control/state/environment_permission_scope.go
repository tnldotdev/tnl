package state

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// a permission selects exact environments or one saved collection. collection
// grants explicitly choose whether later members are included; service names
// remain a separate, fixed allowlist in either case.
type EnvironmentPermissionScope struct {
	EnvironmentIDs            []string `json:"environment_ids,omitempty"`
	CollectionID              string   `json:"collection_id,omitempty"`
	IncludeFutureEnvironments *bool    `json:"include_future_environments,omitempty"`
}

func normalizeEnvironmentPermissionScope(input EnvironmentPermissionScope) (EnvironmentPermissionScope, error) {
	if input.CollectionID != "" {
		if !opaqueid.Valid(input.CollectionID, opaqueid.CollectionPrefix) || input.IncludeFutureEnvironments == nil || len(input.EnvironmentIDs) != 0 {
			return EnvironmentPermissionScope{}, ErrEnvironmentInvalid
		}
		return EnvironmentPermissionScope{CollectionID: input.CollectionID, IncludeFutureEnvironments: new(*input.IncludeFutureEnvironments)}, nil
	}
	if input.IncludeFutureEnvironments != nil || len(input.EnvironmentIDs) == 0 || len(input.EnvironmentIDs) > 1024 {
		return EnvironmentPermissionScope{}, ErrEnvironmentInvalid
	}
	ids := slices.Clone(input.EnvironmentIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if !opaqueid.Valid(id, opaqueid.EnvironmentPrefix) || i > 0 && ids[i-1] == id {
			return EnvironmentPermissionScope{}, ErrEnvironmentInvalid
		}
	}
	return EnvironmentPermissionScope{EnvironmentIDs: ids}, nil
}

func normalizeEnvironmentPermissionServices(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > 128 {
		return nil, ErrEnvironmentInvalid
	}
	names := slices.Clone(input)
	slices.Sort(names)
	for i, name := range names {
		if !naming.ValidServiceName(name) || i > 0 && names[i-1] == name {
			return nil, ErrEnvironmentInvalid
		}
	}
	return names, nil
}

// the caller holds the team and project guards. a fixed collection grant saves
// its initial members once; membership is still checked on every later use.
func captureEnvironmentPermissionScope(ctx context.Context, tx pgx.Tx, team, project string, scope EnvironmentPermissionScope) ([]string, error) {
	q := controlstatedb.New(tx)
	if scope.CollectionID == "" {
		for _, id := range scope.EnvironmentIDs {
			row, err := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: team, ProjectKey: project, ID: id})
			if err != nil {
				return nil, publisherLookupError(err, ErrMachineDenied)
			}
			if row.RetiredAt.Valid {
				return nil, ErrMachineDenied
			}
		}
		return slices.Clone(scope.EnvironmentIDs), nil
	}
	if _, err := q.LockCollection(ctx, controlstatedb.LockCollectionParams{TeamID: team, ProjectKey: project, ID: scope.CollectionID}); err != nil {
		return nil, publisherLookupError(err, ErrMachineDenied)
	}
	if *scope.IncludeFutureEnvironments {
		return []string{}, nil
	}
	rows, err := tx.Query(ctx, `SELECT id FROM control.environments WHERE team_id=$1 AND project_key=$2 AND collection_id=$3 AND retired_at IS NULL ORDER BY id`, team, project, scope.CollectionID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func checkEnvironmentPermissionScope(ctx context.Context, tx pgx.Tx, team, project, environment, creatingCollection, collection string, future bool, captured []string) error {
	if environment == "" {
		if collection == "" || !future || creatingCollection != collection {
			return ErrMachineDenied
		}
		_, err := controlstatedb.New(tx).LockCollection(ctx, controlstatedb.LockCollectionParams{TeamID: team, ProjectKey: project, ID: collection})
		return publisherLookupError(err, ErrMachineDenied)
	}
	row, err := controlstatedb.New(tx).LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: team, ProjectKey: project, ID: environment})
	if err != nil {
		return publisherLookupError(err, ErrMachineDenied)
	}
	if row.RetiredAt.Valid || collection != "" && row.CollectionID.String != collection || !future && !slices.Contains(captured, environment) {
		return ErrMachineDenied
	}
	return nil
}

func environmentPermissionServicesContain(allowed, requested []string) bool {
	for _, name := range requested {
		if !slices.Contains(allowed, name) {
			return false
		}
	}
	return len(requested) > 0
}
