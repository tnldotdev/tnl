package state

import (
	"errors"
	"slices"

	"github.com/jackc/pgx/v5/pgconn"
)

func sortedProjectKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func projectConstraintError(err error) error {
	var constraint *pgconn.PgError
	if errors.As(err, &constraint) && constraint.Code == "23505" {
		return ErrServiceConflict
	}
	return err
}
