package state

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPublisherWatchContentionRequiresCleanRollback(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "55P03", "XX000"} {
		t.Run(code, func(t *testing.T) {
			cause := &pgconn.PgError{Code: code}
			queryErr := fmt.Errorf("authorize watch: %w", cause)
			err := classifyPublisherWatchError(queryErr)
			if !errors.Is(err, cause) || errors.Is(err, ErrPublisherWatchContended) != (code != "XX000") {
				t.Fatalf("unexpected watch authorization error: %v", err)
			}
			rollback := &RollbackFailure{OperationErr: queryErr, RollbackErr: errors.New("cleanup failed")}
			if err := classifyPublisherWatchError(rollback); err != rollback {
				t.Fatalf("watch authorization reclassified an independent rollback failure: %v", err)
			}
		})
	}
}
