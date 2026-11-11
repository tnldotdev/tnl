package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type rollbackTransaction struct {
	pgx.Tx
	failure error
	called  bool
	t       *testing.T
}

func (tx *rollbackTransaction) Rollback(ctx context.Context) error {
	tx.called = true
	if ctx.Err() != nil {
		tx.t.Error("rollback inherited request cancellation")
	}
	if until, ok := ctx.Deadline(); !ok || time.Until(until) <= 0 || time.Until(until) > transactionRollbackTimeout {
		tx.t.Error("rollback has no bounded cleanup deadline")
	}
	return tx.failure
}

func TestRollbackRetainsIndependentFailureAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	failure := errors.New("rollback failed")
	tx := &rollbackTransaction{failure: failure, t: t}
	result := context.Canceled
	rollback(ctx, tx, "test", &result)()
	if !tx.called || !errors.Is(result, context.Canceled) || !errors.Is(result, failure) {
		t.Fatalf("rollback = %v", result)
	}
	result = nil
	tx.failure = pgx.ErrTxClosed
	rollback(ctx, tx, "test", &result)()
	if result != nil {
		t.Fatal(result)
	}
}
