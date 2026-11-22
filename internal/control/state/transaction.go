package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/failure"
)

const transactionRollbackTimeout = 5 * time.Second

// RollbackFailure retains the operation result separately from its cleanup.
// a rollback timeout is not evidence that the operation itself timed out.
type RollbackFailure struct {
	OperationErr error
	RollbackErr  error
}

func (e *RollbackFailure) Error() string {
	return errors.Join(e.OperationErr, e.RollbackErr).Error()
}

func (e *RollbackFailure) Unwrap() []error {
	if e.OperationErr == nil {
		return []error{e.RollbackErr}
	}
	return []error{e.OperationErr, e.RollbackErr}
}

func rollback(ctx context.Context, tx pgx.Tx, operation string, retErr *error) func() {
	return func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), transactionRollbackTimeout)
		defer cancel()
		if err := tx.Rollback(rollbackCtx); err != nil && !failure.Only(err, pgx.ErrTxClosed) {
			*retErr = &RollbackFailure{OperationErr: *retErr, RollbackErr: fmt.Errorf("controlstate: %s: rollback: %w", operation, err)}
		}
	}
}
