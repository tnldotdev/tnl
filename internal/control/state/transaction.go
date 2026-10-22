package state

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func rollback(ctx context.Context, tx pgx.Tx, operation string, retErr *error) func() {
	return func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), transactionRollbackTimeout)
		defer cancel()
		if err := tx.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			*retErr = errors.Join(*retErr, fmt.Errorf("controlstate: %s: rollback: %w", operation, err))
		}
	}
}
