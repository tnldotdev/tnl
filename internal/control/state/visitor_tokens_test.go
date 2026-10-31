package state

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestVisitorPreparationRetryErrorClassification(t *testing.T) {
	var typedNil *pgconn.PgError
	serialization := &pgconn.PgError{Code: "40001"}
	deadlock := &pgconn.PgError{Code: "40P01"}
	for _, tc := range []struct {
		name     string
		err      error
		attempts int
	}{
		{"nil", nil, 1},
		{"typed nil", typedNil, 1},
		{"wrapped typed nil", fmt.Errorf("wrapped: %w", typedNil), 1},
		{"joined typed nil", errors.Join(errors.New("unrelated"), typedNil), 1},
		{"nil PostgreSQL match before real serialization", errors.Join(fmt.Errorf("wrapped: %w", typedNil), serialization), 1},
		// preserve errors.As's existing first-match rule: a real PostgreSQL
		// match remains retryable; a later malformed match is never dereferenced.
		{"real serialization before nil PostgreSQL match", errors.Join(serialization, typedNil), 8},
		{"serialization", serialization, 8},
		{"wrapped deadlock", fmt.Errorf("wrapped: %w", deadlock), 8},
		{"busy row", &pgconn.PgError{Code: "55P03"}, 8},
		{"unrelated PostgreSQL", &pgconn.PgError{Code: "23505"}, 1},
		{"unrelated text", errors.New("40001 40P01"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				defer func() {
					if recover() != nil {
						t.Error("preparation retry classifier panicked")
					}
				}()
				calls := 0
				result, err := retryVisitorPreparation(t.Context(), time.Now(), func(time.Time) (int, error) { calls++; return calls, tc.err })
				if calls != tc.attempts || result != calls || err != tc.err {
					t.Fatal("retry changed attempt bound, result or original error identity")
				}
			})
		})
	}
}

func TestVisitorPreparationRetryFreshDecisionAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := time.Now().Add(-time.Hour)
		calls := 0
		result, err := retryVisitorPreparation(t.Context(), first, func(at time.Time) (int, error) {
			calls++
			if calls == 1 && !at.Equal(first) || calls > 1 && !at.Equal(time.Now()) {
				t.Fatal("retry reused a stale authority decision time")
			}
			if calls < 3 {
				return 0, &pgconn.PgError{Code: "40001"}
			}
			return 7, nil
		})
		if err != nil || result != 7 || calls != 3 {
			t.Fatal("whole-decision retry did not recover")
		}
		cause := errors.New("caller canceled preparation")
		ctx, cancel := context.WithCancelCause(t.Context())
		calls = 0
		result, err = retryVisitorPreparation(ctx, time.Now(), func(time.Time) (int, error) {
			calls++
			cancel(cause)
			return 9, &pgconn.PgError{Code: "40P01"}
		})
		if !errors.Is(err, cause) || calls != 1 || result != 0 {
			t.Fatal("cancellation retried or lost its cause/zero result")
		}
	})
}
