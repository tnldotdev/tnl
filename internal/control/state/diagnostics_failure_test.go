package controlstate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestDatabaseDiagnosticsKeepCausesAndOnlyApprovedFields(t *testing.T) {
	cause := &pgconn.PgError{Code: "42501", Message: "private database credentials", Detail: "private query parameters"}
	err := databaseDiagnosticsError(t.Context(), cause)
	var postgresError *pgconn.PgError
	if !errors.Is(err, cause) || !errors.As(err, &postgresError) || postgresError != cause {
		t.Fatal("diagnostics lost the PostgreSQL cause")
	}
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerDatabaseDiagnosticsUnavailable {
		t.Fatalf("reason = %q", reason)
	}
	message := databaseDiagnosticsMessage(err)
	if !strings.Contains(message, "42501") || strings.Contains(message, "private") {
		t.Fatalf("unsafe diagnostics = %q", message)
	}
	cause.Code = "private"
	if message := databaseDiagnosticsMessage(err); strings.Contains(message, "private") {
		t.Fatalf("unvalidated SQLSTATE = %q", message)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	stop := errors.New("caller stopped")
	cancel(stop)
	if err := databaseDiagnosticsError(ctx, cause); !errors.Is(err, cause) || !errors.Is(err, stop) {
		t.Fatal("diagnostics lost cancellation or query cause")
	}
}
