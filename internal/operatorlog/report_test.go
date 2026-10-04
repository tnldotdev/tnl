package operatorlog

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestFormatDoesNotExposeCauseOrMultilineContext(t *testing.T) {
	cause := errors.New("Authorization: Bearer secret-do-not-log")
	err := failure.Wrap("read client session", failure.ClientStateUnavailable, cause)
	if !errors.Is(err, cause) {
		t.Fatal("failure lost its original cause")
	}
	got := Format("read client session", failure.ClientStateUnavailable, "request_1\nspoofed")
	if strings.Contains(got, "secret-do-not-log") || strings.ContainsRune(got, '\n') ||
		!strings.Contains(got, "reason=client.state_unavailable") || !strings.Contains(got, "request_id=request_1?spoofed") {
		t.Fatalf("operator log = %q", got)
	}
}

func TestSafeCauseFieldsOnlyIncludeTypedFailureData(t *testing.T) {
	cause := &pgconn.PgError{Code: "23505", Message: "customer token=secret-do-not-log"}
	if got := safeCauseFields(cause); got != " sqlstate=23505" {
		t.Fatalf("postgres failure fields = %q", got)
	}
	if got := safeCauseFields(&pgconn.PgError{Code: "23505\nsecret"}); got != "" {
		t.Fatalf("invalid PostgreSQL code escaped: %q", got)
	}
}
