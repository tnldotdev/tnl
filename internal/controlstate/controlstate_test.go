package controlstate

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestCanonicalCertificateIdentifiers(t *testing.T) {
	t.Parallel()

	identifiers, err := canonicalCertificateIdentifiers([]string{"z.example.test", "*.example.test", "a.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"*.example.test", "a.example.test", "z.example.test"}; !slices.Equal(identifiers, want) {
		t.Fatalf("canonical identifiers = %q, want %q", identifiers, want)
	}
	for _, invalid := range [][]string{
		nil,
		{"route.example.test", "route.example.test"},
		{"PublicURL.example.test"},
		{"route.*.example.test"},
	} {
		if _, err := canonicalCertificateIdentifiers(invalid); err == nil {
			t.Errorf("canonicalCertificateIdentifiers(%q) succeeded", invalid)
		}
	}
}

func TestParseDirectConfig(t *testing.T) {
	t.Parallel()

	config, err := parseDirectConfig("postgres://user:secret@database.example:5432/tnl?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if config.Database != "tnl" {
		t.Fatalf("database = %q, want tnl", config.Database)
	}
	if config.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("query execution mode = %v, want %v", config.DefaultQueryExecMode, pgx.QueryExecModeExec)
	}
}

func TestParsePoolConfig(t *testing.T) {
	t.Parallel()

	defaultConfig, err := parsePoolConfig("postgresql://user:secret@database.example/tnl?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if defaultConfig.MaxConns != 8 {
		t.Fatalf("default maximum connections = %d, want 8", defaultConfig.MaxConns)
	}

	config, err := parsePoolConfig("postgresql://user:secret@database.example/tnl?sslmode=require&pool_max_conns=5&default_query_exec_mode=cache_statement")
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxConns != 5 {
		t.Fatalf("maximum connections = %d, want 5", config.MaxConns)
	}
	if config.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("query execution mode = %v, want %v", config.ConnConfig.DefaultQueryExecMode, pgx.QueryExecModeExec)
	}
}

func TestDatabaseURLValidation(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		"postgres:///tnl",
		"postgresql://database.example/tnl",
	} {
		if err := validateDatabaseURL(rawURL); err != nil {
			t.Errorf("validateDatabaseURL(%q): %v", rawURL, err)
		}
	}

	for _, rawURL := range []string{
		"",
		" postgres://database.example/tnl",
		"host=database.example dbname=tnl",
		"https://database.example/tnl",
		"postgres://database.example",
		"postgres://database.example/",
		"postgres://database.example/tnl#fragment",
		"postgres://user:supersecret@%zz/tnl",
	} {
		err := validateDatabaseURL(rawURL)
		if err == nil {
			t.Errorf("validateDatabaseURL(%q) succeeded", rawURL)
			continue
		}
		if strings.Contains(err.Error(), "supersecret") {
			t.Errorf("validateDatabaseURL(%q) leaked its password: %v", rawURL, err)
		}
	}
}

func TestDatabaseNilHealthAndReadiness(t *testing.T) {
	t.Parallel()

	var database *Database
	if err := database.Health(t.Context()); err == nil {
		t.Fatal("Health succeeded for a nil database")
	}
	if err := database.Readiness(t.Context()); err == nil {
		t.Fatal("Readiness succeeded for a nil database")
	}
	database.Close()
}

func TestRollbackUsesBoundedContextAfterRequestCancellation(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.WithValue(t.Context(), rollbackContextKey{}, "request value"))
	cancel()
	operationErr := errors.New("operation failed")
	rollbackErr := errors.New("rollback failed")
	tx := &rollbackContextTx{rollbackErr: rollbackErr}

	result := error(operationErr)
	rollback(requestCtx, tx, "test transaction", &result)()

	if tx.contextErr != nil || tx.contextValue != "request value" || !tx.hasDeadline || tx.remaining <= 0 || tx.remaining > transactionRollbackTimeout {
		t.Fatalf("rollback context: err=%v value=%v deadline=%t remaining=%s", tx.contextErr, tx.contextValue, tx.hasDeadline, tx.remaining)
	}
	if !errors.Is(result, operationErr) || !errors.Is(result, rollbackErr) {
		t.Fatalf("rollback result = %v", result)
	}
}

type rollbackContextKey struct{}

type rollbackContextTx struct {
	pgx.Tx
	rollbackErr  error
	contextErr   error
	contextValue any
	hasDeadline  bool
	remaining    time.Duration
}

func (tx *rollbackContextTx) Rollback(ctx context.Context) error {
	tx.contextErr = ctx.Err()
	tx.contextValue = ctx.Value(rollbackContextKey{})
	deadline, ok := ctx.Deadline()
	tx.hasDeadline = ok
	tx.remaining = time.Until(deadline)
	return tx.rollbackErr
}
