package state

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationPublisherAllocationPreservesReadFailure(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "allocation_read_failure")
	config := database.pool.Config()
	// exec mode delivers execution errors through Rows rather than describe.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnConfig.RuntimeParams["lock_timeout"] = "10ms"
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	reader := &Database{pool: pool}
	publisher := PublisherIdentity{Scope: PublisherScope{Kind: "namespace", TeamID: "missing"}}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request := AllocateServiceRequest{Invocation: invocation, Configuration: ProjectServiceConfiguration{Target: "localhost:3000"}}
	_, err = reader.AllocatePublisherService(t.Context(), publisher, request, now)
	if !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("missing team = %v", err)
	}
	lock, err := database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, lock)
	if _, err := lock.Exec(t.Context(), "LOCK TABLE control.teams IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	_, err = reader.AllocatePublisherService(t.Context(), publisher, request, now)
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) || postgres.Code != "55P03" || errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("team read failure became an identity denial: %v", err)
	}
}
