package controlstate

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestQueryActivityPrivacyBoundsAndCancellation(t *testing.T) {
	activity := new(queryActivity)
	var contexts []context.Context
	parent, cancel := context.WithCancel(t.Context())
	for index := range maximumActiveQueries + 5 {
		statement := "-- name: LockPublishRunForUsage :one\nSELECT secret FROM secret_table WHERE token = $1"
		if index%2 == 0 {
			statement = "-- name: do_not_export :one\nSELECT 'private-url'"
		}
		contexts = append(contexts, activity.TraceQueryStart(parent, nil, pgx.TraceQueryStartData{SQL: statement, Args: []any{"private-token"}}))
	}
	operations, omitted := activity.snapshotWithOmitted(time.Now())
	if len(operations) != maximumActiveQueries || omitted != 5 {
		t.Fatalf("operations=%d omitted=%d", len(operations), omitted)
	}
	for _, operation := range operations {
		if operation.ElapsedSeconds < 0 || operation.Operation != "unknown" && operation.Operation != "LockPublishRunForUsage" {
			t.Fatalf("unsafe operation: %+v", operation)
		}
	}
	data, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "private", "SELECT", "do_not_export"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	cancel()
	// cancellation alone must not pretend the driver has finished a query.
	if active, _ := activity.snapshot(time.Now()); len(active) != maximumActiveQueries {
		t.Fatal("canceled requests disappeared before query completion")
	}
	var workers sync.WaitGroup
	for _, ctx := range contexts {
		workers.Go(func() { activity.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{}); activity.snapshot(time.Now()) })
	}
	workers.Wait()
	if active, truncated := activity.snapshot(time.Now()); len(active) != 0 || truncated {
		t.Fatalf("completed queries retained: %+v %t", active, truncated)
	}
	activity.TraceQueryEnd(context.Background(), nil, pgx.TraceQueryEndData{}) // initialization may have no matching start
}

func TestDiagnosticTransactionNamesAreFixed(t *testing.T) {
	for _, statement := range []string{
		"begin", "begin isolation level read committed", "begin isolation level repeatable read",
		"begin isolation level serializable read only deferrable", "begin read write not deferrable",
		"begin /* private-url private-token */", "begin isolation level read committed; SELECT 'secret'",
	} {
		if name := diagnosticQueryName(statement); name != "begin" {
			t.Fatalf("transaction name = %q, want fixed begin label", name)
		}
	}
	for _, statement := range []string{"beginning private-token", "SELECT 'private-token'", "commit; SELECT 'secret'"} {
		if name := diagnosticQueryName(statement); name != "unknown" {
			t.Fatalf("unexpected statement label = %q", name)
		}
	}
}

type beginActivityRecorder struct {
	*queryActivity
	names chan string
}

func (r *beginActivityRecorder) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	ctx = r.queryActivity.TraceQueryStart(ctx, conn, data)
	if strings.HasPrefix(data.SQL, "begin") {
		r.names <- ctx.Value(queryActivityKey{}).(*activeQuery).operation
	}
	return ctx
}

func TestIntegrationQueryActivityLabelsActualBeginTxVariants(t *testing.T) {
	_, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "begin_activity")
	config, err := parsePoolConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &beginActivityRecorder{queryActivity: new(queryActivity), names: make(chan string, 1)}
	config.ConnConfig.Tracer = recorder
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, isolation := range []pgx.TxIsoLevel{"", pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable, pgx.ReadUncommitted} {
		for _, access := range []pgx.TxAccessMode{"", pgx.ReadOnly, pgx.ReadWrite} {
			for _, deferrable := range []pgx.TxDeferrableMode{"", pgx.Deferrable, pgx.NotDeferrable} {
				options := pgx.TxOptions{IsoLevel: isolation, AccessMode: access, DeferrableMode: deferrable}
				tx, err := pool.BeginTx(t.Context(), options)
				if err != nil {
					t.Fatal(err)
				}
				name := <-recorder.names
				if err := tx.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
				if name != "begin" {
					t.Fatalf("BeginTx(%+v) label = %q", options, name)
				}
			}
		}
	}
}
