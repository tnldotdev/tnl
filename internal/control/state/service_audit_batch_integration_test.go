package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/testutil/ipdigest"
)

type auditQueryCountTx struct {
	pgx.Tx
	calls map[string]int
}

func (tx auditQueryCountTx) record(sql string) {
	name, _, _ := strings.Cut(strings.TrimPrefix(sql, "-- name: "), " ")
	tx.calls[name]++
}

func (tx auditQueryCountTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.record(sql)
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx auditQueryCountTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.record(sql)
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx auditQueryCountTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.record(sql)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func TestIntegrationServiceAuditBatchBoundsWritesAndPreservesInputOrder(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx := t.Context()
	events := make([]serviceaudit.Event, serviceaudit.MaxBatch)
	for index := range events {
		events[index] = serviceaudit.Event{ID: serviceaudit.NewID(), TeamID: f.service.TeamID,
			ServiceID: f.service.ID, ServiceKind: "service", EventType: "http.decision",
			RunID: f.run.RunID, PublisherIdentityID: f.publisher.ID,
			VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix),
			SourceDigest:        ipdigest.Hash("192.0.2.10"), Outcome: "allowed",
			// report arrival, not event time or random ID order, assigns cursors.
			OccurredAt: f.now.Add(-time.Duration(index) * time.Microsecond)}
	}
	events[len(events)-1] = events[0]
	for _, invalid := range [][]serviceaudit.Event{nil, make([]serviceaudit.Event, serviceaudit.MaxBatch+1)} {
		calls := make(map[string]int)
		if _, err := insertServiceAuditBatch(ctx, auditQueryCountTx{calls: calls}, invalid, f.now); !errors.Is(err, serviceaudit.ErrInvalid) || len(calls) != 0 {
			t.Fatal("invalid batch reached storage", len(invalid), calls, err)
		}
	}
	for round := range 2 {
		tx, err := f.database.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, tx)
		calls := make(map[string]int)
		result, err := insertServiceAuditBatch(ctx, auditQueryCountTx{Tx: tx, calls: calls}, events, f.now)
		accepted := serviceaudit.MaxBatch - 1
		wantCalls := 3
		if round == 1 {
			accepted, wantCalls = 0, 4
		}
		if err != nil || result.Accepted != accepted || result.Duplicates != len(events)-accepted {
			t.Fatal("batch lost its within-batch or committed duplicate counts", result, err)
		}
		if len(calls) != wantCalls || calls["ListServiceAuditOwners"] != 1 ||
			calls["LockServiceAuditClock"] != 1 || calls["InsertServiceAuditEvents"] != 1 ||
			calls["ListServiceAuditEventsByID"] != round {
			t.Fatal("batch repeated owner, clock, insert, or duplicate work per event", calls)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := f.database.pool.Query(ctx, `SELECT id FROM control.service_audit_events WHERE service_id=$1 AND event_type='http.decision' ORDER BY cursor`, f.service.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		if index >= len(events)-1 || id != events[index].ID {
			t.Fatal("batch reordered committed cursors", index, id)
		}
		index++
	}
	if err := rows.Err(); err != nil || index != len(events)-1 {
		t.Fatal("batch lost a committed event", index, err)
	}
}

func TestIntegrationServiceAuditBatchConflictRollsBackEveryNeighbor(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx := t.Context()
	original := serviceaudit.Event{ID: serviceaudit.NewID(), TeamID: f.service.TeamID, ServiceID: f.service.ID,
		ServiceKind: "service", EventType: "http.decision", RunID: f.run.RunID, PublisherIdentityID: f.publisher.ID,
		VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), SourceDigest: ipdigest.Hash("192.0.2.10"),
		Outcome: "allowed", OccurredAt: f.now}
	for _, committed := range []bool{false, true} {
		if committed {
			tx, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			if err := insertServiceAudit(ctx, tx, original, f.now); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for _, field := range []string{"source", "time", "outcome", "reason", "visitor", "run", "type", "team", "service"} {
			t.Run(field+map[bool]string{false: "/in batch", true: "/committed"}[committed], func(t *testing.T) {
				bad, neighbor := original, original
				neighbor.ID = serviceaudit.NewID()
				switch field {
				case "source":
					bad.SourceDigest = ipdigest.Hash("192.0.2.11")
				case "time":
					bad.OccurredAt = bad.OccurredAt.Add(time.Microsecond)
				case "outcome":
					bad.Outcome = "denied"
				case "reason":
					bad.Reason = "authorization"
				case "visitor":
					bad.VisitorConnectionID = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
				case "run":
					bad.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
				case "type":
					bad.EventType = "connection.open"
				case "team":
					bad.TeamID = mustOpaqueID(t, opaqueid.TeamPrefix)
				case "service":
					bad.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix)
				}
				batch := []serviceaudit.Event{neighbor, original, bad}
				tx, err := f.database.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, tx)
				if committed {
					batch = []serviceaudit.Event{neighbor, bad}
				}
				if _, err := insertServiceAuditBatch(ctx, tx, batch, f.now); !errors.Is(err, ErrServiceAuditAccess) {
					t.Fatal("conflicting fact did not reject its batch", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1`, neighbor.ID).Scan(&count); err != nil || count != 0 {
					t.Fatal("rejected batch committed a valid neighbor", count, err)
				}
			})
		}
	}
}
