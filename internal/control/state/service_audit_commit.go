package state

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

//go:embed batch/append_fresh_publisher_audit.sql
var appendFreshAuditSQL string

// the caller has locked the service and checked each event against this run.
// new events need no duplicate lookup. send their insert and commit together
// so that an owner clock does not wait for a client round trip before commit.
// a duplicate aborts the transaction before commit, including fresh neighbors.
func (d *Database) appendFreshPublisherAudit(ctx context.Context, tx pgx.Tx, events []serviceaudit.Event, now time.Time, team, guest pgtype.Text) error {
	n := len(events)
	ids, kinds, actors, devices := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	times := make([]pgtype.Timestamptz, n)
	visitors, sources, outcomes, reasons := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, e := range events {
		ids[i], kinds[i], actors[i], devices[i] = e.ID, e.EventType, e.ActorIdentityID, e.DeviceID
		times[i] = timestamptz(e.OccurredAt)
		visitors[i], sources[i], outcomes[i], reasons[i] = e.VisitorConnectionID, e.SourceDigest, e.Outcome, e.Reason
	}
	// track the pending statement just as for an ordinary pgx query. seeing
	// the commit result also closes the transaction's guard measurements.
	query := d.activity.TraceQueryStart(ctx, tx.Conn(), pgx.TraceQueryStartData{SQL: appendFreshAuditSQL})
	b := new(pgx.Batch)
	b.Queue(appendFreshAuditSQL, team, guest, events[0].ServiceID, timestamptz(now), events[0].PublisherIdentityID, events[0].RunID,
		ids, kinds, times, actors, devices, visitors, sources, outcomes, reasons).Exec(func(tag pgconn.CommandTag) error {
		d.activity.TraceQueryEnd(query, tx.Conn(), pgx.TraceQueryEndData{CommandTag: tag})
		query = d.activity.TraceQueryStart(ctx, tx.Conn(), pgx.TraceQueryStartData{SQL: "commit"})
		return nil
	})
	b.Queue("commit").Exec(func(tag pgconn.CommandTag) error {
		if tag.String() != "COMMIT" {
			return fmt.Errorf("publisher audit: expected commit, got %s", tag)
		}
		return nil
	})
	err := tx.SendBatch(ctx, b).Close()
	d.activity.TraceQueryEnd(query, tx.Conn(), pgx.TraceQueryEndData{Err: err})
	return err
}
