package controlstate

import (
	"context"
	"embed"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/observability"
)

// Only names compiled from our sqlc sources may leave the process. Never retain
// SQL, arguments, errors, connection configuration, or request context here.
//
//go:embed queries/*.sql
var diagnosticQuerySources embed.FS

var diagnosticQueryNames = func() map[string]struct{} {
	names := make(map[string]struct{})
	files, _ := diagnosticQuerySources.ReadDir("queries")
	for _, file := range files {
		data, _ := diagnosticQuerySources.ReadFile("queries/" + file.Name())
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.HasPrefix(line, "-- name: ") {
				fields := strings.Fields(line)
				if len(fields) == 4 {
					names[fields[2]] = struct{}{}
				}
			}
		}
	}
	return names
}()

const maximumActiveQueries = MaxDatabaseDiagnosticOperations

type activeQuery struct {
	operation string
	started   time.Time
}

type queryActivity struct {
	mu      sync.Mutex
	active  map[*activeQuery]struct{}
	omitted int
	metrics atomic.Pointer[observability.Metrics]
	guards  map[*pgx.Conn]*transactionGuards
}

type transactionGuards struct {
	done <-chan struct{}
	held map[string]time.Time
}

type queryActivityKey struct{}

func diagnosticQueryName(sql string) string {
	line, _, _ := strings.Cut(sql, "\n")
	fields := strings.Fields(line)
	if len(fields) == 4 && fields[0] == "--" && fields[1] == "name:" {
		if _, ok := diagnosticQueryNames[fields[2]]; ok {
			return strings.Clone(fields[2]) // Do not retain the SQL backing string.
		}
	}
	// pgx appends isolation, access, and deferrability options to BEGIN.
	// Return a fixed label regardless of those options or custom BeginQuery text.
	if sql == "begin" || strings.HasPrefix(sql, "begin ") {
		return "begin"
	}
	switch sql {
	case "commit", "rollback":
		return strings.Clone(sql)
	default:
		return "unknown"
	}
}

func (q *queryActivity) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	query := &activeQuery{operation: diagnosticQueryName(data.SQL), started: time.Now()}
	q.mu.Lock()
	if q.active == nil {
		q.active = make(map[*activeQuery]struct{})
	}
	if len(q.active) < maximumActiveQueries {
		q.active[query] = struct{}{}
	} else {
		q.omitted++
	}
	q.mu.Unlock()
	return context.WithValue(ctx, queryActivityKey{}, query)
}

func (q *queryActivity) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	query, ok := ctx.Value(queryActivityKey{}).(*activeQuery)
	if !ok {
		return
	}
	now := time.Now()
	err := data.Err
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	metrics := q.metrics.Load()
	metrics.ObserveDatabaseQuery(query.operation, err, now.Sub(query.started))
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, exists := q.active[query]; exists {
		delete(q.active, query)
	} else {
		q.omitted--
	}
	if metrics == nil || conn == nil {
		return
	}
	defer q.reapGuards()
	// These queries explicitly acquire guards held until the transaction ends.
	// Driver completion excludes the acquiring query's own wait; it cannot
	// identify the exact instant PostgreSQL acquired or released a lock.
	switch query.operation {
	case "LockLocalTeamForSession", "LockRelayServicesForPlacement", "GetRelayLeaseForClaim", "GetRelayLeaseForReady", "LockIngressRoutingTableClock", "InsertFinalIngressRoutingTableEvent", "LockPublishRunForUsage", "LockIngressLease":
		if err == nil && data.CommandTag.RowsAffected() > 0 && conn.PgConn().TxStatus() != 'I' {
			if q.guards == nil {
				q.guards = make(map[*pgx.Conn]*transactionGuards)
			}
			if q.guards[conn] == nil {
				q.guards[conn] = &transactionGuards{done: conn.PgConn().CleanupDone(), held: make(map[string]time.Time)}
			}
			if _, held := q.guards[conn].held[query.operation]; !held {
				q.guards[conn].held[query.operation] = now
			}
		}
	}
	if query.operation == "commit" || query.operation == "rollback" || conn.IsClosed() {
		if guards := q.guards[conn]; guards != nil {
			for operation, started := range guards.held {
				metrics.ObserveDatabaseGuard(operation, err, now.Sub(started))
			}
			delete(q.guards, conn)
		}
	}
}

// Socket cleanup without a final driver callback has no observed completion
// time. Discard those unfinished windows rather than inventing a duration.
func (q *queryActivity) reapGuards() {
	for conn, guards := range q.guards {
		select {
		case <-guards.done:
			delete(q.guards, conn)
		default:
		}
	}
}

type DatabaseOperation struct {
	Operation      string  `json:"operation"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

func (q *queryActivity) snapshot(now time.Time) ([]DatabaseOperation, bool) {
	result, omitted := q.snapshotWithOmitted(now)
	return result, omitted > 0
}

func (q *queryActivity) snapshotWithOmitted(now time.Time) ([]DatabaseOperation, int) {
	result := []DatabaseOperation{}
	if q == nil {
		return result, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reapGuards()
	for query := range q.active {
		result = append(result, DatabaseOperation{Operation: query.operation, ElapsedSeconds: max(0, now.Sub(query.started).Seconds())})
	}
	slices.SortFunc(result, func(a, b DatabaseOperation) int {
		if a.ElapsedSeconds > b.ElapsedSeconds {
			return -1
		}
		if a.ElapsedSeconds < b.ElapsedSeconds {
			return 1
		}
		return strings.Compare(a.Operation, b.Operation)
	})
	return result, q.omitted
}
