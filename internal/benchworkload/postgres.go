package benchworkload

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/trace"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// PostgresVisitor owns authenticated sessions, not a reconnecting connection pool.
// each worker borrows one already-warm session; failed sessions are never replaced.
type PostgresVisitor struct {
	sessions chan *pgx.Conn
	owned    []*pgx.Conn
	pids     []uint32
	dials    atomic.Int64
}

// Prepare excludes connection, TLS, authentication, and the first query from Run.
func (v *PostgresVisitor) Prepare(ctx context.Context, config *pgx.ConnConfig, workers int) (Histogram, error) {
	var setup Histogram
	if config == nil || workers < 1 || v.sessions != nil {
		return setup, errors.New("invalid PostgreSQL visitor preparation")
	}
	v.sessions = make(chan *pgx.Conn, workers)
	for range workers {
		started := time.Now()
		bounded, cancel := context.WithTimeout(ctx, RequestTimeout)
		cfg := config.Copy()
		cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		dial := cfg.DialFunc
		cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			v.dials.Add(1)
			return dial(ctx, network, address)
		}
		conn, err := pgx.ConnectConfig(bounded, cfg)
		if err == nil {
			v.owned = append(v.owned, conn)
			var value int
			err = conn.QueryRow(bounded, "SELECT 1").Scan(&value)
			if err == nil && value != 1 {
				err = errors.New("unexpected PostgreSQL result")
			}
		}
		cancel()
		if err != nil {
			_ = v.Close()
			return setup, err
		}
		v.pids = append(v.pids, conn.PgConn().PID())
		v.sessions <- conn
		setup.Observe(time.Since(started))
	}
	return setup, nil
}

type PostgresSessions struct {
	BackendPIDs []uint32 `json:"backend_pids"`
	DialCalls   int64    `json:"dial_calls"`
}

// Verify checks server-side identity outside the measured window, after workers join.
func (v *PostgresVisitor) Verify(ctx context.Context) (PostgresSessions, error) {
	result := PostgresSessions{BackendPIDs: make([]uint32, 0, len(v.owned)), DialCalls: v.dials.Load()}
	if len(v.owned) == 0 || result.DialCalls != int64(len(v.owned)) {
		return result, errors.New("PostgreSQL sessions missing or reconnected")
	}
	for index, conn := range v.owned {
		bounded, cancel := context.WithTimeout(ctx, RequestTimeout)
		var pid uint32
		err := conn.QueryRow(bounded, "SELECT pg_backend_pid()").Scan(&pid)
		cancel()
		if err != nil {
			return result, err
		}
		if pid != v.pids[index] || conn.PgConn().PID() != pid {
			return result, errors.New("PostgreSQL backend changed during warm workload")
		}
		result.BackendPIDs = append(result.BackendPIDs, pid)
	}
	return result, nil
}

func (v *PostgresVisitor) Close() error {
	var result error
	for _, conn := range v.owned {
		ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
		result = errors.Join(result, conn.Close(ctx))
		cancel()
	}
	v.owned = nil
	return result
}

func (v *PostgresVisitor) Run(ctx context.Context, config VisitorConfig) (VisitorResult, error) {
	if v.sessions == nil || config.Workers != len(v.owned) {
		return VisitorResult{}, errors.New("PostgreSQL workers must match prepared sessions")
	}
	return runVisitors(ctx, config, []string{"postgres"}, v.request)
}

func (v *PostgresVisitor) request(parent context.Context, address string, scheduled time.Time) (result RequestResult) {
	result.URL, result.Started = address, time.Now()
	scheduled = localSchedule(result.Started, scheduled)
	result.Scheduled, result.QueueDelay = scheduled, result.Started.Sub(scheduled)
	if result.QueueDelay >= RequestTimeout {
		result.QueueExpired, result.Error = true, "request expired in queue"
		return
	}
	_, traced := parent.(visitorRequestTraceContext)
	var cleanup *trace.Region
	if traced {
		// registered before cancel and session return so the region covers both.
		defer func() {
			if cleanup != nil {
				cleanup.End()
			}
		}()
	}
	ctx, cancel := context.WithDeadline(parent, scheduled.Add(RequestTimeout))
	defer cancel()
	conn := <-v.sessions
	defer func() {
		if traced {
			cleanup = trace.StartRegion(ctx, "benchworkload.postgres.cleanup")
		}
		v.sessions <- conn
	}()
	result.Started = time.Now()
	result.QueueDelay = result.Started.Sub(scheduled)
	var value int
	var query *trace.Region
	var backendPID string
	if traced {
		backendPID = strconv.FormatUint(uint64(conn.PgConn().PID()), 10)
		trace.Log(ctx, "benchworkload.postgres.query.begin", backendPID)
		query = trace.StartRegion(ctx, "benchworkload.postgres.query")
	}
	err := conn.QueryRow(ctx, "SELECT 1").Scan(&value)
	result.Duration = time.Since(scheduled)
	if traced {
		query.End()
		trace.Log(ctx, "benchworkload.postgres.query.end", backendPID)
	}
	if err == nil && value != 1 {
		err = fmt.Errorf("unexpected PostgreSQL result: %d", value)
	}
	if err != nil {
		result.Error = safeMeasurementFailure(err)
		result.Timeout = errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	// this is query completion, not a claimed SQL phase or first wire byte.
	return
}
