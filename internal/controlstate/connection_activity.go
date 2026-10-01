package controlstate

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type connectionPurpose int

const (
	requestPoolConnection connectionPurpose = iota
	tlsLeadershipConnection
	dnsChallengeConnection
	diagnosticConnection
	poolerDiagnosticConnection
)

var connectionPurposeNames = [...]string{"request_pool", "tls_leadership", "dns_challenge", "diagnostics", "pooler_diagnostics"}

// counts describe this process's client sockets, not PostgreSQL backend slots.
// only fixed purpose labels and counters are retained, never connection details.
type DatabaseConnectionCounts struct {
	Open       int64 `json:"open"`
	Connecting int64 `json:"connecting"`
	Opened     int64 `json:"opened_total"`
	Closed     int64 `json:"closed_total"`
	Failed     int64 `json:"connect_failures_total"`
}

type connectionActivity struct {
	mu     sync.Mutex
	counts [len(connectionPurposeNames)]DatabaseConnectionCounts
	live   map[<-chan struct{}]connectionPurpose
}

// CleanupDone tracks actual socket cleanup, including cancellation and network
// failure. reaping on connect/snapshot avoids a goroutine per connection and
// prevents completed connections accumulating between diagnostic requests.
func (a *connectionActivity) reapClosed() {
	for done, purpose := range a.live {
		select {
		case <-done:
			a.counts[purpose].Closed++
			a.counts[purpose].Open--
			delete(a.live, done)
		default:
		}
	}
}

func (a *connectionActivity) snapshot() map[string]DatabaseConnectionCounts {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reapClosed()
	result := make(map[string]DatabaseConnectionCounts, len(connectionPurposeNames))
	for purpose, name := range connectionPurposeNames {
		result[name] = a.counts[purpose]
	}
	return result
}

type connectionTracer struct {
	connections *connectionActivity
	purpose     connectionPurpose
	queries     *queryActivity
}

type acquireStartedKey struct{}

func (t *connectionTracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return context.WithValue(ctx, acquireStartedKey{}, time.Now())
}

func (t *connectionTracer) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	if t.queries == nil {
		return
	}
	if started, ok := ctx.Value(acquireStartedKey{}).(time.Time); ok {
		t.queries.metrics.Load().ObserveDatabaseAcquire(data.Err, time.Since(started))
	}
}

func (t *connectionTracer) TraceConnectStart(ctx context.Context, _ pgx.TraceConnectStartData) context.Context {
	if a := t.connections; a != nil {
		a.mu.Lock()
		a.reapClosed()
		a.counts[t.purpose].Connecting++
		a.mu.Unlock()
	}
	return ctx
}

func (t *connectionTracer) TraceConnectEnd(_ context.Context, data pgx.TraceConnectEndData) {
	if a := t.connections; a != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.reapClosed()
		a.counts[t.purpose].Connecting--
		if data.Err != nil {
			a.counts[t.purpose].Failed++
			return
		}
		a.counts[t.purpose].Opened++
		a.counts[t.purpose].Open++
		if a.live == nil {
			a.live = make(map[<-chan struct{}]connectionPurpose)
		}
		a.live[data.Conn.PgConn().CleanupDone()] = t.purpose
	}
}

func (t *connectionTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if t.queries != nil {
		return t.queries.TraceQueryStart(ctx, conn, data)
	}
	return ctx
}

func (t *connectionTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if t.queries != nil {
		t.queries.TraceQueryEnd(ctx, conn, data)
	}
}

func (d *Database) dedicatedConnectionConfig(purpose connectionPurpose) *pgx.ConnConfig {
	config := d.pool.Config().ConnConfig.Copy()
	config.Tracer = &connectionTracer{connections: d.connections, purpose: purpose}
	return config
}
