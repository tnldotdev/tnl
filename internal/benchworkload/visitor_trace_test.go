package benchworkload

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/trace"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPostgresVisitorTraceRequests(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, mode := range []string{"success", "error", "expired", "canceled"} {
			t.Run(strconv.FormatBool(enabled)+"/"+mode, func(t *testing.T) {
				count, workers := 1, 1
				if mode == "success" {
					count, workers = 4, 2
				}
				queryTrace := &visitorQueryTrace{contexts: make(chan context.Context, count)}
				if workers == 2 {
					queryTrace.barrier = make(chan struct{})
				}
				visitor, accepted := preparePostgresVisitor(t, workers, queryTrace)
				before, err := visitor.Verify(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if mode == "canceled" {
					queryTrace.cancel = cancel
				}
				if mode == "error" {
					if err := visitor.owned[0].Close(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				start := time.Now().Add(-time.Second)
				if mode == "expired" {
					start = start.Add(-RequestTimeout)
				}
				var result VisitorResult
				timings := &VisitorTimings{Requests: make([]VisitorRequestTiming, count)}
				events := captureVisitorTrace(t, func() {
					queryTrace.active.Store(true)
					defer queryTrace.active.Store(false)
					result, err = visitor.Run(ctx, VisitorConfig{Rate: 1000, Workers: workers, QueueSlots: count, Start: start, Duration: time.Duration(count) * time.Millisecond, Timing: timings, TraceRequests: enabled})
				})
				if mode == "canceled" {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation lost: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if result.Scheduled != count || result.Missed != 0 || result.Completed+result.QueueExpired != count || len(visitor.sessions) != workers || visitor.dials.Load() != int64(workers) || accepted.Load() != uint32(workers) {
					t.Fatalf("request accounting or session ownership changed: %+v sessions=%d dials=%d accepted=%d", result, len(visitor.sessions), visitor.dials.Load(), accepted.Load())
				}
				queries, outcome := count, "ok"
				switch mode {
				case "expired":
					queries, outcome = 0, "queue_expired"
					if result.QueueExpired != count || result.Completed != 0 {
						t.Fatalf("queue expiry reached query: %+v", result)
					}
				case "error", "canceled":
					outcome = "error"
					if result.Failures != count || result.Timeouts != 0 {
						t.Fatalf("query error hidden: %+v", result)
					}
				default:
					if result.Successes != count || result.Err() != nil {
						t.Fatalf("traced query failed: %+v", result)
					}
				}
				if int(queryTrace.calls.Load()) != queries || len(queryTrace.contexts) != queries {
					t.Fatalf("got %d actual query calls; want %d", queryTrace.calls.Load(), queries)
				}
				for range queries {
					if ctx := <-queryTrace.contexts; !errors.Is(ctx.Err(), context.Canceled) {
						t.Fatalf("request deadline context survived cleanup: %v", ctx.Err())
					}
				}
				if mode == "success" || mode == "expired" {
					after, err := visitor.Verify(t.Context())
					if err != nil || !slices.Equal(before.BackendPIDs, after.BackendPIDs) || before.DialCalls != after.DialCalls {
						t.Fatalf("tracing changed warm sessions: before=%+v after=%+v error=%v", before, after, err)
					}
				}
				assertVisitorTrace(t, events, enabled, count, queries > 0, outcome, before.BackendPIDs, workers)
			})
		}
	}
}

// pgx supplies the actual query's connection and context on the calling worker.
// these independent fixture events prove identity and nesting, not time proximity.
type visitorQueryTrace struct {
	active   atomic.Bool
	calls    atomic.Int64
	contexts chan context.Context
	barrier  chan struct{}
	cancel   context.CancelFunc
}

func (q *visitorQueryTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	if q.active.Load() {
		trace.Log(ctx, "benchworkload.test.client-port", strconv.Itoa(conn.PgConn().Conn().LocalAddr().(*net.TCPAddr).Port))
		trace.Log(ctx, "benchworkload.test.query.begin", strconv.FormatUint(uint64(conn.PgConn().PID()), 10))
		q.contexts <- ctx
		call := q.calls.Add(1)
		if q.barrier != nil && call <= 2 {
			if call == 2 {
				close(q.barrier)
			}
			select {
			case <-q.barrier:
			case <-ctx.Done():
			}
		}
		if q.cancel != nil {
			q.cancel()
		}
	}
	return ctx
}

func (q *visitorQueryTrace) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, _ pgx.TraceQueryEndData) {
	if q.active.Load() {
		trace.Log(ctx, "benchworkload.test.query.end", strconv.FormatUint(uint64(conn.PgConn().PID()), 10))
	}
}

type visitorTraceEvent struct {
	goid, task string
	kind, name string
	message    string
}

func captureVisitorTrace(t *testing.T, run func()) []visitorTraceEvent {
	t.Helper()
	path := filepath.Join(t.TempDir(), "requests.trace")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if err := trace.Start(file); err != nil {
		t.Fatal(err)
	}
	func() {
		defer trace.Stop()
		run()
	}()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "go", "tool", "trace", "-d=parsed", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("parse execution trace: %v\n%s", err, output)
	}
	for _, private := range []string{"SELECT 1", "SELECT pg_backend_pid()", "testpass", "postgres://"} {
		if strings.Contains(string(output), private) {
			t.Fatalf("execution trace contains private query or connection data: %q", private)
		}
	}
	header := regexp.MustCompile(`^M=\S+ P=\S+ G=(\d+) (TaskBegin|TaskEnd|RegionBegin|RegionEnd|Log) Time=\d+ (.*)$`)
	field := regexp.MustCompile(`(?:^| )([A-Za-z]+)=("(?:[^"\\]|\\.)*"|\S+)`)
	var events []visitorTraceEvent
	for _, line := range strings.Split(string(output), "\n") {
		match := header.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		fields := make(map[string]string)
		for _, entry := range field.FindAllStringSubmatch(match[3], -1) {
			value := entry[2]
			if strings.HasPrefix(value, `"`) {
				value, err = strconv.Unquote(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			fields[entry[1]] = value
		}
		name, task := fields["Type"], fields["Task"]
		if match[2] == "Log" {
			name = fields["Category"]
		}
		if strings.HasPrefix(match[2], "Task") {
			task = fields["ID"]
		}
		if strings.HasPrefix(name, "benchworkload.") {
			events = append(events, visitorTraceEvent{goid: match[1], task: task, kind: match[2], name: name, message: fields["Message"]})
		}
	}
	return events
}

func assertVisitorTrace(t *testing.T, events []visitorTraceEvent, enabled bool, count int, queried bool, outcome string, pids []uint32, workers int) {
	t.Helper()
	tasks := make(map[string][]visitorTraceEvent)
	var actualQueries int
	for _, event := range events {
		if event.name == "benchworkload.test.query.begin" {
			actualQueries++
		}
		if !enabled {
			if !strings.HasPrefix(event.name, "benchworkload.test.") || event.task != "0" {
				t.Fatalf("disabled tracing emitted instrumentation or wrapped the context: %+v", event)
			}
			continue
		}
		if event.task == "0" || event.task == "" {
			t.Fatalf("worker event lost its request task: %+v", event)
		}
		tasks[event.task] = append(tasks[event.task], event)
	}
	wantQueries := 0
	if queried {
		wantQueries = count
	}
	if actualQueries != wantQueries {
		t.Fatalf("parsed %d actual query calls; want %d", actualQueries, wantQueries)
	}
	if !enabled {
		return
	}
	if len(tasks) != count {
		t.Fatalf("parsed %d request tasks; want %d", len(tasks), count)
	}
	want := []string{"TaskBegin benchworkload.request", "Log benchworkload.slot", "RegionBegin benchworkload.request"}
	if queried {
		want = append(want, "Log benchworkload.postgres.client-port", "Log benchworkload.postgres.query.begin", "RegionBegin benchworkload.postgres.query", "Log benchworkload.test.client-port", "Log benchworkload.test.query.begin", "Log benchworkload.test.query.end", "RegionEnd benchworkload.postgres.query", "Log benchworkload.postgres.query.end", "RegionBegin benchworkload.postgres.cleanup", "RegionEnd benchworkload.postgres.cleanup")
	}
	want = append(want, "Log benchworkload.result", "RegionEnd benchworkload.request", "TaskEnd benchworkload.request")
	slots, goroutines, backends := make(map[int]bool), make(map[string]bool), make(map[string]bool)
	ports := make(map[string]string)
	for _, task := range tasks {
		var got []string
		goid, pid, port := task[0].goid, "", ""
		for _, event := range task {
			if event.goid != goid {
				t.Fatalf("request markers crossed worker goroutines: %+v", task)
			}
			got = append(got, event.kind+" "+event.name)
			switch event.name {
			case "benchworkload.slot":
				slot, err := strconv.Atoi(event.message)
				if err != nil || slot < 0 || slot >= count || slots[slot] {
					t.Fatalf("lost or duplicated offered slot: %+v", event)
				}
				slots[slot] = true
			case "benchworkload.postgres.client-port":
				port = event.message
				value, err := strconv.Atoi(port)
				if err != nil || value < 1 || value > 65535 {
					t.Fatalf("client port is not a numeric TCP port: %+v", event)
				}
			case "benchworkload.test.client-port":
				if event.message != port {
					t.Fatalf("request port differs from pgx's actual query connection: %+v", task)
				}
			case "benchworkload.postgres.query.begin":
				pid = event.message
				value, err := strconv.ParseUint(pid, 10, 32)
				if err != nil || !slices.Contains(pids, uint32(value)) {
					t.Fatalf("request identified a non-retained session: %+v", event)
				}
				backends[pid] = true
				if previous, ok := ports[port]; ok && previous != pid {
					t.Fatalf("retained sessions share a client port: port=%s PIDs=%s,%s", port, previous, pid)
				}
				ports[port] = pid
			case "benchworkload.postgres.query.end", "benchworkload.test.query.begin", "benchworkload.test.query.end":
				if event.message != pid {
					t.Fatalf("request PID differs from pgx's actual query connection: %+v", task)
				}
			case "benchworkload.result":
				if event.message != outcome {
					t.Fatalf("wrong request outcome: %+v; want %q", event, outcome)
				}
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("query/cleanup boundaries or task nesting changed:\n got %v\nwant %v", got, want)
		}
		goroutines[goid] = true
	}
	if len(slots) != count || len(goroutines) != workers || queried && (len(backends) != workers || len(ports) != workers) {
		t.Fatalf("missing slot/worker/session identities: slots=%v goroutines=%v backends=%v ports=%v", slots, goroutines, backends, ports)
	}
}

func TestVisitorTraceDisabledPreservesRequestContext(t *testing.T) {
	ctx := t.Context()
	_, err := runVisitors(ctx, VisitorConfig{Rate: 1, Workers: 1, QueueSlots: 1, Start: time.Now().Add(-time.Second), Duration: time.Nanosecond}, []string{"private-address"}, func(got context.Context, _ string, at time.Time) RequestResult {
		if got != ctx {
			t.Error("disabled tracing changed the request's parent context")
		}
		return RequestResult{Scheduled: at, Started: time.Now(), Duration: time.Since(at)}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVisitorTracePreservesOfferAccounting(t *testing.T) {
	var baseline VisitorResult
	for _, enabled := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			result, err := runVisitors(t.Context(), VisitorConfig{Rate: 20, Workers: 1, QueueSlots: 1, Start: time.Now(), Duration: time.Second, TraceRequests: enabled}, []string{"private-address"}, func(_ context.Context, _ string, at time.Time) RequestResult {
				began := time.Now()
				time.Sleep(300 * time.Millisecond)
				return RequestResult{Scheduled: at, Started: began, Duration: time.Since(at)}
			})
			if err != nil || result.Scheduled != 20 || result.Missed == 0 || result.Scheduled != result.Completed+result.Missed+result.QueueExpired {
				t.Fatalf("lost offers: %+v, %v", result, err)
			}
			if !enabled {
				baseline = result
			} else if result.Scheduled != baseline.Scheduled || result.Started != baseline.Started || result.Completed != baseline.Completed || result.Missed != baseline.Missed || result.QueueExpired != baseline.QueueExpired || result.OfferDuration != baseline.OfferDuration || result.DrainDuration != baseline.DrainDuration {
				t.Fatalf("tracing changed offer/queue accounting: before=%+v after=%+v", baseline, result)
			}
		})
	}
}
