package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const postgresTargetSampleFixture = "usage_usec 100\nnr_periods 12\nnr_throttled 2\nthrottled_usec 300\n"

func TestPostgresTargetSamplerRequiresVerifiedTLS(t *testing.T) {
	for _, config := range []*pgx.ConnConfig{nil, {}} {
		if _, err := preparePostgresTargetSampler(t.Context(), config); err == nil {
			t.Fatal("accepted missing TLS configuration")
		}
	}
	config, err := pgx.ParseConfig("postgres://fixture@localhost/fixture?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.TLSConfig = &tls.Config{InsecureSkipVerify: true, ServerName: "fixture.test"}
	if _, err := preparePostgresTargetSampler(t.Context(), config); err == nil {
		t.Fatal("accepted unverified TLS")
	}
}

func TestPostgresTargetSamplerRetainsBracketAndJoinsBeforeExport(t *testing.T) {
	entered, release := make(chan context.Context, 1), make(chan struct{})
	var calls, closes atomic.Int32
	s := newPostgresTargetSampler(func(ctx context.Context) (string, []postgresTargetActivity, error) {
		calls.Add(1)
		entered <- ctx
		select {
		case <-release:
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
		return postgresTargetSampleFixture, []postgresTargetActivity{{BackendType: "client backend", State: "idle", WaitEventType: "Client", WaitEvent: "ClientRead", Count: 32}}, nil
	}, func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("observer close is unbounded")
		}
		closes.Add(1)
		return nil
	})
	if err := s.Start(t.Context(), time.Now(), time.Second); err != nil {
		t.Fatal(err)
	}
	var queryContext context.Context
	select {
	case queryContext = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("query did not start")
	}
	if deadline, ok := queryContext.Deadline(); !ok || time.Until(deadline) > postgresTargetSampleTimeout {
		t.Fatal("query timeout exceeds bound")
	}
	directory := filepath.Join(t.TempDir(), "target")
	finished := make(chan error, 1)
	go func() { finished <- s.Finish(directory) }()
	<-s.stop
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("export started before the query joined")
	}
	if queryContext.Err() != nil {
		t.Fatal("normal Finish cancelled the in-flight query")
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || closes.Load() != 1 {
		t.Fatal("extra query or observer connection lifecycle")
	}
	if err := s.Finish(directory); err != nil || closes.Load() != 1 {
		t.Fatal("Finish is not idempotent")
	}
	data, err := os.ReadFile(filepath.Join(directory, "samples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var samples []postgresTargetSample
	if err := json.Unmarshal(data, &samples); err != nil || len(samples) != 1 {
		t.Fatalf("samples: %s %v", data, err)
	}
	row := samples[0]
	if row.Slot != 0 || row.Intended != 0 || row.Started < 0 || row.Completed < row.Started || row.CPU["throttled_usec"] != 300 || len(row.Activity) != 1 || row.Activity[0].Count != 32 || row.CPUStat != postgresTargetSampleFixture {
		t.Fatalf("invalid sample: %+v", row)
	}
	for name, mode := range map[string]os.FileMode{"": 0o700, "samples.json": 0o600, "receipt.json": 0o600} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("private artifact mode for %s: %v", name, err)
		}
	}
}

func TestPostgresTargetSamplerStorageOverflowIsExplicit(t *testing.T) {
	s := newPostgresTargetSampler(func(context.Context) (string, []postgresTargetActivity, error) {
		return postgresTargetSampleFixture, nil, nil
	}, func(context.Context) error { return nil })
	// force the storage boundary independently of the normal duration deadline.
	s.samples = nil
	s.receipt.PhaseStart = time.Now()
	s.stop, s.done, s.cancel = make(chan struct{}), make(chan struct{}), func() {}
	s.run(t.Context())
	if err := s.Finish(filepath.Join(t.TempDir(), "overflow")); err == nil || !strings.Contains(err.Error(), "storage exhausted") {
		t.Fatalf("sample storage silently grew: %v", err)
	}
}

func TestPostgresTargetSamplerSkipsOverdueTicks(t *testing.T) {
	for _, tc := range []struct {
		index     int64
		completed time.Duration
		next      int64
	}{{0, 265 * time.Millisecond, 3}, {6, 603 * time.Millisecond, 7}, {6, 960 * time.Millisecond, 10}} {
		if got := nextPostgresTargetSample(tc.index, tc.completed); got != tc.next {
			t.Fatalf("next slot=%d want=%d", got, tc.next)
		}
	}
}

func TestPostgresTargetSamplerFailuresRetainPrivateReceipt(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		activity  []postgresTargetActivity
		err       error
		code      string
	}{
		{"query", postgresTargetSampleFixture, nil, &pgconn.PgError{Code: "42501", Message: "secret SQL text"}, "postgres_sqlstate_42501"},
		{"counter", "usage_usec invalid", nil, nil, "invalid_cpu_counters"},
		{"missing", "usage_usec 1", nil, nil, "cpu_counters_missing"},
		{"activity", postgresTargetSampleFixture, make([]postgresTargetActivity, 129), nil, "activity_group_bound_exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			s := newPostgresTargetSampler(func(context.Context) (string, []postgresTargetActivity, error) {
				calls++
				return tc.raw, tc.activity, tc.err
			}, func(context.Context) error { return nil })
			if err := s.Start(t.Context(), time.Now(), time.Second); err != nil {
				t.Fatal(err)
			}
			<-s.done
			directory := filepath.Join(t.TempDir(), "target")
			if err := s.Finish(directory); err == nil || !strings.Contains(err.Error(), tc.code) {
				t.Fatalf("failure not propagated: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(directory, "samples.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rows []postgresTargetSample
			if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].CPUStat != tc.raw || rows[0].Error != tc.code || calls != 1 {
				t.Fatalf("lost failure evidence or retried: %s %v", data, err)
			}
			receipt, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
			if err != nil || strings.Contains(string(receipt), "secret SQL") || !strings.Contains(string(receipt), tc.code) {
				t.Fatalf("invalid failure receipt: %s %v", receipt, err)
			}
		})
	}
}

func TestPostgresTargetSamplerCancellationAndAbortedStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	entered := make(chan struct{})
	s := newPostgresTargetSampler(func(ctx context.Context) (string, []postgresTargetActivity, error) {
		close(entered)
		<-ctx.Done()
		return "", nil, ctx.Err()
	}, func(context.Context) error { return nil })
	if err := s.Start(ctx, time.Now(), time.Second); err != nil {
		t.Fatal(err)
	}
	<-entered
	cancel()
	if err := s.Finish(filepath.Join(t.TempDir(), "cancelled")); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cancellation lost: %v", err)
	}
	for _, epoch := range []time.Time{{}, time.Now().Round(0)} {
		s := newPostgresTargetSampler(func(context.Context) (string, []postgresTargetActivity, error) {
			t.Error("query ran without a monotonic epoch")
			return "", nil, nil
		}, func(context.Context) error { return nil })
		if s.Start(t.Context(), epoch, time.Second) == nil {
			t.Fatal("accepted invalid epoch")
		}
		if s.Finish(filepath.Join(t.TempDir(), "invalid")) == nil {
			t.Fatal("invalid start not in receipt")
		}
	}
	var calls int
	s = newPostgresTargetSampler(func(context.Context) (string, []postgresTargetActivity, error) { calls++; return "", nil, nil }, func(context.Context) error { return nil })
	if err := s.Start(t.Context(), time.Now().Add(time.Hour), time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(filepath.Join(t.TempDir(), "before-phase")); err != nil || calls != 0 {
		t.Fatalf("sampled before phase start: %v", err)
	}
}
