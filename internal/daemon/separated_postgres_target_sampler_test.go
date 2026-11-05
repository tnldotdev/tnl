package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const postgresTargetSampleInterval = 100 * time.Millisecond
const postgresTargetSampleTimeout = 5 * time.Second
const postgresTargetSampleLimit = int((5*time.Minute+postgresTargetSampleTimeout)/postgresTargetSampleInterval) + 2

// the observer excludes itself and never selects SQL text, identities or payloads.
const postgresTargetSampleSQL = `SELECT pg_read_file('/sys/fs/cgroup/cpu.stat', 0, 65536),
	COALESCE((SELECT jsonb_agg(to_jsonb(activity)) FROM (
		SELECT backend_type, COALESCE(state, '') AS state,
			COALESCE(wait_event_type, '') AS wait_event_type,
			COALESCE(wait_event, '') AS wait_event, count(*) AS count
		FROM pg_stat_activity WHERE pid <> pg_backend_pid()
		GROUP BY 1, 2, 3, 4 ORDER BY 1, 2, 3, 4 LIMIT 129
	) activity), '[]'::jsonb)`

type postgresTargetActivity struct {
	BackendType   string `json:"backend_type"`
	State         string `json:"state"`
	WaitEventType string `json:"wait_event_type"`
	WaitEvent     string `json:"wait_event"`
	Count         int64  `json:"count"`
}

type postgresTargetSample struct {
	Slot      int64                    `json:"slot"`
	Intended  time.Duration            `json:"intended_ns"`
	Started   time.Duration            `json:"started_ns"`
	Completed time.Duration            `json:"completed_ns"`
	Lateness  time.Duration            `json:"lateness_ns"`
	Skipped   int64                    `json:"skipped"`
	CPUStat   string                   `json:"cpu_stat"`
	CPU       map[string]uint64        `json:"cpu"`
	Activity  []postgresTargetActivity `json:"activity"`
	Error     string                   `json:"error,omitempty"`
}

type postgresTargetReceipt struct {
	PhaseStart  time.Time     `json:"phase_start"`
	Duration    time.Duration `json:"duration_ns"`
	Interval    time.Duration `json:"interval_ns"`
	ObserverPID uint32        `json:"observer_pid"`
	SampleLimit int           `json:"sample_limit"`
	SampleCount int           `json:"sample_count"`
	Error       string        `json:"error,omitempty"`
	Notes       string        `json:"notes"`
}

type postgresTargetSampler struct {
	query          func(context.Context) (string, []postgresTargetActivity, error)
	close          func(context.Context) error
	samples        []postgresTargetSample
	receipt        postgresTargetReceipt
	stop, done     chan struct{}
	cancel         context.CancelFunc
	parent         context.Context
	finish         sync.Once
	finished       bool
	err, finishErr error
}

// prepare before the prepared barrier with postgresLoadConfig(..., true).
// this connection belongs only to diagnostics, never the measured session pool.
func preparePostgresTargetSampler(ctx context.Context, config *pgx.ConnConfig) (*postgresTargetSampler, error) {
	if config == nil || config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || config.TLSConfig.ServerName == "" {
		return nil, errors.New("target sampler requires a verified TLS configuration")
	}
	cfg := config.Copy()
	cfg.Fallbacks, cfg.DefaultQueryExecMode = nil, pgx.QueryExecModeSimpleProtocol
	bounded, cancel := context.WithTimeout(ctx, postgresTargetSampleTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(bounded, cfg)
	if err != nil {
		return nil, fmt.Errorf("prepare target sampler: %s", postgresTargetSampleError(err))
	}
	s := newPostgresTargetSampler(func(ctx context.Context) (raw string, activity []postgresTargetActivity, err error) {
		err = conn.QueryRow(ctx, postgresTargetSampleSQL).Scan(&raw, &activity)
		return
	}, conn.Close)
	s.receipt.ObserverPID = conn.PgConn().PID()
	return s, nil
}

func newPostgresTargetSampler(query func(context.Context) (string, []postgresTargetActivity, error), close func(context.Context) error) *postgresTargetSampler {
	return &postgresTargetSampler{query: query, close: close, samples: make([]postgresTargetSample, 0, postgresTargetSampleLimit), receipt: postgresTargetReceipt{Interval: postgresTargetSampleInterval,
		Notes: "diagnostic-only extra direct verified-TLS connection, no pool or reconnect; observer backend excluded from activity counts and measured sessions. run matched controls with this observer present. offsets use the visitor's monotonic epoch. target counter and activity reads occur within the response bracket, not exactly at either endpoint. observer delay includes target, network and visitor scheduling. skipped ticks are not replayed. sampling continues through request drain until Finish, at most duration plus 5s; Finish allows the one bounded in-flight query to complete before closing. no SQL text or credentials retained."}}
}

// Start and Finish are caller-serialized; Finish is idempotent and must follow
// every successful prepare, including an aborted phase or a failed Start.
func (s *postgresTargetSampler) Start(ctx context.Context, epoch time.Time, duration time.Duration) error {
	if s.finished || s.done != nil {
		return errors.New("target sampler already started or finished")
	}
	if epoch.IsZero() || epoch == epoch.Round(0) || duration <= 0 || duration > 5*time.Minute {
		s.err = errors.New("target sampler requires the visitor's monotonic epoch and duration up to 5m")
		return s.err
	}
	s.receipt.PhaseStart, s.receipt.Duration = epoch, duration
	s.receipt.SampleLimit = int((duration+postgresTargetSampleTimeout)/postgresTargetSampleInterval) + 2
	s.samples = s.samples[:0:s.receipt.SampleLimit]
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	s.parent = ctx
	ctx, s.cancel = context.WithDeadline(ctx, epoch.Add(duration+postgresTargetSampleTimeout))
	go s.run(ctx)
	return nil
}

func (s *postgresTargetSampler) run(ctx context.Context) {
	defer close(s.done)
	epoch := s.receipt.PhaseStart
	timer := time.NewTimer(max(0, time.Until(epoch)))
	defer timer.Stop()
	for index := int64(0); ; {
		select {
		case <-s.stop:
			return
		case <-ctx.Done():
			s.err = fmt.Errorf("target sampling stopped: %s", postgresTargetSampleError(ctx.Err()))
			return
		case <-timer.C:
		}
		select {
		case <-s.stop:
			return
		default:
		}
		row := postgresTargetSample{Slot: index, Intended: time.Duration(index) * postgresTargetSampleInterval, Started: time.Since(epoch)}
		row.Lateness = max(0, row.Started-row.Intended)
		bounded, cancel := context.WithTimeout(ctx, postgresTargetSampleTimeout)
		raw, activity, err := s.query(bounded)
		row.Completed = time.Since(epoch)
		cancel()
		row.CPUStat, row.Activity = raw, activity
		if err != nil {
			row.Error = postgresTargetSampleError(err)
		}
		if raw != "" {
			var parseErr error
			row.CPU, parseErr = parsePostgresLateCounters(raw)
			if parseErr != nil {
				row.Error = "invalid_cpu_counters"
				err = errors.Join(err, errors.New(row.Error))
			}
		}
		if len(activity) > 128 {
			row.Activity = nil
			row.Error = "activity_group_bound_exceeded"
			err = errors.Join(err, errors.New(row.Error))
		}
		if err == nil {
			for _, key := range []string{"usage_usec", "nr_periods", "nr_throttled", "throttled_usec"} {
				if _, ok := row.CPU[key]; !ok {
					row.Error = "cpu_counters_missing"
					err = errors.New(row.Error)
					break
				}
			}
		}
		if err != nil {
			s.err = fmt.Errorf("target sample %d: %s", index, row.Error)
		}
		next := nextPostgresTargetSample(index, row.Completed)
		row.Skipped = next - index - 1
		if len(s.samples) == cap(s.samples) {
			s.err = errors.Join(s.err, errors.New("target sample storage exhausted"))
			return
		}
		s.samples = append(s.samples, row)
		if err != nil {
			return
		}
		index = next
		timer.Reset(max(0, time.Until(epoch.Add(time.Duration(index)*postgresTargetSampleInterval))))
	}
}

func nextPostgresTargetSample(index int64, completed time.Duration) int64 {
	return max(index+1, int64(completed/postgresTargetSampleInterval)+1)
}

func postgresTargetSampleError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && len(pgerr.Code) == 5 {
		return "postgres_sqlstate_" + pgerr.Code
	}
	return "observer_operation_failed"
}

// Finish stops new queries, joins the one query bounded to 5s, closes the
// observer with its own deadline, then writes to a new private directory.
func (s *postgresTargetSampler) Finish(directory string) error {
	if s == nil {
		return nil
	}
	s.finish.Do(func() {
		s.finished = true
		if s.done != nil {
			close(s.stop)
			<-s.done
			s.cancel()
		}
		if s.parent != nil && s.parent.Err() != nil {
			s.err = errors.Join(s.err, fmt.Errorf("target sampler parent: %s", postgresTargetSampleError(s.parent.Err())))
		}
		bounded, cancel := context.WithTimeout(context.Background(), postgresTargetSampleTimeout)
		if err := s.close(bounded); err != nil {
			s.err = errors.Join(s.err, fmt.Errorf("close target observer: %s", postgresTargetSampleError(err)))
		}
		cancel()
		if err := os.Mkdir(directory, 0o700); err != nil {
			s.finishErr = errors.Join(s.err, err)
			return
		}
		write := func(name string, value any) error {
			file, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			return errors.Join(json.NewEncoder(file).Encode(value), file.Close())
		}
		s.err = errors.Join(s.err, write("samples.json", s.samples))
		s.receipt.SampleCount = len(s.samples)
		if s.err != nil {
			s.receipt.Error = s.err.Error()
		}
		s.finishErr = errors.Join(s.err, write("receipt.json", s.receipt))
		s.samples = nil
	})
	return s.finishErr
}
