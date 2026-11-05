package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

var postgresLoadRecording = flag.String("tnl-postgres-load-recording", "live", "PostgreSQL raw results: live or buffered until the phase finishes")
var postgresLoadTiming = flag.Bool("tnl-postgres-load-timing", false, "record bounded visitor offer, collector, and file-write timings in memory; export after the phase")

const postgresRecordingNotes = "buffered retains the preallocated raw-result backing array through the phase and flush; storage bytes exclude referenced strings and are not measured RSS. no forced GC. " +
	"publisher capture preparation and writes remain separate confounds; inspect its capture.json bounds. " + postgresResourceBracketNotes + " inspect the phase resource-guard artifact for coordinator capture bounds. metadata_write_started excludes this metadata write itself. " +
	"timing offsets use the visitor's monotonic phase epoch; completed_ns precedes deferred request cleanup, request_returned_ns follows it; result_index is 1-based JSONL order and slot is 0-based. " +
	"collector_unlock_started_ns precedes unlock; collector_released_ns can include scheduling after unlock. file writes can contain bytes from several results."

type postgresRecording struct {
	Record  func(benchworkload.RequestResult)
	writer  *bufio.Writer
	encoder *json.Encoder
	rows    []benchworkload.RequestResult
	err     error
	timing  *postgresRecordingTiming
}

type postgresRecordingMetadata struct {
	Mode                       string    `json:"mode"`
	SchedulerClock             string    `json:"scheduler_clock"`
	SampleLimit                int       `json:"sample_limit"`
	RetainedResultCapacity     int       `json:"retained_result_capacity"`
	RetainedResultStorageBytes int64     `json:"retained_result_storage_bytes"`
	PreparationStarted         time.Time `json:"preparation_started"`
	PreparationCompleted       time.Time `json:"preparation_completed"`
	MeasurementCompleted       time.Time `json:"measurement_completed"`
	ExportAuthorized           time.Time `json:"export_authorized"`
	FlushStarted               time.Time `json:"flush_started"`
	FlushCompleted             time.Time `json:"flush_completed"`
	TimingEnabled              bool      `json:"timing_enabled"`
	TimingStorageBytes         int64     `json:"timing_storage_bytes"`
	TimingWriteStarted         time.Time `json:"timing_write_started,omitzero"`
	TimingWriteCompleted       time.Time `json:"timing_write_completed,omitzero"`
	MetadataWriteStarted       time.Time `json:"metadata_write_started"`
	MemoryLimit                string    `json:"memory_limit"`
	CPUQuota                   string    `json:"cpu_quota"`
	GOMAXPROCS                 int       `json:"gomaxprocs"`
	Notes                      string    `json:"notes"`
}

func postgresRecordingSamples(mode string, rate int, duration time.Duration) (int, error) {
	if mode != "live" && mode != "buffered" {
		return 0, errors.New("PostgreSQL result recording must be live or buffered")
	}
	if rate < 1 || rate > 10000 || duration <= 0 || duration > 5*time.Minute {
		return 0, errors.New("invalid PostgreSQL result recording rate or duration")
	}
	samples := (int64(rate)*int64(duration) + int64(time.Second) - 1) / int64(time.Second)
	if samples > postgresLoadMaxSamples {
		return 0, fmt.Errorf("postgres load allows at most %d offered queries per phase; reduce RPS or duration", postgresLoadMaxSamples)
	}
	return int(samples), nil
}

func newPostgresRecording(mode string, samples int, output io.Writer) (*postgresRecording, error) {
	if mode != "live" && mode != "buffered" || samples < 1 || samples > postgresLoadMaxSamples {
		return nil, errors.New("invalid PostgreSQL result recording mode or sample bound")
	}
	r := &postgresRecording{writer: bufio.NewWriter(output)}
	r.encoder = json.NewEncoder(r.writer)
	// live keeps the original serialized encoder and 4 KiB writer path.
	r.Record = func(row benchworkload.RequestResult) {
		if r.err == nil {
			r.err = r.encoder.Encode(row)
		}
	}
	if mode == "buffered" {
		// allocate before the visitor's prepared barrier, never grow during Run.
		r.rows = make([]benchworkload.RequestResult, 0, samples)
		r.Record = func(row benchworkload.RequestResult) {
			if len(r.rows) == cap(r.rows) {
				r.err = errors.New("PostgreSQL result recording exceeded its offered-query bound")
				return
			}
			r.rows = append(r.rows, row)
		}
	}
	return r, nil
}

func (r *postgresRecording) storageBytes() int64 {
	return int64(cap(r.rows)) * int64(reflect.TypeFor[benchworkload.RequestResult]().Size())
}

func (r *postgresRecording) Flush() error {
	if r.timing != nil {
		r.timing.DuringRun = false
	}
	var writeErr error
	for index, row := range r.rows {
		if r.timing != nil {
			r.timing.resultIndex = index + 1
		}
		if writeErr == nil {
			writeErr = r.encoder.Encode(row)
		}
	}
	return errors.Join(r.err, writeErr, r.writer.Flush())
}

type postgresWriteTiming struct {
	ResultIndex int           `json:"result_index"`
	Started     time.Duration `json:"started_ns"`
	Completed   time.Duration `json:"completed_ns"`
	Bytes       int           `json:"bytes"`
	Failed      bool          `json:"failed"`
	DuringRun   bool          `json:"during_run"`
}

type postgresRecordingTiming struct {
	Visitor     benchworkload.VisitorTimings `json:"visitor"`
	Writes      []postgresWriteTiming        `json:"writes"`
	DuringRun   bool                         `json:"-"`
	output      io.Writer
	resultIndex int
}

func (r *postgresRecording) enableTiming(samples int, output io.Writer) {
	r.timing = &postgresRecordingTiming{
		Visitor: benchworkload.VisitorTimings{Requests: make([]benchworkload.VisitorRequestTiming, samples)},
		Writes:  make([]postgresWriteTiming, 0, samples+1), output: output, DuringRun: true,
	}
	r.writer = bufio.NewWriter(r.timing)
	r.encoder = json.NewEncoder(r.writer)
	record := r.Record
	r.Record = func(row benchworkload.RequestResult) {
		r.timing.resultIndex++
		record(row)
	}
}

func (w *postgresRecordingTiming) Write(data []byte) (int, error) {
	if len(w.Writes) == cap(w.Writes) {
		return 0, errors.New("PostgreSQL file-write timing exceeded its preallocated bound")
	}
	started := time.Since(w.Visitor.Start)
	n, err := w.output.Write(data)
	w.Writes = append(w.Writes, postgresWriteTiming{ResultIndex: w.resultIndex, Started: started, Completed: time.Since(w.Visitor.Start), Bytes: n, Failed: err != nil || n != len(data), DuringRun: w.DuringRun})
	return n, err
}

func (r *postgresRecording) timingStorageBytes() int64 {
	if r.timing == nil {
		return 0
	}
	return int64(len(r.timing.Visitor.Requests))*int64(reflect.TypeFor[benchworkload.VisitorRequestTiming]().Size()) + int64(cap(r.timing.Writes))*int64(reflect.TypeFor[postgresWriteTiming]().Size())
}
