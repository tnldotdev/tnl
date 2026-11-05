package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

func postgresBarrierCoordination(t *testing.T) *benchworkload.Coordination {
	t.Helper()
	server := httptest.NewServer(benchworkload.NewCoordinator().Handler("barrier-test"))
	t.Cleanup(server.Close)
	coordination, err := benchworkload.NewCoordination(server.URL, "barrier-test")
	if err != nil {
		t.Fatal(err)
	}
	return coordination
}

func TestPostgresExportBarrierCapturePrecedesExportAndClose(t *testing.T) {
	coordination := postgresBarrierCoordination(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	phase := connectLoadPhase{Name: "postgres", Duration: time.Second}
	directory := t.TempDir()
	result := connectLoadResult{RequestsFile: "requests.jsonl"}
	file, err := os.Create(filepath.Join(directory, result.RequestsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	recording, err := newPostgresRecording("buffered", 1, file)
	if err != nil {
		t.Fatal(err)
	}
	row := benchworkload.RequestResult{URL: "postgres", Duration: time.Millisecond}
	recording.Record(row)
	result.Summary.Observe(row)
	steps := make(chan string, 8)
	visitorDone := make(chan error, 1)
	sessionClosed := make(chan struct{})
	go func() {
		defer close(sessionClosed)
		defer func() { steps <- "close" }()
		err := awaitPostgresRecordingExport(ctx, coordination, phase.Name, "visitor-1", recording, file, nil)
		if err == nil {
			steps <- "flush"
			err = errors.Join(recording.Flush(), file.Close())
		}
		if err == nil {
			steps <- "verify"
			err = coordination.Put(ctx, phase.Name+".visitor-1", result)
			steps <- "result"
		}
		visitorDone <- err
	}()
	captureStarted, finishCapture := make(chan struct{}), make(chan struct{})
	coordinatorDone := make(chan error, 1)
	go func() {
		after, err := capturePostgresBeforeExport(ctx, coordination, phase, []string{"visitor-1", "visitor-2"}, func() separatedSnapshot {
			steps <- "capture-start"
			close(captureStarted)
			select {
			case <-finishCapture:
			case <-ctx.Done():
			}
			steps <- "capture-end"
			return separatedSnapshot{Resources: map[string]separatedResources{"postgres-target": {CPUUsec: 123}}}
		})
		if err == nil && after.Resources["postgres-target"].CPUUsec != 123 {
			err = errors.New("lost the guarded snapshot")
		}
		coordinatorDone <- err
	}()
	if err := coordination.Wait(ctx, phase.Name+".visitor-1.measured", nil); err != nil {
		t.Fatal(err)
	}
	// the second measured event is held back while the first visitor is ready.
	select {
	case <-captureStarted:
		t.Fatal("capture started before every visitor finished")
	default:
	}
	if err := coordination.Put(ctx, phase.Name+".visitor-2.measured", true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-captureStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, event := range []string{phase.Name + ".export", phase.Name + ".visitor-1"} {
		if exists, err := coordination.Get(ctx, event, nil); err != nil || exists {
			t.Fatalf("event %s visible during capture: exists=%t err=%v", event, exists, err)
		}
	}
	select {
	case <-sessionClosed:
		t.Fatal("measured session closed during capture")
	default:
	}
	close(finishCapture)
	if err := <-coordinatorDone; err != nil {
		t.Fatal(err)
	}
	if err := <-visitorDone; err != nil {
		t.Fatal(err)
	}
	<-sessionClosed
	close(steps)
	var got []string
	for step := range steps {
		got = append(got, step)
	}
	if want := []string{"capture-start", "capture-end", "flush", "verify", "result", "close"}; !slices.Equal(got, want) {
		t.Fatalf("lifecycle order=%v, want %v", got, want)
	}
	if exists, err := coordination.Get(ctx, phase.Name+".visitor-1", &result); err != nil || !exists {
		t.Fatalf("final result missing: exists=%t err=%v", exists, err)
	}
	if err := forEachConnectLoadRequest(directory, result, func(benchworkload.RequestResult) {}); err != nil {
		t.Fatalf("successful export lost or duplicated rows: %v", err)
	}
}

func TestPostgresExportBarrierCancelledRecordingPreservesRows(t *testing.T) {
	for _, mode := range []string{"live", "buffered"} {
		for _, when := range []string{"before-barrier", "during-barrier"} {
			t.Run(mode+"/"+when, func(t *testing.T) {
				coordination := postgresBarrierCoordination(t)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				visitor, stop := context.WithCancel(ctx)
				defer stop()
				directory := t.TempDir()
				result := connectLoadResult{RequestsFile: "requests.jsonl"}
				file, err := os.Create(filepath.Join(directory, result.RequestsFile))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				recording, err := newPostgresRecording(mode, 3, file)
				if err != nil {
					t.Fatal(err)
				}
				var expected bytes.Buffer
				for _, row := range []benchworkload.RequestResult{
					{URL: "postgres", Duration: time.Millisecond},
					{URL: "postgres", Duration: 2 * time.Millisecond, Error: "query failed"},
					{URL: "postgres", QueueExpired: true, Error: "queue expired"},
				} {
					recording.Record(row)
					result.Summary.Observe(row)
					if err := json.NewEncoder(&expected).Encode(row); err != nil {
						t.Fatal(err)
					}
				}
				if when == "before-barrier" {
					stop()
				}
				runErr := errors.New("visitor run failed")
				done := make(chan error, 1)
				go func() {
					done <- awaitPostgresRecordingExport(visitor, coordination, "postgres", "visitor-1", recording, file, runErr)
				}()
				if err := coordination.Wait(ctx, "postgres.visitor-1.measured", nil); err != nil {
					t.Fatal(err)
				}
				stop()
				if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(err, runErr) {
					t.Fatalf("lost run or barrier error: %v", err)
				}
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("raw artifact was not closed before returning failure: %v", err)
				}
				data, err := os.ReadFile(filepath.Join(directory, result.RequestsFile))
				if err != nil || !bytes.Equal(data, expected.Bytes()) {
					t.Fatalf("aborted export lost or duplicated completed rows: data=%s err=%v", data, err)
				}
				if err := forEachConnectLoadRequest(directory, result, func(benchworkload.RequestResult) {}); err != nil {
					t.Fatal(err)
				}
				for _, event := range []string{"postgres.export", "postgres.visitor-1"} {
					if exists, err := coordination.Get(ctx, event, nil); err != nil || exists {
						t.Fatalf("aborted export published %s: exists=%t err=%v", event, exists, err)
					}
				}
			})
		}
	}
}

type postgresBarrierCloseError struct {
	err   error
	calls int
}

func (c *postgresBarrierCloseError) Close() error {
	c.calls++
	return c.err
}

func TestPostgresExportBarrierAbortJoinsArtifactErrors(t *testing.T) {
	coordination := postgresBarrierCoordination(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runErr, writeErr, closeErr := errors.New("run failed"), errors.New("write failed"), errors.New("close failed")
	recording, err := newPostgresRecording("buffered", 1, postgresErrorWriter{writeErr})
	if err != nil {
		t.Fatal(err)
	}
	recording.Record(benchworkload.RequestResult{URL: "postgres"})
	output := &postgresBarrierCloseError{err: closeErr}
	err = awaitPostgresRecordingExport(ctx, coordination, "postgres", "visitor-1", recording, output, runErr)
	for _, want := range []error{runErr, context.Canceled, writeErr, closeErr} {
		if !errors.Is(err, want) {
			t.Errorf("lost %v: %v", want, err)
		}
	}
	if output.calls != 1 {
		t.Fatalf("artifact close calls=%d, want 1 even after flush failure", output.calls)
	}
}

func TestPostgresExportBarrierReleasesOnCoordinatorAbort(t *testing.T) {
	for _, abort := range []string{"capture-goexit", "wait-cancelled"} {
		t.Run(abort, func(t *testing.T) {
			coordination := postgresBarrierCoordination(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			phase := connectLoadPhase{Name: "postgres", Duration: time.Second}
			visitorDone := make(chan error, 1)
			go func() { visitorDone <- waitPostgresExport(ctx, coordination, phase.Name, "visitor-1") }()
			if err := coordination.Wait(ctx, phase.Name+".visitor-1.measured", nil); err != nil {
				t.Fatal(err)
			}
			coordinatorDone := make(chan struct{})
			go func() {
				defer close(coordinatorDone)
				if abort == "capture-goexit" {
					_, _ = capturePostgresBeforeExport(ctx, coordination, phase, []string{"visitor-1"}, func() separatedSnapshot {
						// t.Fatal uses Goexit; its defers must authorize export too.
						runtime.Goexit()
						return separatedSnapshot{}
					})
					t.Error("capture returned after Goexit")
					return
				}
				stopped, stop := context.WithCancel(ctx)
				stop()
				_, err := capturePostgresBeforeExport(stopped, coordination, phase, []string{"visitor-1", "visitor-2"}, func() separatedSnapshot {
					t.Error("capture ran after cancellation")
					return separatedSnapshot{}
				})
				if !errors.Is(err, context.Canceled) {
					t.Errorf("lost cancellation: %v", err)
				}
			}()
			select {
			case <-coordinatorDone:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := <-visitorDone; err != nil {
				t.Fatalf("coordinator abort stranded visitor: %v", err)
			}
		})
	}
}

func TestPostgresExportBarrierCancelledVisitorStillAnnouncesMeasured(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-barrier", false: "during-barrier"}[before], func(t *testing.T) {
			coordination := postgresBarrierCoordination(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			visitor, stop := context.WithCancel(ctx)
			defer stop()
			if before {
				stop()
			}
			closed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				defer close(closed)
				done <- waitPostgresExport(visitor, coordination, "postgres", "visitor-1")
			}()
			if err := coordination.Wait(ctx, "postgres.visitor-1.measured", nil); err != nil {
				t.Fatalf("cancelled Run did not announce completion: %v", err)
			}
			stop()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("lost visitor cancellation: %v", err)
			}
			<-closed
			if exists, err := coordination.Get(ctx, "postgres.export", nil); err != nil || exists {
				t.Fatalf("visitor needed export authorization to close: exists=%t err=%v", exists, err)
			}
		})
	}
}
