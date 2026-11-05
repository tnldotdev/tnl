package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/trace"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestSeparatedPublisherDiagnosticsOffAndValidation(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(t.Context(), contextKey{}, "unchanged")
	directory := filepath.Join(t.TempDir(), "unused")
	got, diagnostics, err := newSeparatedPublisherDiagnostics(ctx, "off", directory)
	if err != nil || got != ctx || diagnostics != nil || observability.FromContext(got) != nil {
		t.Fatalf("off changed the context or created an owner: %v", err)
	}
	diagnostics.Capture(t, ctx, "../ignored", time.Time{}, 0)
	diagnostics.Close(t)
	for _, mode := range []string{"", "CPU", "metrics,cpu", "unknown"} {
		if _, _, err := newSeparatedPublisherDiagnostics(ctx, mode, directory); err == nil {
			t.Fatalf("accepted diagnostic mode %q", mode)
		}
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("off/invalid modes touched the filesystem: %v", err)
	}
	for _, name := range []string{"", "../escape", "a/b", "payload\n", strings.Repeat("a", 81)} {
		if publisherDiagnosticName(name) {
			t.Fatalf("accepted artifact name %q", name)
		}
	}
	if !publisherDiagnosticName("connect-postgres-warm") {
		t.Fatal("rejected warm phase name")
	}
	ctx, diagnostics, err = newSeparatedPublisherDiagnostics(ctx, "metrics", directory)
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostics.Close(t)
	if observability.FromContext(ctx) != diagnostics.owner {
		t.Fatal("publisher context lacks its diagnostic owner")
	}
	if err := diagnostics.capture(ctx, "../escape", time.Now(), time.Minute); err == nil {
		t.Fatal("capture accepted an unsafe phase name")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := diagnostics.capture(cancelled, "cancelled", time.Now(), time.Minute); err != context.Canceled {
		t.Fatalf("scheduled capture ignored cancellation: %v", err)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 {
		t.Fatalf("validation/pre-start cancellation wrote artifacts: %v", err)
	}
	diagnostics.Close(t)
	diagnostics.Close(t)
	if err := diagnostics.capture(ctx, "closed", time.Now(), time.Minute); err == nil {
		t.Fatal("capture accepted a closed owner")
	}
}

func TestSeparatedPublisherDiagnosticsProfiles(t *testing.T) {
	// never change the parent's profilers: go test may own CPU, trace, mutex, or
	// block profiling. children receive only an exact selector, not those flags.
	fraction, tracing := runtime.SetMutexProfileFraction(-1), trace.IsEnabled()
	output, err := runPublisherDiagnosticChild(t, "TestSeparatedPublisherDiagnosticsProfilerChild")
	if err != nil {
		t.Fatalf("profiler helper: %v\n%s", err, output)
	}
	if runtime.SetMutexProfileFraction(-1) != fraction || trace.IsEnabled() != tracing {
		t.Fatal("child captures changed the parent's profilers")
	}
}

func TestSeparatedPublisherDiagnosticsReportsCanceledWriteErrors(t *testing.T) {
	output, err := runPublisherDiagnosticChild(t, "TestSeparatedPublisherDiagnosticsCaptureFailureChild")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("expected a reported capture failure: %v\n%s", err, output)
	}
	for _, message := range []string{"publisher diagnostics:", "context canceled", "after-metrics.json", "capture.json"} {
		if !bytes.Contains(output, []byte(message)) {
			t.Fatalf("capture hid joined error %q:\n%s", message, output)
		}
	}
}

func TestSeparatedPublisherDiagnosticsProfilerChild(t *testing.T) {
	requirePublisherDiagnosticChild(t)
	for _, mode := range []string{"metrics", "cpu", "contention", "trace"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "diagnostics")
			ctx, diagnostics, err := newSeparatedPublisherDiagnostics(t.Context(), mode, directory)
			if err != nil {
				t.Fatal(err)
			}
			defer diagnostics.Close(t)
			observability.PublisherReadinessStatus(ctx, true, true, true, time.Now(), time.Now())
			previous := runtime.SetMutexProfileFraction(7)
			defer runtime.SetMutexProfileFraction(previous)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			started := false
			diagnostics.recordingStarted = func() {
				started = true
				cancel() // after preparation and successful runtime writer startup
			}
			// this is a normal phase budget, not a cancellation deadline. the
			// explicit start barrier ends recording without any timed race.
			start, duration := time.Now(), 30*time.Second
			diagnostics.Capture(t, ctx, "connect-postgres-warm", start, duration)
			if !started {
				t.Fatal("cancellation did not follow recording startup")
			}
			if got := runtime.SetMutexProfileFraction(-1); got != 7 {
				t.Fatalf("mutex sampling fraction not restored: %d", got)
			}
			if trace.IsEnabled() {
				t.Fatal("runtime tracing leaked beyond capture")
			}
			phaseDirectory := filepath.Join(directory, "connect-postgres-warm")
			data := readPublisherDiagnosticTestFile(t, phaseDirectory, "capture.json")
			var capture publisherDiagnosticCapture
			if err := json.Unmarshal(data, &capture); err != nil {
				t.Fatal(err)
			}
			if capture.Mode != mode || !capture.MetricsOwnerAttached || capture.Phase != "connect-postgres-warm" || !capture.Cancelled || !capture.PhaseStart.Equal(start) || capture.PhaseDuration != duration || capture.StopGuard != publisherDiagnosticGuard || capture.AllocationSampleRate != runtime.MemProfileRate {
				t.Fatalf("incorrect capture metadata: %+v", capture)
			}
			limit := 10 * time.Second
			if mode == "trace" {
				limit = 2 * time.Second
			}
			if capture.WindowLimit != limit || capture.StopTarget.After(start.Add(duration-publisherDiagnosticGuard)) || capture.StopTarget.After(capture.StartRequested.Add(limit)) {
				t.Fatalf("incorrect recording timing: %+v", capture)
			}
			times := []time.Time{
				start, capture.PreparationStarted, capture.MetricsBefore.Started, capture.MetricsBefore.Completed,
				capture.PreparationCompleted, capture.Before.Started, capture.Before.Completed,
				capture.StartRequested, capture.Started, capture.StopRequested, capture.Flushed,
				capture.After.Started, capture.After.Completed, capture.MetricsAfter.Started,
				capture.MetricsAfter.Completed, capture.MetadataWriteStarted,
			}
			for index, at := range times {
				if at.IsZero() || (index > 0 && at.Before(times[index-1])) {
					t.Fatalf("incorrect snapshot/start/stop/write bounds: %+v", capture)
				}
			}
			if len(capture.Delta) == 0 {
				t.Fatal("missing runtime counter snapshots and deltas")
			}
			if _, exists := capture.Delta["/cpu/classes/total:cpu-seconds"]; exists {
				t.Fatal("available CPU capacity must not be presented as CPU usage")
			}
			for _, note := range []string{"off-vs-metrics", "artifact writes", "profiler startup, stop/flush", "recording_stop_requested"} {
				if !strings.Contains(capture.Notes, note) {
					t.Fatalf("missing measurement boundary note %q", note)
				}
			}
			for name, before := range capture.Before.Values {
				if capture.Delta[name] != capture.After.Values[name]-before {
					t.Fatalf("incorrect runtime delta for %s", name)
				}
			}
			for _, when := range []string{"before", "after"} {
				metrics := readPublisherDiagnosticTestFile(t, phaseDirectory, when+"-metrics.json")
				if !json.Valid(metrics) || !bytes.Contains(metrics, []byte("tnl_publisher_ready")) {
					t.Fatalf("missing publisher metrics in %s", when)
				}
				assertPublisherDiagnosticGzip(t, readPublisherDiagnosticTestFile(t, phaseDirectory, when+"-allocs.pb.gz"))
				if mode == "contention" {
					for _, profile := range []string{"mutex", "block"} {
						assertPublisherDiagnosticGzip(t, readPublisherDiagnosticTestFile(t, phaseDirectory, when+"-"+profile+".pb.gz"))
					}
				}
			}
			if mode == "cpu" {
				assertPublisherDiagnosticGzip(t, readPublisherDiagnosticTestFile(t, phaseDirectory, "cpu.pb.gz"))
			}
			if mode == "trace" {
				data := readPublisherDiagnosticTestFile(t, phaseDirectory, "trace.out")
				if len(data) < 16 || !bytes.Contains(data[:16], []byte("trace")) {
					t.Fatal("missing runtime trace header")
				}
			}
			// separately exercise successful stop/flush and CPU/trace restart.
			// preparation is complete and no small phase budget includes it.
			var successful publisherDiagnosticCapture
			if err := recordPublisherDiagnosticWindow(t.Context(), t.TempDir(), mode, time.Now(), &successful, nil); err != nil {
				t.Fatalf("restart after cancellation: %v", err)
			}
			if successful.Started.IsZero() || successful.StopRequested.Before(successful.Started) || successful.Flushed.Before(successful.StopRequested) || runtime.SetMutexProfileFraction(-1) != 7 || trace.IsEnabled() {
				t.Fatal("successful capture did not stop, flush, and restore profiling")
			}
		})
	}
}

func TestSeparatedPublisherDiagnosticsCaptureFailureChild(t *testing.T) {
	requirePublisherDiagnosticChild(t)
	ctx, diagnostics, err := newSeparatedPublisherDiagnostics(t.Context(), "metrics", filepath.Join(t.TempDir(), "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostics.Close(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	diagnostics.recordingStarted = func() {
		for _, name := range []string{"after-metrics.json", "capture.json"} {
			if err := os.WriteFile(filepath.Join(diagnostics.directory, "write-failure", name), []byte("occupied"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cancel()
	}
	// the parent expects this test to fail with cancellation AND both write errors.
	diagnostics.Capture(t, ctx, "write-failure", time.Now(), 30*time.Second)
}

func requirePublisherDiagnosticChild(t *testing.T) {
	t.Helper()
	if flag.Lookup("test.run").Value.String() != "^"+t.Name()+"$" {
		t.Skip("exact-selector diagnostic subprocess only")
	}
	for _, name := range []string{"test.cpuprofile", "test.trace", "test.blockprofile", "test.mutexprofile"} {
		if flag.Lookup(name).Value.String() != "" {
			t.Skip("diagnostic subprocess must not inherit external profiler flags")
		}
	}
}

func runPublisherDiagnosticChild(t *testing.T, name string) ([]byte, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exec.CommandContext(t.Context(), executable, "-test.run=^"+name+"$", "-test.timeout=1m").CombinedOutput()
}

func readPublisherDiagnosticTestFile(t *testing.T, directory, name string) []byte {
	t.Helper()
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("diagnostic directory is not private: %v", err)
	}
	path := filepath.Join(directory, name)
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("diagnostic file %s is not private: %v", name, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("empty diagnostic file %s: %v", name, err)
	}
	return data
}

func assertPublisherDiagnosticGzip(t *testing.T, data []byte) {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	written, err := io.Copy(io.Discard, reader)
	err = errors.Join(err, reader.Close())
	if err != nil || written == 0 {
		t.Fatalf("empty or incomplete profile: %v", err)
	}
}
