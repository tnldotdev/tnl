package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const postgresLoadTarget = "postgres-target:5432"
const postgresLoadHostname = "db.fixture.test"
const postgresLoadMaxSamples = 1_000_000

const postgresResourceBracketNotes = "for successful phases, resource deltas span the prepared before snapshot through the pre-export after snapshot, not exact per-query CPU. " +
	"after capture starts once all visitor workers have joined; measured sessions stay open and buffered results remain retained until export authorization. " +
	"snapshots are sequential, non-atomic reads and include start delay, coordination, background leases and capture queries. " +
	"publisher diagnostics, optional profiling and enabled observer sampling can continue during the capture guard. post-run raw flush/export, PID verification and measured-session teardown follow authorization. " +
	"an aborted visitor preserves raw results and closes sessions without requiring authorization; its resource bracket is invalid."

type postgresResourceGuard struct {
	CaptureStarted   time.Time `json:"capture_started"`
	CaptureCompleted time.Time `json:"capture_completed"`
	Notes            string    `json:"notes"`
}

// publish completion even when Run returned an error or its context was cancelled.
// the caller retains sessions/results until authorization, or closes on failure.
func waitPostgresExport(ctx context.Context, coordination *benchworkload.Coordination, phase, component string) error {
	announce, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	err := coordination.Put(announce, phase+"."+component+".measured", true)
	cancel()
	if err != nil {
		return err
	}
	wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var authorized bool
	if err := coordination.Wait(wait, phase+".export", &authorized); err != nil {
		return err
	}
	if !authorized {
		return errors.New("PostgreSQL export was not authorized")
	}
	return wait.Err()
}

// preserve completed rows before the caller fails and its session defer runs.
// successful export stays on the caller's normal path; never flush it twice.
func awaitPostgresRecordingExport(ctx context.Context, coordination *benchworkload.Coordination, phase, component string, recording *postgresRecording, output io.Closer, runErr error) error {
	if barrierErr := waitPostgresExport(ctx, coordination, phase, component); barrierErr != nil {
		return errors.Join(runErr, barrierErr, recording.Flush(), output.Close())
	}
	return nil
}

// release also runs when a measured wait fails or capture calls t.Fatal. use a
// separate bounded context so cancellation cannot strand a waiting visitor.
func capturePostgresBeforeExport(ctx context.Context, coordination *benchworkload.Coordination, phase connectLoadPhase, components []string, capture func() separatedSnapshot) (after separatedSnapshot, err error) {
	defer func() {
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		err = errors.Join(err, coordination.Put(release, phase.Name+".export", true))
	}()
	wait, cancel := context.WithTimeout(ctx, phase.Duration+15*time.Second)
	defer cancel()
	for _, component := range components {
		var measured bool
		if err := coordination.Wait(wait, phase.Name+"."+component+".measured", &measured); err != nil {
			return after, err
		}
		if !measured {
			return after, fmt.Errorf("PostgreSQL visitor %s did not finish measurement", component)
		}
	}
	if err := wait.Err(); err != nil {
		return after, err
	}
	return capture(), nil
}

func postgresLoadMetadata(t *testing.T) controlv1.ServiceMetadata {
	t.Helper()
	ca, err := os.ReadFile("/database-fixture/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	trust, err := targettrust.CapturePEM(postgresLoadHostname, ca)
	if err != nil {
		t.Fatal(err)
	}
	return controlv1.ServiceMetadata{Protocol: controlv1.Postgres, TargetTls: &controlv1.ServiceTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest, Pem: new(string(trust.PEM)), System: trust.System}}
}

func postgresLoadConfig(t *testing.T, service connectLoadService, local string, direct bool) *pgx.ConnConfig {
	t.Helper()
	// both paths use SCRAM without channel binding: visitor TLS terminates at
	// the publisher, independently of the publisher's verified target TLS.
	config, err := pgx.ParseConfig("postgres://tnl_client:testpass@localhost/tnl_fixture?sslmode=verify-full&channel_binding=disable")
	if err != nil {
		t.Fatal(err)
	}
	address, hostname := service.Target, postgresLoadHostname
	var roots *x509.CertPool
	if direct {
		ca, err := os.ReadFile("/database-fixture/ca.pem")
		if err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("invalid target CA")
		}
	} else {
		address, hostname = local, service.Service.Endpoint.Hostname
		roots = separatedRoots(t, "route-roots.pem")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	config.Host, config.Port = host, uint16(number)
	config.TLSConfig = &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS12}
	config.Fallbacks = nil
	return config
}

func captureSeparatedPostgresTarget(t *testing.T) separatedResources {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), benchworkload.RequestTimeout)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, postgresLoadConfig(t, connectLoadService{Target: postgresLoadTarget}, "", true))
	if err != nil {
		t.Fatalf("connect PostgreSQL target observer: %v", err)
	}
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := connection.Close(finish); err != nil {
			t.Errorf("close PostgreSQL target observer: %v", err)
		}
	}()
	return separatedPostgresResource(t, "postgres-target", func(query string, args ...any) pgx.Row {
		return connection.QueryRow(ctx, query, args...)
	})
}

func runSeparatedPostgresVisitor(t *testing.T, ctx context.Context, component string, service connectLoadService, local string, connectorPID int, nativeTrace *postgresNativeTrace) {
	defer nativeTrace.Close()
	for sequence := range 2 {
		var phase connectLoadPhase
		if !separatedRead(t, ctx, fmt.Sprintf("connect.prepare-%d", sequence), &phase) {
			return
		}
		visitor := &benchworkload.PostgresVisitor{}
		setup, err := visitor.Prepare(ctx, postgresLoadConfig(t, service, local, phase.Direct), *runtimeLoadWorkers)
		if err != nil {
			t.Fatal(err)
		}
		// always close sessions, including a failed PID check or coordination wait.
		func() {
			defer func() {
				if err := visitor.Close(); err != nil {
					t.Error(err)
				}
			}()
			before, err := visitor.Verify(ctx)
			if err != nil {
				t.Fatal(err)
			}
			result := connectLoadResult{Setup: setup, SessionsBefore: &before, RequestsFile: fmt.Sprintf("%s-%s-requests.jsonl", phase.Name, component)}
			requestFile, err := os.Create(filepath.Join("/results", result.RequestsFile))
			if err != nil {
				t.Fatal(err)
			}
			defer requestFile.Close()
			samples, err := postgresRecordingSamples(*postgresLoadRecording, *runtimeLoadRPS, phase.Duration)
			if err != nil {
				t.Fatal(err)
			}
			metadata := postgresRecordingMetadata{Mode: *postgresLoadRecording, SchedulerClock: "monotonic_rebased_once", SampleLimit: samples, PreparationStarted: time.Now(), TimingEnabled: *postgresLoadTiming, LateDiagnostics: *postgresLoadLateDiagnostics, Notes: postgresRecordingNotes}
			metadata.RequestTracing = *postgresLoadLateDiagnostics == "trace"
			metadata.PublisherLateTracing = metadata.RequestTracing && !phase.Direct
			metadata.NativeTracing = metadata.PublisherLateTracing
			recording, err := newPostgresRecording(*postgresLoadRecording, samples, requestFile)
			if err != nil {
				t.Fatal(err)
			}
			metadata.RetainedResultCapacity = cap(recording.rows)
			metadata.RetainedResultStorageBytes = recording.storageBytes()
			var timing *benchworkload.VisitorTimings
			if *postgresLoadTiming {
				recording.enableTiming(samples, requestFile)
				timing = &recording.timing.Visitor
				metadata.TimingStorageBytes = recording.timingStorageBytes()
			}
			var target *postgresTargetSampler
			targetDirectory := filepath.Join("/results", "target-"+phase.Name+"-"+component)
			finishTarget := func() {
				if target == nil {
					return
				}
				metadata.TargetSamplerFinishStarted = time.Since(phase.Start)
				if err := target.Finish(targetDirectory); err != nil {
					t.Error(err)
				}
				metadata.TargetSamplerFinishCompleted = time.Since(phase.Start)
				target = nil
			}
			defer finishTarget()
			if *postgresLoadLateDiagnostics != "off" {
				target, err = preparePostgresTargetSampler(ctx, postgresLoadConfig(t, service, local, true))
				if err != nil {
					t.Fatal(err)
				}
				metadata.TargetObserverConnections = 1
			}
			resources, err := readSeparatedResources()
			if err != nil {
				t.Fatal(err)
			}
			metadata.MemoryLimit, metadata.CPUQuota, metadata.GOMAXPROCS = resources.MemoryLimit, resources.CPUQuota, resources.GOMAXPROCS
			metadata.PreparationCompleted = time.Now()
			separatedWrite(t, phase.Name+"."+component+".prepared", true)
			if !separatedRead(t, ctx, fmt.Sprintf("connect.phase-%d", sequence), &phase) {
				return
			}
			if *postgresLoadLateDiagnostics != "off" {
				now := time.Now()
				phase.Start = now.Add(phase.Start.Sub(now))
			}
			if metadata.NativeTracing {
				if nativeTrace == nil {
					t.Fatal("native trace owner missing for the connector trace phase")
				}
				if err := nativeTrace.Arm(ctx, phase); err != nil {
					t.Fatal(err)
				}
			}
			lateConfig := postgresLateConfig{Phase: phase.Name, Start: phase.Start, Duration: phase.Duration, ConnectorPID: connectorPID}
			publisherTrace := *postgresLoadLateDiagnostics == "trace" && !phase.Direct
			if publisherTrace {
				coordination := separatedCoordination(t)
				lateConfig.Notify = func(notify context.Context, event postgresLateTrigger) error {
					return errors.Join(nativeTrace.Trigger(notify, event), coordination.Put(notify, phase.Name+".late-trigger", event))
				}
			}
			late := startPostgresLateDiagnostic(ctx, lateConfig)
			lateDirectory := filepath.Join("/results", "late-"+phase.Name+"-"+component)
			finishLate := func() {
				if late == nil {
					return
				}
				if err := late.Finish(lateDirectory); err != nil {
					t.Error(err)
				}
				late = nil
				if publisherTrace {
					finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), benchworkload.RequestTimeout)
					defer cancel()
					// notification and capture have joined before no-event is visible.
					if err := separatedCoordination(t).Put(finish, phase.Name+".late-finished", true); err != nil {
						t.Error(err)
					}
				}
			}
			defer func() {
				finishTarget()
				finishLate()
			}()
			if target != nil {
				if err := target.Start(ctx, phase.Start, phase.Duration); err != nil {
					t.Fatal(err)
				}
			}
			var observe func(benchworkload.VisitorRequestTiming)
			if late != nil {
				observe = func(row benchworkload.VisitorRequestTiming) {
					late.Observe(row.Slot, row.Started, row.Completed, row.CallbackStarted, row.CallbackCompleted)
				}
			}
			result.Summary, err = visitor.Run(ctx, benchworkload.VisitorConfig{Rate: *runtimeLoadRPS, Workers: *runtimeLoadWorkers, QueueSlots: *runtimeLoadQueue, Start: phase.Start, Duration: phase.Duration, OnResult: recording.Record, Timing: timing, OnTiming: observe, TraceRequests: *postgresLoadLateDiagnostics == "trace"})
			metadata.MeasurementCompleted = time.Now()
			// keep diagnostic Finish/export calls after this guard; enabled samplers
			// may continue while the coordinator captures resources.
			if exportErr := awaitPostgresRecordingExport(ctx, separatedCoordination(t), phase.Name, component, recording, requestFile, err); exportErr != nil {
				t.Fatal(exportErr)
			}
			metadata.ExportAuthorized = time.Now()
			finishTarget()
			finishLate()
			if metadata.NativeTracing {
				metadata.NativeFinishStarted = time.Since(phase.Start)
				if err := nativeTrace.Finish(ctx); err != nil {
					t.Error(err)
				}
				metadata.NativeFinishCompleted = time.Since(phase.Start)
				metadata.NativeReceipt = nativeTrace.Receipt()
			}
			// publish only metadata, and only once the complete artifact is visible.
			metadata.FlushStarted = time.Now()
			if err := errors.Join(err, recording.Flush(), requestFile.Close()); err != nil {
				t.Error(err)
			}
			metadata.FlushCompleted = time.Now()
			if recording.timing != nil {
				metadata.TimingWriteStarted = time.Now()
				separatedResult(t, phase.Name+"-"+component+"-timing", recording.timing)
				metadata.TimingWriteCompleted = time.Now()
			}
			metadata.MetadataWriteStarted = time.Now()
			separatedResult(t, phase.Name+"-"+component+"-recording", metadata)
			after, err := visitor.Verify(ctx)
			result.SessionsAfter = &after
			if err != nil {
				t.Error(err)
			}
			separatedWrite(t, phase.Name+"."+component, result)
		}()
	}
	var done connectLoadPhase
	if separatedRead(t, ctx, "connect.phase-2", &done) && !done.Done {
		t.Fatal("expected end of PostgreSQL workload")
	}
}
