package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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

func runSeparatedPostgresVisitor(t *testing.T, ctx context.Context, component string, service connectLoadService, local string) {
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
			metadata := postgresRecordingMetadata{Mode: *postgresLoadRecording, SchedulerClock: "monotonic_rebased_once", SampleLimit: samples, PreparationStarted: time.Now(), TimingEnabled: *postgresLoadTiming, Notes: postgresRecordingNotes}
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
			result.Summary, err = visitor.Run(ctx, benchworkload.VisitorConfig{Rate: *runtimeLoadRPS, Workers: *runtimeLoadWorkers, QueueSlots: *runtimeLoadQueue, Start: phase.Start, Duration: phase.Duration, OnResult: recording.Record, Timing: timing})
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
