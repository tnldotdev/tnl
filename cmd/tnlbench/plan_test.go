package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testWorkload() workloadOptions {
	return workloadOptions{Suite: "smoke", ProfileFile: "../../benchmarks/fly.json", Routes: 4, FreshRate: 16, HeldStreams: 4, Concurrency: 128, QueueSlots: 8, PayloadBytes: 32768, Repetitions: 1, Warmup: 5 * time.Second, Duration: 10 * time.Second, CertificateAuthority: "pebble"}
}
func TestPlanOneTargetAndSourceSafeDistribution(t *testing.T) {
	c := testWorkload()
	c.Suite = "target"
	c.Routes = 64
	c.FreshRate = 160
	c.Repetitions = 3
	p, err := c.build()
	if err != nil {
		t.Fatal(err)
	}
	if p.Target.LoadWorkers != 6 || p.Target.PublisherWorkers != 1 || p.Target.Repetitions != 3 || p.Target.Concurrency != 128 || p.Topology != testTopology() {
		t.Fatalf("plan=%+v", p)
	}
	c.Concurrency = 5
	if _, err := c.build(); err == nil {
		t.Fatal("accepted more generators than request concurrency")
	}
}
func TestPlanRejectsRetiredSuitesAndOversizedPublicCA(t *testing.T) {
	c := testWorkload()
	c.Suite = "scout"
	if _, err := c.build(); err == nil {
		t.Fatal("accepted retired scout")
	}
	c.Suite = "target"
	c.CertificateAuthority = "letsencrypt"
	if _, err := c.build(); err == nil {
		t.Fatal("accepted large public CA workload")
	}
}
func TestPlanOutputReadOnlyAndWriterError(t *testing.T) {
	p, err := testWorkload().build()
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if err := writeHumanPlan(&text, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "READ ONLY") || !strings.Contains(text.String(), "BENCH_APPROVED=1") || strings.Contains(text.String(), "$") {
		t.Fatal(text.String())
	}
	want := errors.New("writer failed")
	if err := writeHumanPlan(errorWriter{want}, p); !errors.Is(err, want) {
		t.Fatal(err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }
func TestDecodeJSONFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(`{"unknown":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var profile benchmarkProfile
	if decodeJSONFile(path, &profile) == nil {
		t.Fatal("accepted unknown configuration")
	}
}
