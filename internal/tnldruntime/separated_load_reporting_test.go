package tnldruntime

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/observability"
)

func separatedResult(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/results", name+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func separatedCapture(t *testing.T, database *sql.DB, name string) separatedSnapshot {
	t.Helper()
	result := separatedSnapshot{Resources: make(map[string]separatedResources), Metrics: make(map[string][]*dto.MetricFamily)}
	coordinator, err := readSeparatedResources()
	if err != nil {
		t.Fatal(err)
	}
	coordinator.NetworkNamespace = "coordinator"
	result.Resources["coordinator"] = coordinator
	for _, component := range separatedActiveComponents() {
		result.Resources[component] = separatedResource(t, component)
	}
	// read the PostgreSQL process's own cgroup/proc files through the disposable
	// superuser connection, avoiding a metrics sidecar in its memory budget.
	postgres, err := readSeparatedResourceFiles(func(path string) (string, error) {
		var text string
		err := database.QueryRowContext(integrationOperationContext(t), `SELECT pg_read_file($1, 0, 65536)`, path).Scan(&text)
		return strings.TrimSpace(text), err
	})
	if err != nil {
		t.Fatal(err)
	}
	postgres.Postgres = &separatedPostgresResources{}
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT
		(SELECT coalesce(sum(allocated_size), 0)::bigint FROM pg_shmem_allocations),
		pg_size_bytes(current_setting('shared_buffers')),
		numbackends, blks_read, blks_hit, temp_bytes
		FROM pg_stat_database WHERE datname = current_database()`).Scan(
		&postgres.Postgres.SharedMemoryBytes, &postgres.Postgres.SharedBuffersBytes,
		&postgres.Postgres.Backends, &postgres.Postgres.BlocksRead,
		&postgres.Postgres.BlocksHit, &postgres.Postgres.TempBytes,
	); err != nil {
		t.Fatal(err)
	}
	postgres.NetworkNamespace = "postgres"
	result.Resources["postgres"] = postgres
	for _, role := range separatedServerRoles() {
		response, err := integrationGET(integrationOperationContext(t), &http.Client{Timeout: 2 * time.Second}, "http://"+role+":9090/metrics")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("metrics %s: %v status=%d", role, err, response.StatusCode)
		}
		if err := os.WriteFile(filepath.Join("/results", name+"-"+role+".prom"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		families, err := observability.ParseMetrics(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		result.Metrics[role] = families
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/results", name+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return result
}

func separatedReportResources(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	for _, component := range append(separatedActiveComponents(), "postgres", "coordinator") {
		a, b := before.Resources[component], after.Resources[component]
		if a.ProcessRunID != b.ProcessRunID {
			t.Logf("separated_resource phase=%s component=%s interval_reset=true before_run=%s after_run=%s memory=%d peak=%d fds=%d memory_anon=%d memory_file=%d memory_kernel=%d memory_kernel_stack=%d memory_pagetables=%d memory_sock=%d memory_slab=%d memory_shmem=%d memory_file_dirty=%d memory_file_writeback=%d memory_high_events=%d memory_max_events=%d oom_events=%d oom_kills=%d",
				phase, component, a.ProcessRunID, b.ProcessRunID, b.Memory, b.Peak, b.OpenFileDescriptors,
				b.MemoryAnon, b.MemoryFile, b.MemoryKernel, b.MemoryKernelStack, b.MemoryPageTables, b.MemorySock, b.MemorySlab, b.MemoryShmem,
				b.MemoryFileDirty, b.MemoryFileWriteback, b.MemoryHighEvents, b.MemoryMaxEvents, b.OOMEvents, b.OOMKills)
			if b.OOMKills != 0 {
				t.Errorf("%s OOM after restart", component)
			}
			continue
		}
		seconds := b.At.Sub(a.At).Seconds()
		t.Logf("separated_resource phase=%s component=%s interval=%.3fs quota=%q memory_limit=%q cpu_seconds=%.6f cpu_cores=%.4f throttled_seconds=%.6f throttled_periods=%d/%d memory=%d peak=%d fds=%d memory_anon=%d memory_file=%d memory_kernel=%d memory_kernel_stack=%d memory_pagetables=%d memory_sock=%d memory_slab=%d memory_shmem=%d memory_file_dirty=%d memory_file_writeback=%d memory_high_events=%d memory_max_events=%d oom_events=%d oom_kills=%d rx_bytes=%d tx_bytes=%d gomaxprocs=%d network_namespace=%s",
			phase, component, seconds, b.CPUQuota, b.MemoryLimit, float64(b.CPUUsec-a.CPUUsec)/1e6, float64(b.CPUUsec-a.CPUUsec)/1e6/seconds,
			float64(b.ThrottledUsec-a.ThrottledUsec)/1e6, b.ThrottledPeriods-a.ThrottledPeriods, b.Periods-a.Periods, b.Memory, b.Peak, b.OpenFileDescriptors,
			b.MemoryAnon, b.MemoryFile, b.MemoryKernel, b.MemoryKernelStack, b.MemoryPageTables, b.MemorySock, b.MemorySlab, b.MemoryShmem,
			b.MemoryFileDirty, b.MemoryFileWriteback, b.MemoryHighEvents-a.MemoryHighEvents, b.MemoryMaxEvents-a.MemoryMaxEvents,
			b.OOMEvents-a.OOMEvents, b.OOMKills-a.OOMKills,
			b.ReceiveBytes-a.ReceiveBytes, b.SendBytes-a.SendBytes, b.GOMAXPROCS, b.NetworkNamespace)
		if b.OOMKills > a.OOMKills {
			t.Errorf("%s OOM in %s", component, phase)
		}
		if component == "postgres" && a.Postgres != nil && b.Postgres != nil {
			t.Logf("separated_postgres phase=%s shared_memory=%d shared_buffers=%d backends=%d blocks_read=%d blocks_hit=%d temp_bytes=%d",
				phase, b.Postgres.SharedMemoryBytes, b.Postgres.SharedBuffersBytes, b.Postgres.Backends,
				b.Postgres.BlocksRead-a.Postgres.BlocksRead, b.Postgres.BlocksHit-a.Postgres.BlocksHit, b.Postgres.TempBytes-a.Postgres.TempBytes)
		}
	}
	for _, role := range separatedServerRoles() {
		if role == "relay-a" && (phase == "relay-restart" || phase == "relay-kill") || role == "control-a" && phase == "control-restart" {
			continue
		} // new runtime registry.
		summaries, err := separatedDurationSummaries(before, after, role)
		if err != nil {
			t.Fatal(err)
		}
		for _, summary := range summaries {
			if summary.Count > 0 && summary.Name != "tnl_database_query_duration_seconds" {
				t.Logf("separated_duration phase=%s role=%s metric=%s labels=%v calls=%d mean_seconds=%g", phase, role, summary.Name, summary.Labels, summary.Count, summary.MeanSeconds)
			}
		}
	}
}

func separatedReportBandwidth(t *testing.T, name string, start time.Time, duration time.Duration, config *benchworkload.BandwidthConfig, results []separatedVisitorResult, combined bool) benchworkload.BandwidthResult {
	t.Helper()
	aggregate := benchworkload.BandwidthResult{
		Direction: config.Direction, StreamsPerDirection: config.Streams,
		TargetBytesPerSecond: config.BytesPerSecond, TargetDuration: duration, StartedAt: start,
	}
	for _, result := range results {
		if result.Bandwidth == nil {
			t.Error("bandwidth visitor returned no result")
			continue
		}
		bandwidth := result.Bandwidth
		aggregate.Elapsed = max(aggregate.Elapsed, bandwidth.Elapsed)
		aggregate.ExpectedUploadBytes += bandwidth.ExpectedUploadBytes
		aggregate.UploadBytes += bandwidth.UploadBytes
		aggregate.ExpectedDownloadBytes += bandwidth.ExpectedDownloadBytes
		aggregate.DownloadBytes += bandwidth.DownloadBytes
		aggregate.Failures += bandwidth.Failures
		for _, sample := range bandwidth.FailureSamples {
			if len(aggregate.FailureSamples) < 8 {
				aggregate.FailureSamples = append(aggregate.FailureSamples, sample)
			}
		}
	}
	if err := aggregate.Err(); err != nil {
		t.Error(err)
	}
	seconds := aggregate.Elapsed.Seconds()
	aggregate.UploadBytesPerSecond = float64(aggregate.UploadBytes) / seconds
	aggregate.DownloadBytesPerSecond = float64(aggregate.DownloadBytes) / seconds
	uploadMbits, downloadMbits := aggregate.UploadBytesPerSecond*8/1_000_000, aggregate.DownloadBytesPerSecond*8/1_000_000
	t.Logf("separated_bandwidth phase=%s direction=%s streams_per_direction=%d target_mbits_per_second=%d upload_mbits_per_second=%.3f download_mbits_per_second=%.3f failures=%d elapsed=%s",
		name, aggregate.Direction, aggregate.StreamsPerDirection, *runtimeLoadBandwidthMbits, uploadMbits, downloadMbits, aggregate.Failures, aggregate.Elapsed)
	summaryName := name + "-summary"
	if combined {
		summaryName = name + "-bandwidth-summary"
	}
	separatedResult(t, summaryName, aggregate)
	return aggregate
}

func separatedCollectVisitors(t *testing.T, phase string, timeout time.Duration) []separatedVisitorResult {
	t.Helper()
	var results []separatedVisitorResult
	for i := 1; i <= 4; i++ {
		var result separatedVisitorResult
		separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase, i), timeout, &result)
		if result.RequestsFile != "" {
			path := filepath.Join("/results", result.RequestsFile)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(file)
			for {
				var row benchworkload.RequestResult
				if err := decoder.Decode(&row); err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				result.Requests = append(result.Requests, row)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if len(result.Requests) != result.Completed+result.QueueExpired {
				t.Fatalf("%s request artifact: got %d rows, want %d", path, len(result.Requests), result.Completed+result.QueueExpired)
			}
		}
		results = append(results, result)
	}
	separatedResult(t, phase+"-visitors", results)
	return results
}

type separatedHeldSummary struct {
	Requested       int           `json:"requested"`
	Opened          int           `json:"opened"`
	Surviving       int           `json:"surviving"`
	Progressing     int           `json:"progressing"`
	Closed          int           `json:"closed"`
	OpeningDuration time.Duration `json:"opening_duration"`
}

func separatedReportHeld(t *testing.T, phase string, results []separatedVisitorResult, expected int, opening, measuring, closing bool) {
	t.Helper()
	var summary separatedHeldSummary
	for _, result := range results {
		summary.Requested += result.HeldRequested
		summary.Opened += result.HeldOpened
		summary.Surviving += result.HeldSurviving
		summary.Progressing += result.HeldProgressing
		summary.Closed += result.HeldClosed
		summary.OpeningDuration = max(summary.OpeningDuration, result.HeldOpeningDuration)
	}
	t.Logf("separated_held phase=%s requested=%d opened=%d surviving=%d progressing=%d closed=%d opening_duration=%s", phase,
		summary.Requested, summary.Opened, summary.Surviving, summary.Progressing, summary.Closed, summary.OpeningDuration)
	separatedResult(t, phase+"-held-summary", summary)
	if opening && (summary.Requested != expected || summary.Opened != expected || summary.Surviving != expected) {
		t.Errorf("%s: requested=%d opened=%d surviving=%d, want %d", phase, summary.Requested, summary.Opened, summary.Surviving, expected)
	}
	if measuring && (summary.Surviving != expected || summary.Progressing != expected) {
		t.Errorf("%s: surviving=%d progressing=%d, want %d", phase, summary.Surviving, summary.Progressing, expected)
	}
	if closing && summary.Closed != expected {
		t.Errorf("%s: closed=%d, want %d", phase, summary.Closed, expected)
	}
}

func separatedReportVisitors(t *testing.T, phase string, results []separatedVisitorResult, restart separatedRestart, repaired time.Time) {
	t.Helper()
	var first, firstExit time.Time
	failures, missed, total, surviving := 0, 0, 0, 0
	var merged benchworkload.VisitorResult
	var successfulDurations []time.Duration
	cohorts := make(map[string]benchworkload.VisitorResult)
	healthy, progressing := 0, 0
	for _, result := range results {
		healthy += result.HealthyHeld
		progressing += result.HealthyHeldProgress
		for name, summary := range result.Cohorts {
			cohort := cohorts[name]
			if err := cohort.Merge(summary); err != nil {
				t.Fatal(err)
			}
			cohorts[name] = cohort
		}
		if err := merged.Merge(result.VisitorResult); err != nil {
			t.Fatal(err)
		}
		missed += result.Missed + result.QueueExpired
		surviving += result.HeldSurviving
		for _, row := range result.Requests {
			total++
			if phase == "relay-kill" {
				if err := validateRelayKillVisitor(row, restart.Exited); err != nil {
					t.Error(err)
				}
			}
			if row.Error != "" {
				failures++
				if failures <= 3 {
					t.Logf("separated_request_failure phase=%s started=%s error=%s", phase, row.Started, row.Error)
				}
				if phase == "control-restart" || phase != "relay-kill" && (runtimeControlledFault(phase) || phase != *runtimeLoadScenario || !row.Started.Before(repaired)) {
					t.Errorf("visitor failed in %s after recovery=%t", phase, !row.Started.Before(repaired))
				}
				continue
			}
			successfulDurations = append(successfulDurations, row.Duration)
			if !row.Started.Before(restart.Started) && (first.IsZero() || row.FirstByte.Before(first)) {
				first = row.FirstByte
			}
			if !row.Started.Before(restart.Exited) && (firstExit.IsZero() || row.FirstByte.Before(firstExit)) {
				firstExit = row.FirstByte
			}
		}
	}
	slices.Sort(successfulDurations)
	var exactP95, exactP99 *float64
	if len(successfulDurations) > 0 {
		p95 := float64(exactLatencyPercentile(successfulDurations, 95)) / float64(time.Millisecond)
		p99 := float64(exactLatencyPercentile(successfulDurations, 99)) / float64(time.Millisecond)
		exactP95, exactP99 = &p95, &p99
	}
	format := func(value *float64) string {
		if value == nil {
			return "unavailable"
		}
		return fmt.Sprintf("%.3fms", *value)
	}
	t.Logf("separated_visitors phase=%s requests=%d success=%d failures=%d missed=%d p50=%s p95=%s p95_exact=%s p99_exact=%s maximum=%.3fms first_body_byte_p95=%s offer=%s drain=%s", phase, total, merged.Successes, failures, missed,
		format(merged.Total.Percentile(50)), format(merged.Total.Percentile(95)), format(exactP95), format(exactP99), merged.Total.MaximumMilliseconds, format(merged.FirstByte.Percentile(95)), merged.OfferDuration, merged.DrainDuration)
	separatedResult(t, phase+"-summary", merged)
	separatedResult(t, phase+"-exact-latency", struct {
		Samples         int      `json:"samples"`
		P95Milliseconds *float64 `json:"p95_milliseconds"`
		P99Milliseconds *float64 `json:"p99_milliseconds"`
	}{len(successfulDurations), exactP95, exactP99})
	if missed != 0 || total == 0 {
		t.Errorf("phase %s: missed=%d requests=%d", phase, missed, total)
	}
	separatedResult(t, phase+"-cohorts", cohorts)
	if runtimeBlackhole(phase) {
		t.Logf("healthy_held_streams alive=%d progressing=%d", healthy, progressing)
		if healthy == 0 || progressing != healthy {
			t.Error("healthy-path held streams did not survive")
		}
	}
	if phase == *runtimeLoadScenario {
		if first.IsZero() || firstExit.IsZero() {
			t.Error("no successful visitor during recovery")
		}
		if phase == "forwarding-blackhole" {
			t.Logf("separated_recovery first_body_after_drop_applied=%s verified_recovery_after_rule_removal=%s held_surviving=%d", firstExit.Sub(restart.Exited), repaired.Sub(restart.Restored), surviving)
		} else {
			t.Logf("separated_recovery first_body_after_stop=%s first_body_after_exit=%s runtime_exit=%s all_connections_repaired=%s held_surviving=%d", first.Sub(restart.Started), firstExit.Sub(restart.Exited), restart.Exited.Sub(restart.Started), repaired.Sub(restart.Started), surviving)
		}
		separatedResult(t, phase+"-recovery", struct {
			Scenario                                          string
			Fault                                             separatedRestart
			FirstSuccessfulBodyAfterApplied, VerifiedRecovery time.Time
			HeldSurviving                                     int
		}{phase, restart, firstExit, repaired, surviving})
	}
}

func exactLatencyPercentile(sorted []time.Duration, percentile int) time.Duration {
	return sorted[(len(sorted)*percentile+99)/100-1]
}

func TestExactLatencyPercentileUsesRequestSamples(t *testing.T) {
	var sorted []time.Duration
	for i := 1; i <= 100; i++ {
		sorted = append(sorted, time.Duration(i)*time.Millisecond)
	}
	if got := exactLatencyPercentile(sorted, 95); got != 95*time.Millisecond {
		t.Fatalf("exact p95 = %s", got)
	}
	if got := exactLatencyPercentile(sorted[:21], 95); got != 20*time.Millisecond {
		t.Fatalf("exact p95 for 21 samples = %s", got)
	}
}

func validateRelayKillVisitor(row benchworkload.RequestResult, relayExited time.Time) error {
	if relayExited.IsZero() {
		return fmt.Errorf("relay-kill visitor has no relay exit boundary")
	}
	if row.Started.Before(relayExited) {
		return fmt.Errorf("relay-kill visitor started before relay exit")
	}
	if row.Error != "" {
		return fmt.Errorf("relay-kill visitor failed after relay exit: %s", row.Error)
	}
	return nil
}

func assertRelayOpenedVisitors(t *testing.T, before, after separatedSnapshot, role string) {
	t.Helper()
	count := func(snapshot separatedSnapshot) uint64 {
		var count uint64
		for _, family := range snapshot.Metrics[role] {
			if family.GetName() != "tnl_relay_operation_duration_seconds" {
				continue
			}
			for _, metric := range family.Metric {
				labels := make(map[string]string)
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["operation"] == "RelayOpenVisitorStream" && labels["outcome"] == "success" {
					count += metric.GetHistogram().GetSampleCount()
				}
			}
		}
		return count
	}
	if count(after) <= count(before) {
		t.Errorf("%s accepted no visitor streams during measurement", role)
	}
}
