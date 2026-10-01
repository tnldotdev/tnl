package controlstate

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

// isolate page processing from the cadence scheduler and competing pool users.
// the same production histograms distinguish round trips from pool waiting.
func TestProfileIngressUsage(t *testing.T) {
	f := newControlLoadFixture(t)
	const pageSize = 16
	if f.routes < pageSize {
		t.Fatal("usage profile requires at least 16 routes")
	}
	ingress := registerTestIngress(t, f.database, f.now)
	bucket := f.now.Truncate(time.Minute)
	reports := make([]IngressUsageReport, pageSize)
	for index := range reports {
		setup, err := f.database.CreatePublishRun(t.Context(), f.request(index), f.now, time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		reports[index] = IngressUsageReport{
			PublicURLID: setup.PublicURLID, PublishRunNumber: setup.PublishRunNumber,
			BucketStart: bucket, BucketEnd: bucket.Add(time.Minute), ObservedThrough: f.now,
			ReportRevision: 1, ConnectionAttempts: 1, IngressBytes: 10,
			HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary(),
		}
	}
	for _, phase := range []string{"fresh", "replay", "advance"} {
		if phase == "advance" {
			for index := range reports {
				reports[index].ReportRevision++
				reports[index].ConnectionAttempts++
				reports[index].IngressBytes += 10
			}
		}
		before, err := f.metrics[0].Gather()
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if err := f.controls[0].ReportIngressUsage(t.Context(), ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: reports}, f.now); err != nil {
			t.Fatal(err)
		}
		t.Logf("phase=%s reports=%d delay=%s elapsed=%s", phase, pageSize, f.delay, time.Since(started))
		after, err := f.metrics[0].Gather()
		if err != nil {
			t.Fatal(err)
		}
		summaries, err := observability.DurationSummaries(before, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, summary := range summaries {
			if summary.Count > 0 {
				t.Logf("phase=%s metric=%s labels=%v calls=%d total_seconds=%g", phase, summary.Name, summary.Labels, summary.Count, summary.SumSeconds)
			}
		}
	}
	var attempts, bytes int64
	if err := f.database.pool.QueryRow(t.Context(), `SELECT sum(connection_attempts), sum(ingress_bytes) FROM control.public_url_usage_buckets`).Scan(&attempts, &bytes); err != nil || attempts != 2*pageSize || bytes != 20*pageSize {
		t.Fatalf("profile accounting: attempts=%d bytes=%d: %v", attempts, bytes, err)
	}
}
