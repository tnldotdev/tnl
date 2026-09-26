package ingress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publicurlusage"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestNewUsageReporterRejectsNegativeInterval(t *testing.T) {
	t.Parallel()
	if _, err := NewUsageReporter(&usageControlStub{}, -time.Second, nil); err == nil {
		t.Fatal("NewUsageReporter accepted a negative interval")
	}
}

func TestUsageReporterRetriesExactCumulativeReport(t *testing.T) {
	control := &usageControlStub{err: errors.New("unavailable")}
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	connection := reporter.Open("route-a", 3, netip.MustParseAddr("192.0.2.1"), base.Add(time.Second))
	connection.PolicyDenied(base.Add(2 * time.Second))
	connection.Close(base.Add(3 * time.Second))
	if err := reporter.flush(t.Context(), base.Add(10*time.Second), false); !errors.Is(err, control.err) {
		t.Fatalf("first flush error = %v", err)
	}
	if len(control.calls) != 1 || len(control.calls[0].reports) != 1 {
		t.Fatalf("first reports = %#v", control.calls)
	}
	first := control.calls[0].reports[0]
	if first.ReportRevision != 1 || first.ConnectionAttempts != 1 || first.PolicyDenials != 1 || first.Final {
		t.Fatalf("first report = %#v", first)
	}
	control.err = nil
	if err := reporter.flush(t.Context(), base.Add(20*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || !reflect.DeepEqual(control.calls[0], control.calls[1]) {
		t.Fatalf("retried reports = %#v", control.calls)
	}
}

func TestUsageReporterFinalizesConnectionDurationAcrossMinuteBuckets(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	connection := reporter.Open("route-a", 3, netip.MustParseAddr("192.0.2.1"), base.Add(50*time.Second))
	connection.StreamOpened(base.Add(50 * time.Second))
	connection.AddIngress(5, base.Add(65*time.Second))
	connection.AddEgress(7, base.Add(70*time.Second))
	connection.Close(base.Add(80 * time.Second))
	if err := reporter.flush(t.Context(), base.Add(80*time.Second), true); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 1 || len(control.calls[0].reports) != 2 ||
		control.calls[0].observedThrough == nil || !control.calls[0].complete {
		t.Fatalf("final reports = %#v", control.calls)
	}
	first, second := control.calls[0].reports[0], control.calls[0].reports[1]
	if !first.Final || first.ConnectionAttempts != 1 || first.SuccessfulStreams != 1 ||
		first.ConnectionNanoseconds != int64(10*time.Second) || first.IngressBytes != 0 || first.EgressBytes != 0 {
		t.Fatalf("first bucket = %#v", first)
	}
	if !second.Final || second.ConnectionAttempts != 0 || second.SuccessfulStreams != 0 ||
		second.ConnectionNanoseconds != int64(20*time.Second) || second.IngressBytes != 5 || second.EgressBytes != 7 {
		t.Fatalf("second bucket = %#v", second)
	}
}

func TestUsageReporterSendsFinalRevisionAfterCheckpoint(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	connection := reporter.Open("route-a", 3, netip.MustParseAddr("192.0.2.1"), base.Add(time.Second))
	connection.Close(base.Add(2 * time.Second))
	if err := reporter.flush(t.Context(), base.Add(10*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if err := reporter.flush(t.Context(), base.Add(time.Minute), false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || control.calls[0].reports[0].Final || !control.calls[1].reports[0].Final ||
		control.calls[1].reports[0].ReportRevision != 2 {
		t.Fatalf("reports = %#v", control.calls)
	}
}

func TestUsageReporterAdvancesIdleWatermark(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 4, 12, 0, 10, 0, time.UTC)
	if err := reporter.flush(t.Context(), now, false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 1 || len(control.calls[0].reports) != 0 || control.calls[0].complete ||
		control.calls[0].observedThrough == nil || !control.calls[0].observedThrough.Equal(now) {
		t.Fatalf("idle checkpoint = %#v", control.calls)
	}
}

func TestUsageReporterRefreshesRejectedIdleWatermark(t *testing.T) {
	control := &usageControlStub{err: errors.New("unavailable")}
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 9, 4, 12, 0, 10, 0, time.UTC)
	if err := reporter.flush(t.Context(), first, false); !errors.Is(err, control.err) {
		t.Fatalf("first flush error = %v", err)
	}
	control.err = nil
	second := first.Add(10 * time.Second)
	if err := reporter.flush(t.Context(), second, false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || control.calls[0].observedThrough == nil ||
		!control.calls[0].observedThrough.Equal(first) || control.calls[1].observedThrough == nil ||
		!control.calls[1].observedThrough.Equal(second) {
		t.Fatalf("idle checkpoints = %#v", control.calls)
	}
}

func TestUsageReporterCompletesOnlyFinalPage(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	for index := range 33 {
		connection := reporter.Open(
			fmt.Sprintf("route-%03d", index), 1, netip.MustParseAddr("192.0.2.1"), base,
		)
		connection.PolicyDenied(base)
		connection.Close(base)
	}
	if err := reporter.flush(t.Context(), base.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 3 || len(control.calls[0].reports) != 16 || len(control.calls[1].reports) != 16 || len(control.calls[2].reports) != 1 ||
		control.calls[0].observedThrough != nil || control.calls[0].complete ||
		control.calls[1].observedThrough != nil || control.calls[1].complete ||
		control.calls[2].observedThrough == nil || !control.calls[2].complete {
		t.Fatalf("final pages = %#v", control.calls)
	}
}

func TestUsageReporterMovesLateEventsPastCommittedWatermark(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	watermark := base.Add(time.Minute)
	if err := reporter.flush(t.Context(), watermark, false); err != nil {
		t.Fatal(err)
	}
	connection := reporter.Open("route-a", 1, netip.MustParseAddr("192.0.2.1"), base)
	connection.PolicyDenied(base)
	connection.Close(base)
	if err := reporter.flush(t.Context(), watermark.Add(time.Second), false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || len(control.calls[1].reports) != 1 ||
		!control.calls[1].reports[0].BucketStart.Equal(watermark) {
		t.Fatalf("late event reports = %#v", control.calls)
	}
}

func TestUsageReporterCapturesHistogramsAndVisitorSketch(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	connection := reporter.Open("route-a", 3, netip.MustParseAddr("192.0.2.1"), base.Add(time.Second))
	connection.VisitorStreamOpening(base.Add(2 * time.Second))
	connection.VisitorStreamOpened(base.Add(5 * time.Second))
	connection.StreamOpened(base.Add(6 * time.Second))
	connection.AddEgress(10, base.Add(10*time.Second))
	connection.Close(base.Add(16 * time.Second))
	if err := reporter.flush(t.Context(), base.Add(20*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 1 || len(control.calls[0].reports) != 1 {
		t.Fatalf("reports = %#v", control.calls)
	}
	checkpoint, err := publicurlusage.ParseCheckpoint(control.calls[0].reports[0].HistogramData)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.VisitorStreamOpenLatency.Count() != 1 ||
		checkpoint.VisitorStreamOpenLatency.SumNanoseconds() != uint64(3*time.Second) ||
		checkpoint.TimeToFirstPublisherByte.Count() != 1 ||
		checkpoint.TimeToFirstPublisherByte.SumNanoseconds() != uint64(9*time.Second) ||
		checkpoint.SuccessfulConnectionDuration.Count() != 1 ||
		checkpoint.SuccessfulConnectionDuration.SumNanoseconds() != uint64(10*time.Second) ||
		checkpoint.VisitorNetworks.Estimate() != 1 {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
}

type usageControlStub struct {
	calls    []usageReportBatch
	err      error
	onReport func(usageReportBatch) error
}

func (s *usageControlStub) ReportUsage(_ context.Context, batch usageReportBatch) error {
	cloned := batch
	cloned.reports = append([]ingressv1.IngressUsageReport(nil), batch.reports...)
	for index := range cloned.reports {
		cloned.reports[index].HistogramData = append([]byte(nil), batch.reports[index].HistogramData...)
	}
	if batch.observedThrough != nil {
		value := *batch.observedThrough
		cloned.observedThrough = &value
	}
	s.calls = append(s.calls, cloned)
	if s.onReport != nil {
		return s.onReport(batch)
	}
	return s.err
}

func TestUsageReporterFreezesCheckpointWhileFirstPageBlocked(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	source := netip.MustParseAddr("192.0.2.1")
	for index := range 257 {
		connection := reporter.Open(fmt.Sprintf("route-%03d", index), 1, source, base)
		connection.Close(base)
	}
	started, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	control.onReport = func(usageReportBatch) error {
		if len(control.calls) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	done := make(chan error, 1)
	cutoff := base.Add(59 * time.Second)
	go func() { done <- reporter.flush(ctx, cutoff, false) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Mutate the first page and an unsent page, then cross the minute while the
	// request is blocked. None of these events belong to the frozen checkpoint.
	for _, name := range []string{"route-000", "route-256"} {
		connection := reporter.Open(name, 1, source, cutoff)
		connection.Close(cutoff)
	}
	connection := reporter.Open("new-minute", 1, source, base.Add(61*time.Second))
	connection.Close(base.Add(61 * time.Second))
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for index, batch := range control.calls {
		if (batch.observedThrough != nil) != (index == len(control.calls)-1) {
			t.Fatal("watermark before all pages acknowledged")
		}
		for _, report := range batch.reports {
			if report.ObservedThrough.Before(report.BucketStart) || report.PublicUrlId == "new-minute" || seen[report.PublicUrlId] || report.ConnectionAttempts != 1 {
				t.Fatalf("checkpoint changed during drain: route=%s attempts=%d start=%s observed=%s duplicate=%t", report.PublicUrlId, report.ConnectionAttempts, report.BucketStart, report.ObservedThrough, seen[report.PublicUrlId])
			}
			seen[report.PublicUrlId] = true
		}
	}
	if len(seen) != 257 {
		t.Fatalf("reported %d routes", len(seen))
	}
	control.calls = nil
	control.onReport = nil
	// A delayed ticker timestamp must not predate an already observed mutation.
	if err := reporter.flush(ctx, cutoff, false); err != nil {
		t.Fatal(err)
	}
	found := false
	mutated := 0
	for _, batch := range control.calls {
		for _, report := range batch.reports {
			if report.ObservedThrough.Before(report.BucketStart) {
				t.Fatal("stale cutoff created invalid report")
			}
			if report.PublicUrlId == "new-minute" {
				found = true
			}
			if report.PublicUrlId == "route-000" || report.PublicUrlId == "route-256" {
				if report.ConnectionAttempts != 2 {
					t.Fatal("next checkpoint lost concurrent mutation")
				}
				mutated++
			}
		}
	}
	if !found || mutated != 2 {
		t.Fatal("next checkpoint lost concurrent bucket")
	}
}

func TestUsageReporterLostPageResponseRetriesFrozenPayloadBeforeClose(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Minute)
	source := netip.MustParseAddr("192.0.2.1")
	for index := range 33 {
		connection := reporter.Open(fmt.Sprintf("route-%02d", index), 1, source, base)
		connection.Close(base)
	}
	lost := errors.New("response lost after server committed")
	control.onReport = func(usageReportBatch) error {
		if len(control.calls) == 2 {
			return lost
		}
		return nil
	}
	if err := reporter.flush(t.Context(), base, false); !errors.Is(err, lost) {
		t.Fatalf("lost response = %v", err)
	}
	if len(control.calls) != 2 || control.calls[0].observedThrough != nil || control.calls[1].observedThrough != nil {
		t.Fatal("premature watermark")
	}
	connection := reporter.Open("route-16", 1, source, base)
	connection.PolicyDenied(base)
	connection.Close(base)
	if err := reporter.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(control.calls[1], control.calls[2]) {
		t.Fatal("retry changed payload or revision")
	}
	if control.calls[3].observedThrough == nil || control.calls[3].complete {
		t.Fatal("prior checkpoint was not completed before close")
	}
	last := control.calls[len(control.calls)-1]
	if !last.complete || last.observedThrough == nil || !reporter.closed {
		t.Fatal("close did not finish final checkpoint")
	}
	found := false
	for _, batch := range control.calls[4:] {
		if len(batch.reports) > 16 {
			t.Fatal("unbounded page")
		}
		for _, report := range batch.reports {
			if !report.Final {
				t.Fatal("close emitted nonfinal report")
			}
			if report.PublicUrlId == "route-16" {
				found = report.ConnectionAttempts == 2 && report.PolicyDenials == 1 && report.ReportRevision == 2
			}
		}
	}
	if !found {
		t.Fatal("close lost mutation made during retry")
	}
}

func TestUsageReporterCloseDoesNotWaitForBlockedRunFlush(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	control.onReport = func(usageReportBatch) error {
		close(started)
		<-release
		return nil
	}
	flushDone := make(chan error, 1)
	go func() { flushDone <- reporter.flush(t.Context(), time.Now(), false) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("run flush did not start")
	}
	closeCtx, cancel := context.WithCancel(t.Context())
	cancel()
	closeDone := make(chan error, 1)
	go func() { closeDone <- reporter.Close(closeCtx) }()
	select {
	case err := <-closeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("close = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close waited for blocked run flush")
	}
	unblock()
	if err := <-flushDone; err != nil {
		t.Fatal(err)
	}
}

func TestUsageReporterCloseIsIdempotentAfterCancellation(t *testing.T) {
	reporter, err := NewUsageReporter(new(usageControlStub), time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reporter.Close(ctx); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

func (*usageControlStub) VisitorNetworkHashKey(time.Time) ([32]byte, bool) {
	return [32]byte{1}, true
}
