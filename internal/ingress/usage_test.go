package ingress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/routeusage"
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

func TestUsageReporterCompletesOnlyFinalPage(t *testing.T) {
	control := new(usageControlStub)
	reporter, err := NewUsageReporter(control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	for index := range 257 {
		connection := reporter.Open(
			fmt.Sprintf("route-%03d", index), 1, netip.MustParseAddr("192.0.2.1"), base,
		)
		connection.PolicyDenied(base)
		connection.Close(base)
	}
	if err := reporter.flush(t.Context(), base.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || len(control.calls[0].reports) != 256 || len(control.calls[1].reports) != 1 ||
		control.calls[0].observedThrough != nil || control.calls[0].complete ||
		control.calls[1].observedThrough == nil || !control.calls[1].complete {
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
	connection.PublisherOpening(base.Add(2 * time.Second))
	connection.PublisherOpened(base.Add(5 * time.Second))
	connection.StreamOpened(base.Add(6 * time.Second))
	connection.AddEgress(10, base.Add(10*time.Second))
	connection.Close(base.Add(16 * time.Second))
	if err := reporter.flush(t.Context(), base.Add(20*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 1 || len(control.calls[0].reports) != 1 {
		t.Fatalf("reports = %#v", control.calls)
	}
	checkpoint, err := routeusage.ParseCheckpoint(control.calls[0].reports[0].HistogramData)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.PublisherOpenLatency.Count() != 1 ||
		checkpoint.PublisherOpenLatency.SumNanoseconds() != uint64(3*time.Second) ||
		checkpoint.TimeToFirstPublisherByte.Count() != 1 ||
		checkpoint.TimeToFirstPublisherByte.SumNanoseconds() != uint64(9*time.Second) ||
		checkpoint.SuccessfulConnectionDuration.Count() != 1 ||
		checkpoint.SuccessfulConnectionDuration.SumNanoseconds() != uint64(10*time.Second) ||
		checkpoint.VisitorNetworks.Estimate() != 1 {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
}

type usageControlStub struct {
	calls []usageReportBatch
	err   error
}

func (s *usageControlStub) ReportUsage(_ context.Context, batch usageReportBatch) error {
	cloned := batch
	cloned.reports = append([]ingressv1.IngressUsageReport(nil), batch.reports...)
	if batch.observedThrough != nil {
		value := *batch.observedThrough
		cloned.observedThrough = &value
	}
	s.calls = append(s.calls, cloned)
	return s.err
}

func (*usageControlStub) VisitorNetworkHashKey(time.Time) ([32]byte, bool) {
	return [32]byte{1}, true
}
