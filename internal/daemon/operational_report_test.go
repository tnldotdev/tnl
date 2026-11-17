package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
)

// Error must never be invoked by the observation projection.
type unprintableReportCause struct{}

func (unprintableReportCause) Error() string { panic("raw error text was formatted") }

type cyclicReportCause struct{}

func (*cyclicReportCause) Error() string   { return "private cause" }
func (e *cyclicReportCause) Unwrap() error { return e }

func TestOperationalReportObserverCannotChangeProductionReporting(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	native := &quic.StreamError{StreamID: 73, ErrorCode: 17, Remote: true}
	cause := failure.Wrap("forward through relay", failure.TargetUnavailable, errors.Join(native, unprintableReportCause{}))
	calls := 0
	d := &daemon{observeOperationalReport: func(report operationalReport) {
		calls++
		if strings.Count(output.String(), "reason=") != 1 || report.reason != failure.TargetUnavailable ||
			report.operation != "forward through relay" || report.result.truncated {
			t.Error("observer ran before or replaced production reporting")
		}
		found := false
		for i := range report.result.nodes {
			node := &report.result.nodes[i]
			if node.native == "stream" {
				found = node.streamID == 73 && node.code == 17 && node.remote
				// only detached facts can be changed, never the original error.
				node.code, node.remote = 0, false
			}
		}
		if !found {
			t.Error("report lost its exact typed native fields")
		}
		report.reason = failure.Unexpected
	}}
	d.reportOperationalError(context.Background(), "forward through relay", failure.ServerRelayFailed, cause)
	d.reportOperationalError(context.Background(), "forward through relay", failure.ServerRelayFailed, nil)
	if calls != 1 || strings.Count(output.String(), "reason=") != 1 || native.ErrorCode != 17 || !native.Remote ||
		!errors.Is(cause, native) || !strings.Contains(output.String(), "reason="+string(failure.TargetUnavailable)) {
		t.Fatal("observer changed counts, typed native cause, or operational reason")
	}
	if strings.Contains(output.String(), "stream 73") || strings.Contains(output.String(), "private cause") {
		t.Fatal("production report exposed cause content")
	}
}

func TestOperationalCauseSnapshotIsBoundedAndNeverFormatsCauseText(t *testing.T) {
	cause := errors.Join(unprintableReportCause{}, errors.New("secret=https://private.invalid/token"))
	snapshot := snapshotCauses(cause)
	if snapshot.truncated || len(snapshot.nodes) != 3 || strings.Contains(fmt.Sprintf("%+v", snapshot), "secret") ||
		strings.Contains(fmt.Sprintf("%+v", snapshot), "private.invalid") {
		t.Fatal("observation formatted or retained raw error text")
	}
	if got := snapshotCauses(&cyclicReportCause{}); !got.truncated || len(got.nodes) != 32 {
		t.Fatal("cyclic cause projection was not bounded")
	}
	wide := make([]error, 256)
	for i := range wide {
		wide[i] = unprintableReportCause{}
	}
	if got := snapshotCauses(errors.Join(wide...)); !got.truncated || len(got.nodes) != 128 {
		t.Fatal("wide cause projection was not bounded")
	}
}
