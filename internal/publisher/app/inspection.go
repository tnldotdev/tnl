package app

import (
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

// SummaryObservation records body-free summaries without changing their result.
func SummaryObservation(recorder *clientstate.InspectionRecorder) inspection.Observer {
	if recorder == nil {
		return nil
	}
	return func(summary inspection.Summary) {
		recorder.Observe(clientstate.InspectionRecordFromSummary(summary))
	}
}
