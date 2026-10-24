package serviceaudit

import (
	"errors"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// APIObservations copies only allowlisted facts into the generated wire model.
func APIObservations(batch Batch) ([]controlv1.ServiceObservation, error) {
	if len(batch.Events) < 1 || len(batch.Events) > MaxBatch {
		return nil, ErrInvalid
	}
	result := make([]controlv1.ServiceObservation, 0, len(batch.Events))
	optional := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	for _, e := range batch.Events {
		if err := e.Validate(); err != nil {
			return nil, err
		}
		var reason *controlv1.ServiceObservationReason
		if e.Reason != "" {
			value := controlv1.ServiceObservationReason(e.Reason)
			reason = &value
		}
		result = append(result, controlv1.ServiceObservation{EventId: e.EventID, ServiceId: e.ServiceID, ServiceKind: controlv1.ServiceObservationServiceKind(e.ServiceKind), EventType: controlv1.ServiceObservationEventType(e.EventType), OccurredAt: e.OccurredAt, RunId: e.RunID, RunNumber: e.RunNumber, ConnectorSessionId: optional(e.ConnectorSessionID), StreamAllocationId: optional(e.StreamAllocationID), VisitorConnectionId: e.VisitorConnectionID, SourceIp: optional(e.SourceIP), Outcome: controlv1.ServiceObservationOutcome(e.Outcome), Reason: reason})
	}
	return result, nil
}

func ValidateAcknowledgement(accepted, duplicates, count int) error {
	if count < 1 || count > MaxBatch || accepted < 0 || duplicates < 0 || accepted > MaxBatch || duplicates > MaxBatch || accepted+duplicates != count {
		return errors.New("invalid service audit acknowledgement")
	}
	return nil
}
