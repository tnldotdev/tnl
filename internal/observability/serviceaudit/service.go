package serviceaudit

import (
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NewPrivateSessionDenial records only the bound control session's scope. a
// visitor entry is not an admission and must never supply its service or run.
// control independently verifies the session, source and reporting ingress.
func NewPrivateSessionDenial(bound ingressv1.ConnectorSessionResult, visitorID string) (Observation, error) {
	o := Observation{EventID: NewID(), OccurredAt: time.Now().UTC(), ServiceID: bound.ServiceId,
		ServiceKind: "service", ConnectorSessionID: bound.ConnectorSessionId,
		VisitorConnectionID: visitorID, SourceIP: bound.ObservedSourceIp,
		EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
	_, subjectErr := visitorsubject.Parse(bound.Subject)
	if subjectErr != nil || bound.ExpiresAt.IsZero() || o.Validate() != nil {
		return Observation{}, ErrInvalid
	}
	return o, nil
}

// NewNativeStreamObservation takes run facts only after local permission and
// reservation verification. control derives actor/source scope from immutable
// session facts and this exact ingress-owned allocation, not stream claim rows.
func NewNativeStreamObservation(bound ingressv1.ConnectorSessionResult, entry tunnelv1.ConnectorVisitorEntry, reservation tunnelv1.StreamReservation, permission visitortoken.Permission, eventType, outcome, reason string) (Observation, error) {
	o, err := NewPrivateSessionDenial(bound, entry.VisitorConnectionID)
	subject, subjectErr := visitortoken.NativeSubject(permission.Subject)
	if err != nil || subjectErr != nil || !visitorsubject.Equal(bound.Subject, subject) || permission.Scope.ID != entry.ServiceID || string(permission.Scope.Kind) != "service" || entry.Validate() != nil || entry.ServiceID != bound.ServiceId || reservation.Validate() != nil || reservation.ResourceKind != "service" || reservation.ResourceID != entry.ServiceID || reservation.RunID != entry.ServiceRunID || reservation.RunNumber != entry.RunNumber || reservation.VisitorConnectionID != entry.VisitorConnectionID {
		return Observation{}, ErrInvalid
	}
	o.RunID, o.RunNumber, o.StreamAllocationID = entry.ServiceRunID, int64(entry.RunNumber), reservation.AllocationID
	o.EventType, o.Outcome, o.Reason = eventType, outcome, reason
	if err := o.Validate(); err != nil {
		return Observation{}, err
	}
	return o, nil
}
