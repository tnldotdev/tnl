package serviceaudit

import (
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

// NewPrivateSessionDenial records only the bound control session's scope. a
// visitor entry is not an admission and must never supply its service or run.
// control independently verifies the session, source and reporting ingress.
func NewPrivateSessionDenial(bound ingressv1.PrivateConnectorSessionResult, visitorID string) (Observation, error) {
	o := Observation{EventID: NewID(), OccurredAt: time.Now().UTC(), ServiceID: bound.PrivateServiceId,
		ServiceKind: "private_service", ConnectorSessionID: bound.ConnectorSessionId,
		VisitorConnectionID: visitorID, SourceIP: bound.ObservedSourceIp,
		EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
	if !ValidReference(bound.IdentityId) || !opaqueid.Valid(bound.DeviceId, "vdev_") || bound.ExpiresAt.IsZero() || o.Validate() != nil {
		return Observation{}, ErrInvalid
	}
	return o, nil
}

// NewPrivateStreamObservation takes run facts only from control's admitted
// stream result. a device session may admit another service when authorized;
// its session, identity, device and observed source must still match exactly.
func NewPrivateStreamObservation(bound ingressv1.PrivateConnectorSessionResult, admitted ingressv1.PrivateServiceStreamResult, eventType, outcome, reason string) (Observation, error) {
	o, err := NewPrivateSessionDenial(bound, admitted.VisitorConnectionId)
	if err != nil || admitted.ConnectorSessionId != bound.ConnectorSessionId || admitted.IdentityId != bound.IdentityId ||
		admitted.DeviceId != bound.DeviceId || admitted.ObservedSourceIp != bound.ObservedSourceIp ||
		admitted.GrantRevision < 1 || admitted.ExpiresAt.IsZero() || admitted.ValidUntil.IsZero() {
		return Observation{}, ErrInvalid
	}
	o.ServiceID, o.RunID, o.RunNumber = admitted.PrivateServiceId, admitted.PrivateRunId, admitted.RunNumber
	o.EventType, o.Outcome, o.Reason = eventType, outcome, reason
	if o.RunID == "" || o.Validate() != nil {
		return Observation{}, ErrInvalid
	}
	return o, nil
}
