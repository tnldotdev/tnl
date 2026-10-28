package controlv1

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

// NativePeerPairProof converts the generated HTTP fields to the handwritten
// signing value. this is an adapter: tunnelv1 owns validation and v1 bytes.
// neither source credentials nor signature bytes contribute to the proof.
func NativePeerPairProof(serviceID string, body NativePeerPairRequest) (tunnelv1.NativePeerPairProof, error) {
	if len(body.ExpectedRelays) != 2 ||
		body.Subject.Kind == VisitorSubjectKind(tunnelv1.VisitorHumanDevice) &&
			(body.Subject.IdentityId == nil || body.Subject.DeviceId == nil || body.Subject.WorkloadSessionId != nil) ||
		body.Subject.Kind == VisitorSubjectKind(tunnelv1.VisitorWorkloadSession) &&
			(body.Subject.WorkloadSessionId == nil || body.Subject.IdentityId != nil || body.Subject.DeviceId != nil) {
		return tunnelv1.NativePeerPairProof{}, tunnelv1.ErrNativePeerPairProof
	}
	subject := tunnelv1.VisitorSubject{Kind: string(body.Subject.Kind)}
	if body.Subject.IdentityId != nil {
		subject.IdentityID = *body.Subject.IdentityId
	}
	if body.Subject.DeviceId != nil {
		subject.DeviceID = *body.Subject.DeviceId
	}
	if body.Subject.WorkloadSessionId != nil {
		subject.WorkloadSessionID = *body.Subject.WorkloadSessionId
	}
	proof := tunnelv1.NativePeerPairProof{ServiceID: serviceID, ServiceRunID: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherIdentityID: body.PublisherIdentityId, Subject: subject, Action: string(body.Action), IdempotencyKey: body.IdempotencyKey,
		RequestedAt: body.RequestedAt}
	if body.PreviousPairId != nil {
		proof.PreviousPairID = *body.PreviousPairId
	}
	if body.PreviousGeneration != nil {
		proof.PreviousGeneration = *body.PreviousGeneration
	}
	for i, relay := range body.ExpectedRelays {
		if relay.RelayLease.RelayLeaseRevision < 1 {
			return tunnelv1.NativePeerPairProof{}, tunnelv1.ErrNativePeerPairProof
		}
		proof.ExpectedRelays[i] = tunnelv1.NativePeerPairRelay{PublisherConnectionID: relay.PublisherConnectionId,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TlsServerName,
			RelayLease: tunnelv1.NativePeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId,
				RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision)}}
	}
	if _, err := proof.Message(); err != nil {
		return tunnelv1.NativePeerPairProof{}, err
	}
	return proof, nil
}

// NativePeerPairProofMessage is pure signing input for a generated HTTP
// request. callers sign the returned bytes with the enrolled device or
// workload key before setting body.Signature.
func NativePeerPairProofMessage(serviceID string, body NativePeerPairRequest) ([]byte, error) {
	proof, err := NativePeerPairProof(serviceID, body)
	if err != nil {
		return nil, err
	}
	return proof.Message()
}
