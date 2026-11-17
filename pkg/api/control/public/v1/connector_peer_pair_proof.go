package controlv1

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

// ConnectorPeerPairProof converts the generated HTTP fields to the handwritten
// signing value. this is an adapter: tunnelv1 owns validation and v1 bytes.
// neither source credentials nor signature bytes contribute to the proof.
func ConnectorPeerPairProof(serviceID string, body ConnectorPeerPairRequest) (tunnelv1.ConnectorPeerPairProof, error) {
	subject, valid := connectorProofSubject(body.Subject)
	if len(body.ExpectedRelays) != 2 || !valid {
		return tunnelv1.ConnectorPeerPairProof{}, tunnelv1.ErrConnectorPeerPairProof
	}
	proof := tunnelv1.ConnectorPeerPairProof{ServiceID: serviceID, ServiceRunID: body.ServiceRunId, RunNumber: body.RunNumber,
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
			return tunnelv1.ConnectorPeerPairProof{}, tunnelv1.ErrConnectorPeerPairProof
		}
		proof.ExpectedRelays[i] = tunnelv1.ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionId,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TlsServerName,
			RelayLease: tunnelv1.ConnectorPeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId,
				RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision)}}
	}
	if _, err := proof.Message(); err != nil {
		return tunnelv1.ConnectorPeerPairProof{}, err
	}
	return proof, nil
}

func connectorProofSubject(wire VisitorSubject) (tunnelv1.VisitorSubject, bool) {
	subject := tunnelv1.VisitorSubject{Kind: string(wire.Kind)}
	switch string(wire.Kind) {
	case tunnelv1.VisitorHumanDevice:
		if wire.IdentityId == nil || wire.DeviceId == nil || wire.WorkloadSessionId != nil || wire.GrantId != nil || wire.KeyId != nil {
			return subject, false
		}
		subject.IdentityID, subject.DeviceID = *wire.IdentityId, *wire.DeviceId
	case tunnelv1.VisitorWorkloadSession:
		if wire.WorkloadSessionId == nil || wire.IdentityId != nil || wire.DeviceId != nil || wire.GrantId != nil || wire.KeyId != nil {
			return subject, false
		}
		subject.WorkloadSessionID = *wire.WorkloadSessionId
	case tunnelv1.VisitorRegisteredKey:
		if wire.GrantId == nil || wire.KeyId == nil || wire.IdentityId != nil || wire.DeviceId != nil || wire.WorkloadSessionId != nil {
			return subject, false
		}
		subject.GrantID, subject.KeyID = *wire.GrantId, *wire.KeyId
	default:
		return subject, false
	}
	return subject, subject.Validate() == nil
}

// ConnectorPeerPairProofMessage is pure signing input for a generated HTTP
// request. callers sign the returned bytes with the enrolled human-device,
// workload, or registered key before setting body.Signature.
func ConnectorPeerPairProofMessage(serviceID string, body ConnectorPeerPairRequest) ([]byte, error) {
	proof, err := ConnectorPeerPairProof(serviceID, body)
	if err != nil {
		return nil, err
	}
	return proof.Message()
}
